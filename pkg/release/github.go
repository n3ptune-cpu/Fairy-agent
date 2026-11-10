package release

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Size limits for what is downloaded.
const (
	MaxAssetSize = 96 << 20 // one binary (today about 10-20 MB)
	maxSmallFile = 64 << 10 // SHA256SUMS, its signature, VERSION
	maxAPIBody   = 2 << 20  // the release JSON
)

// DefaultHosts are the only hosts a Client talks to, including redirects: the API, github.com (release
// download URLs) and the hosts GitHub redirects asset downloads to.
var DefaultHosts = []string{"api.github.com", "github.com", "objects.githubusercontent.com",
	"release-assets.githubusercontent.com", "github-releases.githubusercontent.com"}

var repoRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)

// ValidRepo reports whether s is "owner/name" (a GitHub repository; never a URL or a host).
func ValidRepo(s string) bool {
	if !repoRe.MatchString(s) {
		return false
	}
	_, name, _ := strings.Cut(s, "/")
	return name != "." && name != ".." && !strings.Contains(name, "..")
}

var tagRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// Client reads one repository's releases from GitHub over HTTPS. No token: the repositories are public.
type Client struct {
	Repo      string
	UserAgent string
	HTTP      *http.Client
	// APIBase and DownloadBase are https://api.github.com and https://github.com; Hosts is DefaultHosts.
	// Only tests change them (to a local TLS server); nothing in a config file can.
	APIBase, DownloadBase string
	Hosts                 []string
}

// maxResponseHeaderBytes: see NewClient (the same number as devices.MaxResponseHeaderBytes).
const maxResponseHeaderBytes = 64 << 10

// NewClient returns a client for repo ("owner/name") with time limits and the host allow-list for redirects.
func NewClient(repo, userAgent string) (*Client, error) {
	if !ValidRepo(repo) {
		return nil, fmt.Errorf("%q is not a GitHub repository name (owner/name)", repo)
	}
	c := &Client{Repo: repo, UserAgent: userAgent, APIBase: "https://api.github.com", DownloadBase: "https://github.com"}
	// MaxResponseHeaderBytes: without it net/http reads up to 10 MiB of header per answer into memory, and the
	// agent that asks runs inside 64 MiB. GitHub's answers carry about 5 KiB.
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true, MaxIdleConns: 4,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:    10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 30 * time.Second}
	c.HTTP = &http.Client{Transport: tr}
	return c, nil
}

func (c *Client) hosts() []string {
	if c.Hosts != nil {
		return c.Hosts
	}
	return DefaultHosts
}

func (c *Client) allowed(u *url.URL) error {
	if u.Scheme != "https" || u.User != nil || !slices.Contains(c.hosts(), strings.ToLower(u.Hostname())) {
		return fmt.Errorf("refusing to fetch from %s://%s (only https from GitHub)", u.Scheme, u.Host)
	}
	return nil
}

// do GETs u (following redirects only to allowed hosts) and returns the body limited to max bytes.
func (c *Client) do(ctx context.Context, u, accept string, max int64) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if err := c.allowed(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", accept)
	if strings.HasPrefix(u, c.APIBase) {
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	hc := *c.HTTP
	hc.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return c.allowed(r.URL)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, fmt.Errorf("GitHub: %s not found (no release yet?)", req.URL.Path)
		case http.StatusForbidden, http.StatusTooManyRequests:
			return nil, fmt.Errorf("GitHub refused the request (HTTP %d, rate limit?)", resp.StatusCode)
		}
		return nil, fmt.Errorf("GitHub: HTTP %d for %s", resp.StatusCode, req.URL.Path)
	}
	if resp.ContentLength > max {
		resp.Body.Close()
		return nil, fmt.Errorf("%s is larger than the %d-byte limit", req.URL.Path, max)
	}
	return resp, nil
}

func (c *Client) get(ctx context.Context, u, accept string, max int64) ([]byte, error) {
	resp, err := c.do(ctx, u, accept, max)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is larger than the %d-byte limit", u, max)
	}
	return b, nil
}

// Release is a GitHub release as far as Fairy cares.
type Release struct {
	Tag       string           `json:"tag"`
	URL       string           `json:"url"`
	Published time.Time        `json:"published_at"`
	Assets    map[string]int64 `json:"-"` // name -> size
}

// Latest returns the repository's latest release.
func (c *Client) Latest(ctx context.Context) (*Release, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	b, err := c.get(ctx, c.APIBase+"/repos/"+c.Repo+"/releases/latest", "application/vnd.github+json", maxAPIBody)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Tag       string    `json:"tag_name"`
		URL       string    `json:"html_url"`
		Published time.Time `json:"published_at"`
		Assets    []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, errors.New("GitHub: unexpected release JSON")
	}
	if !tagRe.MatchString(raw.Tag) {
		return nil, fmt.Errorf("GitHub: unexpected release tag %q", raw.Tag)
	}
	r := &Release{Tag: raw.Tag, Published: raw.Published, Assets: map[string]int64{}}
	if u, err := url.Parse(raw.URL); err == nil && u.Scheme == "https" && u.Host == "github.com" {
		r.URL = raw.URL
	}
	for _, a := range raw.Assets {
		if ValidName(a.Name) {
			r.Assets[a.Name] = a.Size
		}
	}
	return r, nil
}

// downloadURL is built here from the repository, tag and file name (never taken from the API's JSON).
func (c *Client) downloadURL(tag, name string) string {
	return c.DownloadBase + "/" + c.Repo + "/releases/download/" + url.PathEscape(tag) + "/" + url.PathEscape(name)
}

// Checked is a release whose SHA256SUMS signature and VERSION file have been verified.
type Checked struct {
	*Release
	Program, Version string
	Sums             Sums
	// The verified files as downloaded (to stage them for a second check by the privileged installer).
	SumsRaw, SigRaw, VersionRaw []byte
}

// Check fetches the latest release's SHA256SUMS, signature and VERSION and verifies them with pub. program is
// what VERSION must name (a Fairy-dashboard release cannot pass for a Fairy-agent one).
func (c *Client) Check(ctx context.Context, pub ed25519.PublicKey, program string) (*Checked, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrNoKey
	}
	rel, err := c.Latest(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ch := &Checked{Release: rel}
	for _, f := range []struct {
		name string
		dst  *[]byte
	}{{SumsFile, &ch.SumsRaw}, {SigFile, &ch.SigRaw}, {VersionFile, &ch.VersionRaw}} {
		if *f.dst, err = c.get(ctx, c.downloadURL(rel.Tag, f.name), "application/octet-stream", maxSmallFile); err != nil {
			return nil, fmt.Errorf("release %s: %w", rel.Tag, err)
		}
	}
	return ch, ch.verify(pub, program)
}

// VerifyFiles checks a release's three small files (as staged on disk, or just downloaded).
func VerifyFiles(pub ed25519.PublicKey, program string, sums, sig, version []byte) (*Checked, error) {
	ch := &Checked{Release: &Release{}, SumsRaw: sums, SigRaw: sig, VersionRaw: version}
	return ch, ch.verify(pub, program)
}

func (ch *Checked) verify(pub ed25519.PublicKey, program string) error {
	var err error
	if ch.Sums, err = VerifySums(pub, ch.SumsRaw, ch.SigRaw); err != nil {
		return err
	}
	if err := ch.Sums.Check(VersionFile, ch.VersionRaw); err != nil {
		return err
	}
	if ch.Program, ch.Version, err = ParseVersionFile(ch.VersionRaw); err != nil {
		return err
	}
	if ch.Program != program {
		return fmt.Errorf("this release is %s, not %s (wrong repository?)", ch.Program, program)
	}
	return nil
}

// FetchAsset downloads one binary of a checked release into dir (a new file with a random name), checks its
// size and SHA-256 against the signed SHA256SUMS and returns the file's path. On any error nothing is left
// behind.
func (c *Client) FetchAsset(ctx context.Context, ch *Checked, name, dir string) (string, error) {
	want, ok := ch.Sums[name]
	if !ok || !ValidName(name) {
		return "", fmt.Errorf("release %s has no %s (not built for this platform?)", ch.Tag, name)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	resp, err := c.do(ctx, c.downloadURL(ch.Tag, name), "application/octet-stream", MaxAssetSize)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	f, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	ok = false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(path)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, MaxAssetSize+1))
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", name, err)
	}
	if n > MaxAssetSize {
		return "", fmt.Errorf("%s is larger than the %d-byte limit", name, MaxAssetSize)
	}
	if [32]byte(h.Sum(nil)) != want {
		return "", fmt.Errorf("%s does not match its %s line (corrupted or tampered download)", name, SumsFile)
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return filepath.Clean(path), nil
}
