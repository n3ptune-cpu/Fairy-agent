// Package releasetest is a fake GitHub for tests (here and in the panel): it serves one signed release over
// TLS the way api.github.com and github.com do, including a redirect for asset downloads.
package releasetest

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

// Server is a fake GitHub with one repository and one latest release.
type Server struct {
	*httptest.Server
	Repo string
	Key  ed25519.PrivateKey
	Pub  ed25519.PublicKey

	mu     sync.Mutex
	tag    string
	files  map[string][]byte
	hits   []string
	broken bool
}

// New starts the server with a throwaway key and no release.
func New(t testing.TB, repo string) *Server {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Repo: repo, Key: priv, Pub: pub, files: map[string][]byte{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// Publish makes a release with these binaries, a VERSION file and a SHA256SUMS signed with key (s.Key if nil).
func (s *Server) Publish(tag, program, version string, bins map[string][]byte, key ed25519.PrivateKey) {
	if key == nil {
		key = s.Key
	}
	files := map[string][]byte{release.VersionFile: []byte(program + " " + version + "\n")}
	names := []string{release.VersionFile}
	for n, b := range bins {
		files[n] = b
		names = append(names, n)
	}
	slices.Sort(names)
	sums := release.FormatSums(names, files)
	files[release.SumsFile] = sums
	files[release.SigFile] = release.Sign(key, sums)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tag, s.files = tag, files
}

// Replace swaps one published file's content (after signing: a tampered download).
func (s *Server) Replace(name string, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[name] = b
}

// SetBroken makes the API answer 503.
func (s *Server) SetBroken(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.broken = v
}

// Hits are the paths requested so far.
func (s *Server) Hits() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.hits)
}

// Downloads is how many times the file name was fetched from the storage host so far.
func (s *Server) Downloads(name string) int {
	n := 0
	for _, h := range s.Hits() {
		if h == "/storage/"+name {
			n++
		}
	}
	return n
}

// Client returns a release.Client for s.Repo that talks to this server.
func (s *Server) Client() *release.Client {
	c, err := release.NewClient(s.Repo, "releasetest")
	if err != nil {
		panic(err)
	}
	u, _ := url.Parse(s.URL)
	c.HTTP = s.Server.Client()
	c.APIBase, c.DownloadBase, c.Hosts = s.URL+"/api", s.URL, []string{u.Hostname()}
	return c
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = append(s.hits, r.URL.Path)
	if s.broken {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	switch {
	case r.URL.Path == "/api/repos/"+s.Repo+"/releases/latest":
		if s.tag == "" {
			http.NotFound(w, r)
			return
		}
		var assets []map[string]any
		for n, b := range s.files {
			assets = append(assets, map[string]any{"name": n, "size": len(b), "browser_download_url": "https://evil.example/" + n})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": s.tag, "html_url": "https://github.com/" + s.Repo + "/releases/tag/" + s.tag,
			"published_at": "2026-11-08T18:00:00Z", "assets": assets})
	case strings.HasPrefix(r.URL.Path, "/"+s.Repo+"/releases/download/"+s.tag+"/"):
		// like github.com: redirect to the storage host (here the same server)
		http.Redirect(w, r, "/storage/"+strings.TrimPrefix(r.URL.Path, "/"+s.Repo+"/releases/download/"+s.tag+"/"), http.StatusFound)
	case strings.HasPrefix(r.URL.Path, "/storage/"):
		b, ok := s.files[strings.TrimPrefix(r.URL.Path, "/storage/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	default:
		http.NotFound(w, r)
	}
}
