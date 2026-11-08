// Package release is Fairy's signed releases, shared by fairy-agent's self-update and the panel's
// `fairy update`: the layout of a GitHub release, the ed25519 signature check, the download from GitHub (fixed
// hosts, size caps, time limits) and the installer that swaps a binary, restarts it and rolls back when the new
// one does not come up healthy.
//
// A release (made by .github/workflows/release.yml in Fairy-agent and Fairy-dashboard on every push to main):
//
//	tag            build-<run number> (never semver: Go would take it for a module version), marked "latest"
//	<binaries>     one per platform, e.g. fairy-agent-linux-arm64, fairy-agent-windows-amd64.exe, fairy-linux-amd64
//	VERSION        "<program> <version>\n", e.g. "fairy-agent 42-1a2b3c4" (build number - short commit)
//	SHA256SUMS     sha256sum format, one line for every file above
//	SHA256SUMS.sig the base64 ed25519 signature of SHA256SUMS, made with the owner's release key
//
// The binaries carry the public key (set with -ldflags at build time). An update trusts nothing it downloads
// until the signature of SHA256SUMS checks out with that key; every other file must then match its line.
package release

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// File names every release has besides the binaries.
const (
	SumsFile    = "SHA256SUMS"
	SigFile     = "SHA256SUMS.sig"
	VersionFile = "VERSION"
)

// The official repositories. Forks can be configured instead (self_update.repo, updates.*_repo).
const (
	AgentRepo = "n3ptune-cpu/Fairy-agent"
	PanelRepo = "n3ptune-cpu/Fairy-dashboard"
)

// Programs, as named in VERSION and in the asset names.
const (
	AgentProgram = "fairy-agent"
	PanelProgram = "fairy"
)

// ErrNoKey is returned when a binary was built without the release public key (a local build).
var ErrNoKey = errors.New("this build has no release signing key (it was not built by the release workflow), " +
	"so it cannot check a download and will not update itself; install a release build from GitHub once by hand")

// AssetName is the release file for a program on an OS / architecture.
func AssetName(program, goos, goarch string) string {
	n := program + "-" + goos + "-" + goarch
	if goos == "windows" {
		n += ".exe"
	}
	return n
}

// ParsePublicKey reads a public key: base64 of the 32-byte ed25519 key (the content of release/signing.pub).
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrNoKey
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("release public key: expected base64 of 32 bytes")
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey reads a private key: base64 of the 32-byte ed25519 seed (the GitHub secret FAIRY_RELEASE_KEY).
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("release private key: expected base64 of a 32-byte ed25519 seed (as written by fairy-release-key gen)")
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// GenerateKey makes a new key pair, both as base64 text (public key, private seed).
func GenerateKey() (pub, priv string, err error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", "", err
	}
	k := ed25519.NewKeyFromSeed(seed)
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(seed), nil
}

// PublicOf is the base64 public key of a private key.
func PublicOf(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

// Sign returns the content of SHA256SUMS.sig for a SHA256SUMS file.
func Sign(k ed25519.PrivateKey, sums []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(k, sums)) + "\n")
}

// Sums is a parsed SHA256SUMS: file name -> SHA-256.
type Sums map[string][32]byte

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// ValidName reports whether s is a plain release file name (no path, no "..").
func ValidName(s string) bool { return nameRe.MatchString(s) && !strings.Contains(s, "..") }

// ParseSums reads sha256sum output ("<64 hex>  <name>" or "<64 hex> *<name>").
func ParseSums(b []byte) (Sums, error) {
	out := Sums{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		h, name, ok := strings.Cut(line, " ")
		name = strings.TrimPrefix(strings.TrimPrefix(name, " "), "*")
		raw, err := hex.DecodeString(h)
		if !ok || err != nil || len(raw) != sha256.Size || !ValidName(name) {
			return nil, fmt.Errorf("%s line %d is not \"<sha256>  <file>\"", SumsFile, n)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%s lists %s twice", SumsFile, name)
		}
		out[name] = [32]byte(raw)
	}
	if len(out) == 0 {
		return nil, errors.New(SumsFile + " is empty")
	}
	return out, nil
}

// FormatSums writes files in sha256sum format, in the given order (tests and tools).
func FormatSums(names []string, data map[string][]byte) []byte {
	var b strings.Builder
	for _, n := range names {
		h := sha256.Sum256(data[n])
		fmt.Fprintf(&b, "%x  %s\n", h, n)
	}
	return []byte(b.String())
}

// VerifySignature checks a file against its .sig content and the public key.
func VerifySignature(pub ed25519.PublicKey, data, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrNoKey
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New(SigFile + " is not a base64 ed25519 signature")
	}
	if !ed25519.Verify(pub, data, raw) {
		return errors.New("the release signature does not match this build's release key (" + SigFile +
			" was not made with the owner's key, or " + SumsFile + " was changed)")
	}
	return nil
}

// VerifySums checks SHA256SUMS against its signature and the public key, then parses it.
func VerifySums(pub ed25519.PublicKey, sums, sig []byte) (Sums, error) {
	if err := VerifySignature(pub, sums, sig); err != nil {
		return nil, err
	}
	return ParseSums(sums)
}

// Check reports whether data is the file name as listed.
func (s Sums) Check(name string, data []byte) error {
	want, ok := s[name]
	if !ok {
		return fmt.Errorf("%s is not listed in %s", name, SumsFile)
	}
	if sha256.Sum256(data) != want {
		return fmt.Errorf("%s does not match its %s line (corrupted or tampered download)", name, SumsFile)
	}
	return nil
}

var versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// ValidVersion reports whether v looks like a version string (what binaries and VERSION files carry).
func ValidVersion(v string) bool { return versionRe.MatchString(v) }

// ParseVersionFile reads VERSION ("<program> <version>").
func ParseVersionFile(b []byte) (program, version string, err error) {
	f := strings.Fields(string(b))
	if len(f) != 2 || !ValidVersion(f[1]) {
		return "", "", errors.New(VersionFile + ` must be "<program> <version>"`)
	}
	return f[0], f[1], nil
}

// BuildNumber is the release build number at the start of a version ("42-1a2b3c4" -> 42). ok is false for
// versions that do not start with one (local builds: "dev", "v0.1.0-3-gabcdef").
func BuildNumber(v string) (int, bool) {
	head, _, _ := strings.Cut(v, "-")
	n, err := strconv.Atoi(head)
	if err != nil || n < 0 || len(head) > 9 {
		return 0, false
	}
	return n, true
}

// Compare tells how a candidate release version relates to the running one: 1 newer, 0 the same, -1 older,
// and known=false when either has no build number (then only "the same" can be told apart).
func Compare(current, candidate string) (cmp int, known bool) {
	if current == candidate {
		return 0, true
	}
	a, ok1 := BuildNumber(current)
	b, ok2 := BuildNumber(candidate)
	if !ok1 || !ok2 {
		return 1, false
	}
	switch {
	case b > a:
		return 1, true
	case b < a:
		return -1, true
	}
	return 0, true // same build number, different commit text: treat as the same build
}
