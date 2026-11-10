package release_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release/releasetest"
)

func TestKeysSignAndVerify(t *testing.T) {
	pubS, privS, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := release.ParsePublicKey(pubS + "\n")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := release.ParsePrivateKey(privS)
	if err != nil {
		t.Fatal(err)
	}
	if release.PublicOf(priv) != pubS {
		t.Fatal("public key does not belong to the private key")
	}
	files := map[string][]byte{"fairy-agent-linux-amd64": []byte("binary"), "VERSION": []byte("fairy-agent 7-abcdef1\n")}
	sums := release.FormatSums([]string{"VERSION", "fairy-agent-linux-amd64"}, files)
	sig := release.Sign(priv, sums)

	s, err := release.VerifySums(pub, sums, sig)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Check("fairy-agent-linux-amd64", []byte("binary")); err != nil {
		t.Fatal(err)
	}
	if err := s.Check("fairy-agent-linux-amd64", []byte("binarY")); err == nil {
		t.Fatal("tampered asset accepted")
	}
	if err := s.Check("fairy-agent-linux-arm64", []byte("binary")); err == nil {
		t.Fatal("unlisted asset accepted")
	}
	// tampered SHA256SUMS
	bad := []byte(strings.Replace(string(sums), "fairy-agent-linux-amd64", "fairy-agent-linux-arm64", 1))
	if _, err := release.VerifySums(pub, bad, sig); err == nil {
		t.Fatal("tampered SHA256SUMS accepted")
	}
	// tampered signature
	raw := []byte(strings.TrimSpace(string(sig)))
	raw[5] ^= 1
	if _, err := release.VerifySums(pub, sums, raw); err == nil {
		t.Fatal("tampered signature accepted")
	}
	// wrong key
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if _, err := release.VerifySums(otherPub, sums, sig); err == nil {
		t.Fatal("signature from another key accepted")
	}
	// no key at all (local build)
	if _, err := release.VerifySums(nil, sums, sig); !errors.Is(err, release.ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
	if _, err := release.ParsePublicKey(""); !errors.Is(err, release.ErrNoKey) {
		t.Fatal("empty public key must be ErrNoKey")
	}
	for _, k := range []string{"not base64!", "AAAA"} {
		if _, err := release.ParsePublicKey(k); err == nil {
			t.Fatalf("bad public key %q accepted", k)
		}
		if _, err := release.ParsePrivateKey(k); err == nil {
			t.Fatalf("bad private key %q accepted", k)
		}
	}
}

func TestParseSums(t *testing.T) {
	h := strings.Repeat("ab", 32)
	s, err := release.ParseSums([]byte(h + "  fairy-linux-amd64\n" + h + " *fairy-linux-arm64\r\n\n"))
	if err != nil || len(s) != 2 {
		t.Fatalf("%v %v", s, err)
	}
	for _, bad := range []string{"", h + "  ../etc/passwd\n", h + "  a/b\n", "xyz  file\n", h + "  f\n" + h + "  f\n", h[:60] + "  f\n"} {
		if _, err := release.ParseSums([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// I14: a line longer than the reader's buffer used to end the list there without a word: every file listed
// after it was "not in the release". It is an error now, wherever the long line stands.
func TestParseSumsOverLongLine(t *testing.T) {
	h := strings.Repeat("ab", 32)
	long := strings.Repeat("x", 70<<10)
	for name, in := range map[string]string{
		"first":  long + "\n" + h + "  later\n",
		"middle": h + "  first\n" + long + "\n" + h + "  later\n",
		"last":   h + "  first\n" + h + "  second\n" + long,
		"name":   h + "  first\n" + h + "  " + long + "\n",
	} {
		s, err := release.ParseSums([]byte(in))
		if err == nil {
			t.Fatalf("%s: accepted, %d entries", name, len(s))
		}
		if !strings.Contains(err.Error(), "over-long line") {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := release.VerifySums(nil, []byte(in), nil); err == nil {
			t.Fatalf("%s: VerifySums accepted", name)
		}
	}
	// just under the limit is an ordinary bad line, and long lists of ordinary lines are fine
	if _, err := release.ParseSums([]byte(h + "  " + strings.Repeat("x", 60<<10) + "\n")); err == nil || strings.Contains(err.Error(), "over-long") {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&b, "%s  file-%d\n", h, i)
	}
	if s, err := release.ParseSums([]byte(b.String())); err != nil || len(s) != 5000 {
		t.Fatal(len(s), err)
	}
}

func TestAssetNamesAndVersions(t *testing.T) {
	for _, c := range [][4]string{
		{"fairy-agent", "windows", "amd64", "fairy-agent-windows-amd64.exe"},
		{"fairy-agent", "linux", "arm64", "fairy-agent-linux-arm64"},
		{"fairy", "linux", "amd64", "fairy-linux-amd64"},
	} {
		if got := release.AssetName(c[0], c[1], c[2]); got != c[3] {
			t.Fatalf("%v: %s", c, got)
		}
	}
	if n, ok := release.BuildNumber("42-1a2b3c4"); !ok || n != 42 {
		t.Fatal(n, ok)
	}
	for v, want := range map[string]int{"0-a": 0, "7": 7, "042-x": 42, "999999999-abcdef0": 999999999} {
		if n, ok := release.BuildNumber(v); !ok || n != want || release.NoBuildNumber(v) != "" {
			t.Fatalf("%q: %d %v %q", v, n, ok, release.NoBuildNumber(v))
		}
	}
	for _, v := range []string{"dev", "v0.1.0-3-gabc", "v0.4.2", "", "-1", "+42-abc", " 42-abc", "4 2-abc", "0x2a-abc", "42a-abc",
		"1000000000-abc", "99999999999999999999-abc"} {
		if _, ok := release.BuildNumber(v); ok {
			t.Fatalf("%q has no build number", v)
		}
		if release.NoBuildNumber(v) == "" {
			t.Fatalf("%q: no reason", v)
		}
	}
	if why := release.NoBuildNumber("1000000000-abc"); !strings.Contains(why, "more than 9 digits") {
		t.Fatal(why)
	}
	if why := release.NoBuildNumber("v0.4.2"); !strings.Contains(why, "does not start with a build number") {
		t.Fatal(why)
	}
	cases := []struct {
		cur, cand string
		cmp       int
		known     bool
	}{{"41-aaaaaaa", "42-bbbbbbb", 1, true}, {"42-bbbbbbb", "42-bbbbbbb", 0, true}, {"43-c", "42-b", -1, true},
		{"dev", "42-b", 1, false}, {"20-abc", "v0.4.2", 1, false}, {"20-abc", "1000000000-abc", 1, false}, {"dev", "dev", 0, true},
		{"42-aaaaaaa", "42-bbbbbbb", 0, true}}
	for _, c := range cases {
		cmp, known := release.Compare(c.cur, c.cand)
		if cmp != c.cmp || known != c.known {
			t.Fatalf("%v: %d %v", c, cmp, known)
		}
		// L23: NotComparable is an error exactly when Compare cannot tell, and it names the version at fault
		err := release.NotComparable(c.cur, c.cand)
		if (err == nil) != known {
			t.Fatalf("%v: NotComparable %v", c, err)
		}
		if err != nil && !errors.Is(err, release.ErrNotComparable) {
			t.Fatalf("%v: %v", c, err)
		}
	}
	if err := release.NotComparable("20-abc", "v0.4.2"); err == nil || !strings.Contains(err.Error(), `the release's version "v0.4.2"`) {
		t.Fatal(err)
	}
	if err := release.NotComparable("dev", "42-b"); err == nil || !strings.Contains(err.Error(), `the installed version "dev"`) {
		t.Fatal(err)
	}
	if p, v, err := release.ParseVersionFile([]byte("fairy-agent 42-1a2b3c4\n")); err != nil || p != "fairy-agent" || v != "42-1a2b3c4" {
		t.Fatal(p, v, err)
	}
	for _, bad := range []string{"", "fairy-agent", "fairy-agent 1 2", "fairy-agent ../x"} {
		if _, _, err := release.ParseVersionFile([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestValidRepo(t *testing.T) {
	for _, ok := range []string{"n3ptune-cpu/Fairy-agent", "someone/fork.of_fairy"} {
		if !release.ValidRepo(ok) {
			t.Fatalf("%s refused", ok)
		}
	}
	for _, bad := range []string{"", "Fairy-agent", "a/b/c", "evil.example/x", "https://evil/x", "o/..", "o/.", "-o/x",
		"o/x?y", "o/x#", "o/x y", "127.0.0.1:80/x", "o/" + strings.Repeat("x", 101)} {
		if release.ValidRepo(bad) {
			t.Fatalf("%q accepted", bad)
		}
		if _, err := release.NewClient(bad, "t"); err == nil {
			t.Fatalf("client for %q", bad)
		}
	}
}

func TestCheckAndFetchFromFakeGitHub(t *testing.T) {
	gh := releasetest.New(t, release.AgentRepo)
	bin := []byte("new fairy-agent binary")
	gh.Publish("build-42", "fairy-agent", "42-1a2b3c4", map[string][]byte{"fairy-agent-linux-amd64": bin}, nil)
	c := gh.Client()
	ctx := context.Background()

	ch, err := c.Check(ctx, gh.Pub, "fairy-agent")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Tag != "build-42" || ch.Version != "42-1a2b3c4" || ch.Program != "fairy-agent" {
		t.Fatalf("%+v", ch)
	}
	dir := t.TempDir()
	p, err := c.FetchAsset(ctx, ch, "fairy-agent-linux-amd64", dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != string(bin) || filepath.Dir(p) != dir {
		t.Fatalf("%s %q", p, b)
	}
	for _, h := range gh.Hits() {
		if strings.Contains(h, "evil") {
			t.Fatal("followed a URL from the API JSON")
		}
	}
	// not built for this platform
	if _, err := c.FetchAsset(ctx, ch, "fairy-agent-linux-riscv64", dir); err == nil {
		t.Fatal("missing asset")
	}
	// tampered asset after signing: refused, nothing left behind
	gh.Replace("fairy-agent-linux-amd64", []byte("evil binary"))
	if _, err := c.FetchAsset(ctx, ch, "fairy-agent-linux-amd64", dir); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered asset: %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("left files behind: %v", ents)
	}
	// wrong key / wrong program / tampered VERSION
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := c.Check(ctx, other, "fairy-agent"); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := c.Check(ctx, gh.Pub, "fairy"); err == nil {
		t.Fatal("agent release accepted as a panel release")
	}
	gh.Replace("VERSION", []byte("fairy-agent 99-fffffff\n"))
	if _, err := c.Check(ctx, gh.Pub, "fairy-agent"); err == nil {
		t.Fatal("tampered VERSION accepted")
	}
	// signed by another key
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	gh.Publish("build-43", "fairy-agent", "43-1a2b3c4", map[string][]byte{"fairy-agent-linux-amd64": bin}, otherPriv)
	if _, err := c.Check(ctx, gh.Pub, "fairy-agent"); err == nil {
		t.Fatal("release signed by another key accepted")
	}
	if _, err := c.Check(ctx, nil, "fairy-agent"); !errors.Is(err, release.ErrNoKey) {
		t.Fatal("no key")
	}
	gh.SetBroken(true)
	if _, err := c.Latest(ctx); err == nil {
		t.Fatal("503 accepted")
	}
}

func TestRedirectsOnlyToAllowedHosts(t *testing.T) {
	gh := releasetest.New(t, release.AgentRepo)
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) }))
	defer evil.Close()
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(evil.URL, "127.0.0.1", "localhost", 1)+"/x", http.StatusFound)
	}))
	defer redir.Close()
	c := gh.Client()
	c.APIBase = redir.URL // allowed host that redirects to one not in the list
	if _, err := c.Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("redirect to an unlisted host: %v", err)
	}
	c.APIBase = strings.Replace(redir.URL, "127.0.0.1", "localhost", 1) // a host not in the list at all
	if _, err := c.Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("unlisted host: %v", err)
	}
	c = gh.Client()
	c.Hosts = append(c.Hosts, "localhost")
	// plain http is never used
	c.APIBase = strings.Replace(gh.URL, "https://", "http://", 1) + "/api"
	if _, err := c.Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("http: %v", err)
	}
}

func TestDefaultClient(t *testing.T) {
	c, err := release.NewClient(release.AgentRepo, "t")
	if err != nil {
		t.Fatal(err)
	}
	if c.APIBase != "https://api.github.com" || c.DownloadBase != "https://github.com" || c.HTTP == nil {
		t.Fatalf("%+v", c)
	}
}

// ---- installer: swap, health check, rollback (with fakes)

type fakeSvc struct {
	target   string
	starts   int
	stops    int
	failNew  bool // the new binary "crashes": Healthy fails while it is installed
	startErr error
}

func (f *fakeSvc) installer(renameSwap bool) *release.Installer {
	return &release.Installer{Target: f.target, RenameSwap: renameSwap, HealthTimeout: 300 * time.Millisecond, Interval: 10 * time.Millisecond,
		Start: func(context.Context) error { f.starts++; return f.startErr },
		Stop: func() func(context.Context) error {
			if !renameSwap {
				return nil
			}
			return func(context.Context) error { f.stops++; return nil }
		}(),
		Healthy: func(context.Context) error {
			b, _ := os.ReadFile(f.target)
			if f.failNew && string(b) == "new" {
				return errors.New("version check: still old")
			}
			return nil
		}, Logf: func(string, ...any) {}}
}

func setupTarget(t *testing.T) (string, string) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fairy-agent")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("new"))
	staged := filepath.Join(t.TempDir(), "fairy-agent-linux-amd64")
	if err := os.WriteFile(staged, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := release.CopyVerified(staged, dir, h)
	if err != nil {
		t.Fatal(err)
	}
	return target, p
}

func TestInstallerSwapsAndKeepsOld(t *testing.T) {
	for _, rs := range []bool{false, true} {
		target, newPath := setupTarget(t)
		f := &fakeSvc{target: target}
		if err := f.installer(rs).Install(context.Background(), newPath); err != nil {
			t.Fatal(rs, err)
		}
		if b, _ := os.ReadFile(target); string(b) != "new" {
			t.Fatal(rs, string(b))
		}
		if b, _ := os.ReadFile(target + ".old"); string(b) != "old" {
			t.Fatal(rs, "old not kept:", string(b))
		}
		if st, _ := os.Stat(target); st.Mode().Perm() != 0o755 {
			t.Fatal(rs, st.Mode())
		}
		if f.starts != 1 {
			t.Fatal(rs, f.starts)
		}
	}
}

func TestInstallerRollsBack(t *testing.T) {
	for _, rs := range []bool{false, true} {
		// unhealthy new version
		target, newPath := setupTarget(t)
		f := &fakeSvc{target: target, failNew: true}
		err := f.installer(rs).Install(context.Background(), newPath)
		var rb *release.RolledBackError
		if !errors.As(err, &rb) || rb.RollbackErr != nil || !strings.Contains(err.Error(), "rolled back") {
			t.Fatalf("%v: %v", rs, err)
		}
		if b, _ := os.ReadFile(target); string(b) != "old" {
			t.Fatal(rs, "not rolled back:", string(b))
		}
		if f.starts != 2 {
			t.Fatal(rs, "starts", f.starts)
		}
		// start fails: rollback, and the rollback's start fails too
		target, newPath = setupTarget(t)
		f = &fakeSvc{target: target, startErr: errors.New("unit failed")}
		err = f.installer(rs).Install(context.Background(), newPath)
		if !errors.As(err, &rb) || rb.RollbackErr == nil {
			t.Fatalf("%v: %v", rs, err)
		}
		if b, _ := os.ReadFile(target); string(b) != "old" {
			t.Fatal(rs, "not rolled back:", string(b))
		}
	}
}

// L28: the check after a rollback must look for the PREVIOUS version. With one check for both (one that
// expects the new version, as the agent's does) a clean rollback was reported as "rolling back FAILED too",
// after waiting the whole health timeout a second time.
func TestInstallerChecksThePreviousVersionAfterARollback(t *testing.T) {
	for _, rs := range []bool{false, true} {
		target, newPath := setupTarget(t)
		running := func() string { b, _ := os.ReadFile(target); return string(b) }
		expect := func(want string) func(context.Context) error {
			return func(context.Context) error {
				if got := running(); got != want {
					return fmt.Errorf("agent reports version %q, want %s", got, want)
				}
				return nil
			}
		}
		var asked []string
		in := &release.Installer{Target: target, RenameSwap: rs, HealthTimeout: 300 * time.Millisecond, Interval: 10 * time.Millisecond,
			Start: func(context.Context) error { return nil },
			Stop:  func(context.Context) error { return nil },
			// the new binary never reports the new version (it "crashes": the old one's answer is all there is)
			Healthy: func(ctx context.Context) error {
				asked = append(asked, "new")
				return errors.New("agent not answering")
			},
			HealthyPrevious: func(ctx context.Context) error { asked = append(asked, "previous"); return expect("old")(ctx) }}
		start := time.Now()
		err := in.Install(context.Background(), newPath)
		var rb *release.RolledBackError
		if !errors.As(err, &rb) || rb.RollbackErr != nil {
			t.Fatalf("renameSwap=%v: %v", rs, err)
		}
		if !strings.Contains(err.Error(), "rolled back to the previous version") || strings.Contains(err.Error(), "FAILED") {
			t.Fatalf("renameSwap=%v: %v", rs, err)
		}
		if running() != "old" {
			t.Fatalf("renameSwap=%v: not rolled back", rs)
		}
		if asked[len(asked)-1] != "previous" || asked[0] != "new" {
			t.Fatalf("renameSwap=%v: checks %v", rs, asked)
		}
		// the rollback's check passes at once: one health timeout in all, not two
		if d := time.Since(start); d > 550*time.Millisecond {
			t.Fatalf("renameSwap=%v: took %s", rs, d)
		}

		// without HealthyPrevious the one check is used for both, as before (the panel's own updater)
		target, newPath = setupTarget(t)
		f := &fakeSvc{target: target, failNew: true}
		if err := f.installer(rs).Install(context.Background(), newPath); !errors.As(err, &rb) || rb.RollbackErr != nil {
			t.Fatalf("renameSwap=%v, one check: %v", rs, err)
		}

		// A previous version that was put back and started but does not pass its check is not a clean rollback,
		// and it is not "rolling back FAILED too" either (review N2: that was said whenever something kept the
		// check from its answer, for example a full port, although the previous version was running). The
		// report says what is known: put back, started, check not passed, and why.
		target, newPath = setupTarget(t)
		in = &release.Installer{Target: target, RenameSwap: rs, HealthTimeout: 100 * time.Millisecond, Interval: 10 * time.Millisecond,
			Start: func(context.Context) error { return nil }, Stop: func(context.Context) error { return nil },
			Healthy:         func(context.Context) error { return errors.New("agent not answering") },
			HealthyPrevious: func(context.Context) error { return errors.New("agent not answering") }}
		err = in.Install(context.Background(), newPath)
		if !errors.As(err, &rb) || rb.RollbackErr == nil || !rb.Restored {
			t.Fatalf("renameSwap=%v, previous version not confirmed: %v", rs, err)
		}
		if msg := err.Error(); strings.Contains(msg, "FAILED") || strings.Contains(msg, "rolled back to the previous version") ||
			!strings.Contains(msg, "the previous version was put back and started again, but its health check did not pass") ||
			!strings.Contains(msg, "agent not answering") {
			t.Fatalf("renameSwap=%v, previous version not confirmed: %s", rs, msg)
		}
		if running() != "old" {
			t.Fatalf("renameSwap=%v: the previous binary is not back in place", rs)
		}

		// "rolling back FAILED too" is for a rollback that did fail: the previous version could not be started
		target, newPath = setupTarget(t)
		starts := 0
		in = &release.Installer{Target: target, RenameSwap: rs, HealthTimeout: 100 * time.Millisecond, Interval: 10 * time.Millisecond,
			Start: func(context.Context) error {
				if starts++; starts > 1 {
					return errors.New("unit failed")
				}
				return nil
			},
			Stop:    func(context.Context) error { return nil },
			Healthy: func(context.Context) error { return errors.New("agent not answering") }}
		err = in.Install(context.Background(), newPath)
		if !errors.As(err, &rb) || rb.RollbackErr == nil || rb.Restored || !strings.Contains(err.Error(), "rolling back FAILED too") ||
			!strings.Contains(err.Error(), "starting the previous version") {
			t.Fatalf("renameSwap=%v, previous version does not start: %v", rs, err)
		}
	}
}

func TestInstallerRefusesOtherFolder(t *testing.T) {
	target, _ := setupTarget(t)
	other := filepath.Join(t.TempDir(), "x")
	_ = os.WriteFile(other, []byte("new"), 0o644)
	f := &fakeSvc{target: target}
	if err := f.installer(false).Install(context.Background(), other); err == nil {
		t.Fatal("accepted a binary from another folder")
	}
}

func TestCopyVerifiedAndReadStaged(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged")
	_ = os.WriteFile(src, []byte("payload"), 0o644)
	if _, err := release.CopyVerified(src, dir, sha256.Sum256([]byte("other"))); err == nil {
		t.Fatal("mismatch accepted")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("left files behind: %v", ents)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(src, link); err == nil {
		if _, err := release.ReadStaged(link, 100); err == nil {
			t.Fatal("followed a symlink")
		}
		if _, err := release.CopyVerified(link, dir, sha256.Sum256([]byte("payload"))); err == nil {
			t.Fatal("copied through a symlink")
		}
	}
	if _, err := release.ReadStaged(dir, 100); err == nil {
		t.Fatal("read a directory")
	}
	if _, err := release.ReadStaged(src, 3); err == nil {
		t.Fatal("size limit")
	}
	if b, err := release.ReadStaged(src, 100); err != nil || string(b) != "payload" {
		t.Fatal(string(b), err)
	}
}
