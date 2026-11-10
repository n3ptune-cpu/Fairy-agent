package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release/releasetest"
)

const testAsset = "fairy-agent-linux-amd64"

type updRig struct {
	gh      *releasetest.Server
	u       *Updater
	stage   string
	result  string
	applied atomic.Int32
	srv     *httptest.Server
}

func newUpdRig(t *testing.T, version string, key ed25519.PublicKey) *updRig {
	t.Helper()
	r := &updRig{gh: releasetest.New(t, release.AgentRepo)}
	dir := t.TempDir()
	r.stage, r.result = filepath.Join(dir, "state", "update"), filepath.Join(dir, "result", "result.json")
	if key == nil {
		key = r.gh.Pub
	}
	r.u = NewUpdater(UpdaterOptions{Version: version, Key: key, Client: r.gh.Client(), StageDir: r.stage,
		ResultPath: r.result, Asset: testAsset, ResultWait: 200 * time.Millisecond,
		Apply: func(context.Context) error { r.applied.Add(1); return nil }})
	cfg := mustParse(t, "self_update: {enabled: true}\ncontrol_rate_per_min: 60\n")
	a := New(cfg, Tokens{Read: readTok, Control: ctlTok}, Deps{Collector: agenttest.NewCollector(), Updater: r.u, Version: version})
	r.srv = httptest.NewServer(a.Handler())
	t.Cleanup(r.srv.Close)
	return r
}

func (r *updRig) wait(t *testing.T) UpdateStatus {
	t.Helper()
	r.u.mu.Lock()
	done := r.u.done
	r.u.mu.Unlock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("update did not finish")
	}
	return r.u.Status()
}

func post(t *testing.T, url, tok string, body any) (int, map[string]any) {
	t.Helper()
	rr := &rig{srv: &httptest.Server{URL: url}}
	return rr.do(t, "POST", "/update", tok, body)
}

func TestSelfUpdateConfig(t *testing.T) {
	c := mustParse(t, "self_update: {enabled: true}\n")
	if !c.ControlEnabled() || c.SelfUpdate.Repo != release.AgentRepo {
		t.Fatalf("%+v", c.SelfUpdate)
	}
	for _, bad := range []string{"https://evil.example/x", "evil.example:443/x", "a/b/c", "o/.."} {
		if _, err := Parse([]byte("self_update: {enabled: true, repo: \""+bad+"\"}\n"), filepath.Join(t.TempDir(), "c.yaml")); err == nil {
			t.Fatalf("repo %q accepted", bad)
		}
	}
	if c := mustParse(t, "self_update: {enabled: true, repo: someone/Fairy-agent-fork}\n"); c.SelfUpdate.Repo != "someone/Fairy-agent-fork" {
		t.Fatal(c.SelfUpdate.Repo)
	}
	// enabling it needs the control token, like the other control features
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "token"), []byte(readTok), 0o600)
	c, _ = Parse([]byte("self_update: {enabled: true}\n"), filepath.Join(dir, "config.yaml"))
	if _, err := c.LoadTokens(); err == nil || !strings.Contains(err.Error(), "self-update") {
		t.Fatalf("control token not required: %v", err)
	}
}

func TestUpdateEndpointAuth(t *testing.T) {
	// off by default: 404 with a code, whoever asks
	off := newRig(t, "")
	if st, b := off.do(t, "POST", "/update", ctlTok, map[string]any{}); st != 404 || b["code"] != "self_update_disabled" {
		t.Fatalf("disabled: %d %v", st, b)
	}
	if st, b := off.do(t, "GET", "/metrics", readTok, nil); st != 200 || b["self_update"] != nil || b["features"].(map[string]any)["self_update"] != false {
		t.Fatalf("metrics without self_update: %v", b["features"])
	}
	r := newUpdRig(t, "41-aaaaaaa", nil)
	r.gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{testAsset: []byte("new")}, nil)
	for _, tok := range []string{"", readTok, "wrong-token-xxxxxxxxxxxxxxxxxxxxx"} {
		if st, _ := post(t, r.srv.URL, tok, map[string]any{}); st != 401 {
			t.Fatalf("token %q: %d", tok, st)
		}
	}
	if st, _ := (&rig{srv: r.srv}).do(t, "GET", "/update", ctlTok, nil); st != 405 {
		t.Fatalf("GET /update: %d", st)
	}
	if r.applied.Load() != 0 {
		t.Fatal("applied without a valid control token")
	}
	st, b := post(t, r.srv.URL, ctlTok, map[string]any{"requested_by": "Neptune <admin>"})
	if st != 202 || b["state"] != "downloading" {
		t.Fatalf("%d %v", st, b)
	}
	r.wait(t)
	if r.applied.Load() != 1 {
		t.Fatal("installer not started")
	}
}

func TestUpdaterStagesVerifiedRelease(t *testing.T) {
	r := newUpdRig(t, "41-aaaaaaa", nil)
	bin := []byte("fairy-agent build 42")
	r.gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{testAsset: bin, "fairy-agent-linux-arm64": []byte("arm")}, nil)
	if st, _ := r.u.Start(UpdateRequest{RequestedBy: "Neptune"}); st != 202 {
		t.Fatal(st)
	}
	if st, b := r.u.Start(UpdateRequest{}); st != 409 {
		t.Fatalf("second request while busy: %d %v", st, b)
	}
	st := r.wait(t)
	// no result file appears in this test: the "installer did not report back"
	if st.State != "failed" || !strings.Contains(st.Message, "did not report back") || st.Target != "42-bbbbbbb" {
		t.Fatalf("%+v", st)
	}
	if b, _ := os.ReadFile(filepath.Join(r.stage, testAsset)); string(b) != string(bin) {
		t.Fatalf("staged binary %q", b)
	}
	var req stageRequest
	b, _ := os.ReadFile(filepath.Join(r.stage, stageRequestFile))
	if json.Unmarshal(b, &req) != nil || req.From != "41-aaaaaaa" || req.To != "42-bbbbbbb" || req.RequestedBy != "Neptune" || req.ID == "" {
		t.Fatalf("%s", b)
	}
	if _, err := os.Stat(filepath.Join(r.stage, "fairy-agent-linux-arm64")); err == nil {
		t.Fatal("staged another platform's binary")
	}
	// the installer's result with the same id is picked up
	r.u.o.ResultWait = 5 * time.Second
	r.u.Start(UpdateRequest{Force: true})
	go func() { // the installer: answers the new request
		for i := 0; i < 200; i++ {
			var nreq stageRequest
			b, _ := os.ReadFile(filepath.Join(r.stage, stageRequestFile))
			if json.Unmarshal(b, &nreq) == nil && nreq.ID != req.ID {
				_ = writeResult(r.result, UpdateResult{ID: nreq.ID, OK: true, From: nreq.From, To: nreq.To, Message: "updated", At: 1})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if st := r.wait(t); st.State != "idle" || st.Last == nil || !st.Last.OK {
		t.Fatalf("%+v", st)
	}
}

func TestUpdaterRefusesBadReleases(t *testing.T) {
	cases := []struct {
		name    string
		version string
		publish func(gh *releasetest.Server)
		state   string
		msg     string
	}{
		{"up to date", "42-bbbbbbb", func(gh *releasetest.Server) {
			gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{testAsset: []byte("x")}, nil)
		}, "idle", "already up to date"},
		{"older", "43-ccccccc", func(gh *releasetest.Server) {
			gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{testAsset: []byte("x")}, nil)
		}, "failed", "not downgrading"},
		{"other key", "41-a", func(gh *releasetest.Server) {
			_, k, _ := ed25519.GenerateKey(nil)
			gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{testAsset: []byte("x")}, k)
		}, "failed", "signature"},
		{"tampered binary", "41-a", func(gh *releasetest.Server) {
			gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{testAsset: []byte("x")}, nil)
			gh.Replace(testAsset, []byte("evil"))
		}, "failed", "does not match"},
		{"no binary for this platform", "41-a", func(gh *releasetest.Server) {
			gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{"fairy-agent-windows-amd64.exe": []byte("x")}, nil)
		}, "failed", "has no " + testAsset},
		{"panel release", "41-a", func(gh *releasetest.Server) {
			gh.Publish("build-42", "fairy", "42-bbbbbbb", map[string][]byte{testAsset: []byte("x")}, nil)
		}, "failed", "not fairy-agent"},
		{"github down", "41-a", func(gh *releasetest.Server) { gh.SetBroken(true) }, "failed", "HTTP 503"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newUpdRig(t, c.version, nil)
			c.publish(r.gh)
			r.u.Start(UpdateRequest{})
			st := r.wait(t)
			if st.State != c.state || !strings.Contains(st.Message, c.msg) {
				t.Fatalf("%+v", st)
			}
			if r.applied.Load() != 0 {
				t.Fatal("installer started")
			}
			if _, err := os.Stat(filepath.Join(r.stage, testAsset)); err == nil {
				t.Fatal("binary staged")
			}
		})
	}
}

func TestUpdaterWithoutKeyIsUnavailable(t *testing.T) {
	u := NewUpdater(UpdaterOptions{Version: "dev", KeyErr: release.ErrNoKey})
	if st := u.Status(); st.State != "unavailable" || !strings.Contains(st.Message, "no release signing key") {
		t.Fatalf("%+v", st)
	}
	if st, b := u.Start(UpdateRequest{}); st != 503 || b["code"] != "self_update_unavailable" {
		t.Fatalf("%d %v", st, b)
	}
}

func TestUpdaterReportsLastResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	_ = writeResult(path, UpdateResult{ID: "ab", OK: false, From: "41-a", To: "42-b", Message: "update to 42-b failed: rolled back", At: float64(time.Now().Unix())})
	u := NewUpdater(UpdaterOptions{Version: "41-a", Key: make([]byte, 32), ResultPath: path})
	if st := u.Status(); st.State != "failed" || st.Last == nil || st.Last.To != "42-b" {
		t.Fatalf("%+v", st)
	}
	// the installer writes its verdict after this (restarted) agent is up: picked up without a restart
	path2 := filepath.Join(t.TempDir(), "result.json")
	u = NewUpdater(UpdaterOptions{Version: "42-b", Key: make([]byte, 32), ResultPath: path2})
	if st := u.Status(); st.State != "idle" || st.Last != nil {
		t.Fatalf("%+v", st)
	}
	_ = writeResult(path2, UpdateResult{ID: "cd", OK: true, From: "41-a", To: "42-b", Message: "updated from 41-a to 42-b", At: float64(time.Now().Unix())})
	u.mu.Lock()
	u.checkedAt = time.Time{}
	u.mu.Unlock()
	if st := u.Status(); st.State != "idle" || st.Last == nil || !st.Last.OK || st.Last.ID != "cd" {
		t.Fatalf("%+v", st)
	}
}

// ---- the installer side, with a fake service

type applyRig struct {
	gh       *releasetest.Server
	stage    string
	result   string
	target   string
	starts   int
	running  string // the "running" binary's content
	unhealty bool
}

func newApplyRig(t *testing.T, publishVersion string, bin []byte) *applyRig {
	t.Helper()
	ar := &applyRig{gh: releasetest.New(t, release.AgentRepo)}
	dir := t.TempDir()
	ar.stage, ar.result = filepath.Join(dir, "state", "update"), filepath.Join(dir, "res", "result.json")
	bindir := filepath.Join(dir, "bin")
	_ = os.MkdirAll(bindir, 0o755)
	ar.target = filepath.Join(bindir, "fairy-agent")
	_ = os.WriteFile(ar.target, []byte("installed 41"), 0o755)
	ar.gh.Publish("build-42", "fairy-agent", publishVersion, map[string][]byte{testAsset: bin}, nil)
	// stage it exactly as the agent does (its own stage step; the agent's refusals before it are not the
	// installer's, which must stand on its own)
	u := NewUpdater(UpdaterOptions{Version: "41-aaaaaaa", Key: ar.gh.Pub, Client: ar.gh.Client(), StageDir: ar.stage,
		ResultPath: ar.result, Asset: testAsset, ResultWait: time.Millisecond, Apply: func(context.Context) error { return nil }})
	ch, err := ar.gh.Client().Check(context.Background(), ar.gh.Pub, release.AgentProgram)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.stage(context.Background(), ch, false, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ar.stage, testAsset)); err != nil {
		t.Fatalf("not staged: %v", err)
	}
	return ar
}

func (ar *applyRig) apply(key ed25519.PublicKey) UpdateResult {
	if key == nil {
		key = ar.gh.Pub
	}
	in := &release.Installer{Target: ar.target, HealthTimeout: 200 * time.Millisecond, Interval: 10 * time.Millisecond,
		Start: func(context.Context) error {
			ar.starts++
			b, _ := os.ReadFile(ar.target)
			ar.running = string(b)
			return nil
		}}
	return ApplyStaged(context.Background(), ApplyOptions{StageDir: ar.stage, ResultPath: ar.result, Asset: testAsset,
		Key: key, CurrentVersion: "41-aaaaaaa", Installer: in,
		Healthy: func(_ context.Context, want string) error {
			if ar.unhealty && ar.running != "installed 41" {
				return errors.New("agent reports the old version")
			}
			return nil
		}})
}

func TestApplyStagedInstalls(t *testing.T) {
	ar := newApplyRig(t, "42-bbbbbbb", []byte("new 42"))
	res := ar.apply(nil)
	if !res.OK || res.To != "42-bbbbbbb" || res.From != "41-aaaaaaa" || len(res.ID) != 16 {
		t.Fatalf("%+v", res)
	}
	if b, _ := os.ReadFile(ar.target); string(b) != "new 42" {
		t.Fatalf("%q", b)
	}
	if b, _ := os.ReadFile(ar.target + ".old"); string(b) != "installed 41" {
		t.Fatalf(".old %q", b)
	}
	if r := readResult(ar.result); r == nil || !r.OK || r.ID != res.ID {
		t.Fatalf("result file %+v", r)
	}
}

func TestApplyStagedReverifiesAndRollsBack(t *testing.T) {
	// the stage is changed after the agent verified it (the agent's user owns it): refused
	ar := newApplyRig(t, "42-bbbbbbb", []byte("new 42"))
	_ = os.WriteFile(filepath.Join(ar.stage, testAsset), []byte("evil"), 0o600)
	if res := ar.apply(nil); res.OK || !strings.Contains(res.Message, "does not match") {
		t.Fatalf("%+v", res)
	}
	if b, _ := os.ReadFile(ar.target); string(b) != "installed 41" || ar.starts != 0 {
		t.Fatal("target touched")
	}
	// a forged SHA256SUMS (agent's user writes its own sums for its own binary) fails the signature
	ar = newApplyRig(t, "42-bbbbbbb", []byte("new 42"))
	forged := release.FormatSums([]string{testAsset}, map[string][]byte{testAsset: []byte("evil")})
	_ = os.WriteFile(filepath.Join(ar.stage, release.SumsFile), forged, 0o600)
	_ = os.WriteFile(filepath.Join(ar.stage, testAsset), []byte("evil"), 0o600)
	if res := ar.apply(nil); res.OK || !strings.Contains(res.Message, "signature") {
		t.Fatalf("%+v", res)
	}
	// the installer's own key differs from the one the agent used
	ar = newApplyRig(t, "42-bbbbbbb", []byte("new 42"))
	other, _, _ := ed25519.GenerateKey(nil)
	if res := ar.apply(other); res.OK {
		t.Fatal("other key accepted")
	}
	// symlinked stage file
	ar = newApplyRig(t, "42-bbbbbbb", []byte("new 42"))
	p := filepath.Join(ar.stage, testAsset)
	_ = os.Rename(p, p+".real")
	if os.Symlink(p+".real", p) == nil {
		if res := ar.apply(nil); res.OK {
			t.Fatal("followed a symlink in the stage")
		}
	}
	// unhealthy new version: rolled back, result says so
	ar = newApplyRig(t, "42-bbbbbbb", []byte("new 42"))
	ar.unhealty = true
	res := ar.apply(nil)
	if res.OK || !strings.Contains(res.Message, "rolled back") {
		t.Fatalf("%+v", res)
	}
	if b, _ := os.ReadFile(ar.target); string(b) != "installed 41" || ar.running != "installed 41" || ar.starts != 2 {
		t.Fatalf("not rolled back: %q running %q starts %d", b, ar.running, ar.starts)
	}
	if r := readResult(ar.result); r == nil || r.OK {
		t.Fatal("result file")
	}
	// nothing staged at all
	ar = newApplyRig(t, "42-bbbbbbb", []byte("new 42"))
	_ = os.RemoveAll(ar.stage)
	if res := ar.apply(nil); res.OK || !strings.Contains(res.Message, "nothing staged") {
		t.Fatalf("%+v", res)
	}
}

// The stage is written by the less privileged agent, so the installer never goes back to an older release, not
// even with force (that would let a compromised agent bring back an old flaw). force still reinstalls the same
// version.
func TestApplyStagedNeverDowngrades(t *testing.T) {
	ar := newApplyRig(t, "42-bbbbbbb", []byte("new 42"))
	var req stageRequest
	b, _ := os.ReadFile(filepath.Join(ar.stage, stageRequestFile))
	_ = json.Unmarshal(b, &req)
	in := &release.Installer{Target: ar.target, Start: func(context.Context) error { return nil }}
	apply := func(current string) UpdateResult {
		return ApplyStaged(context.Background(), ApplyOptions{StageDir: ar.stage, ResultPath: ar.result, Asset: testAsset,
			Key: ar.gh.Pub, CurrentVersion: current, Installer: in, Healthy: func(context.Context, string) error { return nil }})
	}
	if res := apply("50-ddddddd"); res.OK || !strings.Contains(res.Message, "not downgrading") {
		t.Fatalf("%+v", res)
	}
	req.Force = true
	nb, _ := json.Marshal(req)
	_ = os.WriteFile(filepath.Join(ar.stage, stageRequestFile), nb, 0o600)
	if res := apply("50-ddddddd"); res.OK || !strings.Contains(res.Message, "fairy-agent update --force") {
		t.Fatalf("forced downgrade: %+v", res)
	}
	if res := apply("42-bbbbbbb"); !res.OK {
		t.Fatalf("forced reinstall of the same version: %+v", res)
	}
}

// L23: the "never older" rule rests on build numbers. A validly signed release whose version has none (v0.4.2),
// or one of ten digits, used to pass as "newer" and went over build 20. The installer refuses it, with or
// without force in the stage; so does an installed version that cannot be compared (a local build).
func TestApplyStagedRefusesVersionsItCannotCompare(t *testing.T) {
	for _, c := range []struct{ current, staged, want string }{
		{"20-abcdef0", "v0.4.2", `the release's version "v0.4.2" does not start with a build number`},
		{"20-abcdef0", "1000000000-abcdef0", "more than 9 digits"},
		{"dev", "42-bbbbbbb", `the installed version "dev"`},
	} {
		for _, force := range []bool{false, true} {
			ar := newApplyRig(t, c.staged, []byte("other "+c.staged))
			var req stageRequest
			b, _ := os.ReadFile(filepath.Join(ar.stage, stageRequestFile))
			_ = json.Unmarshal(b, &req)
			req.Force = force
			nb, _ := json.Marshal(req)
			_ = os.WriteFile(filepath.Join(ar.stage, stageRequestFile), nb, 0o600)
			starts := 0
			in := &release.Installer{Target: ar.target, Start: func(context.Context) error { starts++; return nil }}
			res := ApplyStaged(context.Background(), ApplyOptions{StageDir: ar.stage, ResultPath: ar.result, Asset: testAsset,
				Key: ar.gh.Pub, CurrentVersion: c.current, Installer: in, Healthy: func(context.Context, string) error { return nil }})
			if res.OK || !strings.Contains(res.Message, c.want) || !strings.Contains(res.Message, "fairy-agent update --force") {
				t.Fatalf("%v force=%v: %+v", c, force, res)
			}
			if b, _ := os.ReadFile(ar.target); string(b) != "installed 41" || starts != 0 {
				t.Fatalf("%v force=%v: the program was touched (%q, %d starts)", c, force, b, starts)
			}
			if _, err := os.Stat(ar.target + ".old"); err == nil {
				t.Fatalf("%v force=%v: a backup was made", c, force)
			}
		}
	}
}

// L23, the agent's half: it does not download a release it cannot compare (the installer would refuse it).
func TestUpdaterRefusesVersionsItCannotCompare(t *testing.T) {
	for _, c := range []struct{ current, published string }{{"20-abcdef0", "v0.4.2"}, {"20-abcdef0", "1000000000-abcdef0"}, {"dev", "42-bbbbbbb"}} {
		for _, force := range []bool{false, true} {
			r := newUpdRig(t, c.current, nil)
			r.gh.Publish("build-42", "fairy-agent", c.published, map[string][]byte{testAsset: []byte("new")}, nil)
			if st, _ := post(t, r.srv.URL, ctlTok, map[string]any{"force": force}); st != 202 {
				t.Fatal(st)
			}
			st := r.wait(t)
			if st.State != "failed" || !strings.Contains(st.Message, "cannot be compared") || !strings.Contains(st.Message, "fairy-agent update --force") {
				t.Fatalf("%v force=%v: %+v", c, force, st)
			}
			if r.applied.Load() != 0 {
				t.Fatalf("%v force=%v: the installer was started", c, force)
			}
			if _, err := os.Stat(filepath.Join(r.stage, testAsset)); err == nil {
				t.Fatalf("%v force=%v: the release was downloaded", c, force)
			}
		}
	}
}

// Windows without the fairy-agent-update service (e.g. after an update from 0.4.2 through the panel, before an
// administrator ran setup-self-update): self-update says why and how to fix it, and picks it up once fixed.
func TestUpdaterNotReady(t *testing.T) {
	ready := errors.New("the panel's Update button needs the fairy-agent-update service, which is not installed: run setup-self-update")
	u := NewUpdater(UpdaterOptions{Version: "41-a", Key: make([]byte, 32), Ready: func() error { return ready }})
	if st := u.Status(); st.State != "unavailable" || !strings.Contains(st.Message, "setup-self-update") {
		t.Fatalf("%+v", st)
	}
	if st, b := u.Start(UpdateRequest{}); st != 503 || b["code"] != "self_update_unavailable" {
		t.Fatalf("%d %v", st, b)
	}
	ready = nil
	u.mu.Lock()
	u.readyAt = time.Now().Add(-2 * time.Minute)
	u.mu.Unlock()
	if st := u.Status(); st.State != "idle" {
		t.Fatalf("after setup: %+v", st)
	}
}

// A stage folder that is a link is refused (Linux: symlink; Windows: also junctions, through the attributes).
func TestApplyStagedRefusesLinkedStage(t *testing.T) {
	ar := newApplyRig(t, "42-bbbbbbb", []byte("new 42"))
	link := filepath.Join(t.TempDir(), "stage-link")
	if err := os.Symlink(ar.stage, link); err != nil {
		t.Skip(err)
	}
	in := &release.Installer{Target: ar.target, Start: func(context.Context) error { return nil }}
	res := ApplyStaged(context.Background(), ApplyOptions{StageDir: link, ResultPath: ar.result, Asset: testAsset,
		Key: ar.gh.Pub, CurrentVersion: "41-a", Installer: in, Healthy: func(context.Context, string) error { return nil }})
	if res.OK || !strings.Contains(res.Message, "not a plain folder") {
		t.Fatalf("%+v", res)
	}
}

func TestCheckRunning(t *testing.T) {
	r := newUpdRig(t, "42-bbbbbbb", nil)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "token"), []byte(readTok), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "control-token"), []byte(ctlTok), 0o600)
	addr := strings.TrimPrefix(r.srv.URL, "http://")
	cfg, err := Parse([]byte("listen: "+addr+"\nself_update: {enabled: true}\n"), filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckRunning(context.Background(), cfg, "42-bbbbbbb"); err != nil {
		t.Fatal(err)
	}
	if err := CheckRunning(context.Background(), cfg, "43-ccccccc"); err == nil {
		t.Fatal("wrong version accepted")
	}
}
