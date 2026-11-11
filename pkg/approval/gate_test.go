package approval_test

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// rig is one machine: a gate on a trust file in its own folder, a clock the test moves, and the made-up issuer.
type rig struct {
	t     testing.TB
	g     *approval.Gate
	iss   *approvaltest.Issuer
	files approval.Files
	log   *syncBuf

	mu     sync.Mutex
	now    time.Time
	uptime time.Duration
}

func (r *rig) Now() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
func (r *rig) wait(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.uptime += d
	r.mu.Unlock()
}

// newRig returns a machine without a trust file; with trusted, the issuer is set as its trust (first-time set).
func newRig(t testing.TB, trusted bool) *rig {
	t.Helper()
	r := &rig{t: t, iss: approvaltest.New(), log: &syncBuf{}, now: time.Unix(1794000000, 0), uptime: 3 * time.Hour}
	r.files = approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	r.g = r.gate()
	if trusted {
		if st, ref := r.g.Init(r.iss.Init()); ref != nil || st.State != api.ApprovalRequired {
			t.Fatalf("first-time set: %+v, %v", st, ref)
		}
	}
	return r
}

// gate is another gate on the same file and clock (the same machine after a restart, or a second process).
func (r *rig) gate() *approval.Gate {
	return approval.NewGate(approval.Options{Files: r.files, EnforcedBy: api.EnforcedByAgent, Now: r.Now,
		Uptime: func() (time.Duration, error) { r.mu.Lock(); defer r.mu.Unlock(); return r.uptime, nil },
		Log:    slog.New(slog.NewTextHandler(r.log, nil))})
}

func ip(i int) *int       { return &i }
func sp(s string) *string { return &s }

func power(action string, delay int) api.ApprovalRequest {
	return api.ApprovalRequest{Verb: api.ApprovePower, Action: sp(action), DelayS: ip(delay)}
}
func fanSet(zone, pct int) api.ApprovalRequest {
	return api.ApprovalRequest{Verb: api.ApproveFanSet, Zone: ip(zone), Percent: ip(pct)}
}
func fanMode(mode string) api.ApprovalRequest {
	return api.ApprovalRequest{Verb: api.ApproveFanMode, Mode: sp(mode)}
}

var update = api.ApprovalRequest{Verb: api.ApproveApplyUpdate}

// entry asks g for a challenge for req and returns the entry of an approval.
func (r *rig) entryFrom(g *approval.Gate, req api.ApprovalRequest) api.ApprovalEntry {
	r.t.Helper()
	c, ref := g.Challenge(req)
	if ref != nil || !c.Needed || len(c.Challenge) != api.ChallengeLen {
		r.t.Fatalf("challenge for %+v: %+v, %v", req, c, ref)
	}
	if want, _ := req.Canonical(); c.Request != want || c.Issuer != r.iss.URL || c.ClientID != r.iss.ClientID {
		r.t.Fatalf("challenge answer %+v", c)
	}
	return api.ApprovalEntry{Challenge: c.Challenge, Request: c.Request}
}

func (r *rig) entry(req api.ApprovalRequest) api.ApprovalEntry { return r.entryFrom(r.g, req) }

// approve is a good approval of req on this machine: challenge, then the issuer's token.
func (r *rig) approve(req api.ApprovalRequest) *api.Approval {
	r.t.Helper()
	return r.iss.Approve(r.Now(), r.entry(req))
}

// refused checks that ref is a refusal with code and, for approval_refused, with the reason.
func refused(t *testing.T, what string, ref *approval.Refusal, code, reason string) {
	t.Helper()
	if ref == nil {
		t.Errorf("%s: accepted, want %s %s", what, code, reason)
		return
	}
	if ref.Code != code || (reason != "" && !strings.HasPrefix(ref.Msg, "approval refused ("+reason+")")) {
		t.Errorf("%s: %d %s %q, want %s %s", what, ref.Status, ref.Code, ref.Msg, code, reason)
	}
}

func accepted(t *testing.T, what string, ref *approval.Refusal) {
	t.Helper()
	if ref != nil {
		t.Errorf("%s: refused: %v", what, ref)
	}
}

func TestOffLetsEverythingRun(t *testing.T) {
	r := newRig(t, false)
	st := r.g.Status()
	if st.State != api.ApprovalOff || st.EnforcedBy != api.EnforcedByAgent || st.Proto != api.ApprovalProto || st.Issuer != "" || st.Keys != nil {
		t.Fatalf("status %+v", st)
	}
	for _, req := range []api.ApprovalRequest{power("shutdown", 60), fanSet(0, 50), fanMode("full"), update} {
		accepted(t, "off", r.g.Check(req, nil))
		c, ref := r.g.Challenge(req)
		if ref != nil || c.Needed || c.Reason != "off" || c.Challenge != "" {
			t.Errorf("challenge while off: %+v, %v", c, ref)
		}
	}
	// an approval sent to a machine without trust is not looked at
	accepted(t, "off, with junk", r.g.Check(power("reboot", 60), &api.Approval{Token: "junk"}))
	var none *approval.Gate
	accepted(t, "no gate", none.Check(power("shutdown", 60), nil))
	if r.log.String() != "" {
		t.Errorf("a machine without trust wrote to the log:\n%s", r.log.String())
	}
}

func TestApprovedOnceThenRefused(t *testing.T) {
	r := newRig(t, true)
	st := r.g.Status()
	if st.State != api.ApprovalRequired || st.Issuer != r.iss.URL || st.ClientID != r.iss.ClientID || st.Users != 1 ||
		len(st.Keys) != 1 || st.Keys[0].Kid != r.iss.Kid || len(st.Keys[0].Thumbprint) != 43 || *st.FanWindowS != 30 || *st.BootShutdownS != 0 {
		t.Fatalf("status %+v", st)
	}
	req := power("shutdown", 60)
	refused(t, "no approval", r.g.Check(req, nil), api.CodeApprovalRequired, "")
	ap := r.approve(req)
	accepted(t, "approved", r.g.Check(req, ap))
	// replay: the same approval a second time
	refused(t, "replay", r.g.Check(req, ap), api.CodeApprovalRefused, approval.ReasonNoChallenge)
	// and no window for power: the next one needs its own
	refused(t, "second shutdown", r.g.Check(req, nil), api.CodeApprovalRequired, "")
	refused(t, "update", r.g.Check(update, nil), api.CodeApprovalRequired, "")
	log := r.log.String()
	for _, want := range []string{"approval: accepted", "sub=" + approvaltest.User, "kid=" + approvaltest.Kid, "name=neptune",
		`request="power action=shutdown delay_s=60"`, "challenge=" + ap.Entries[0].Challenge[:8], "approval: refused", "reason=no_challenge",
		"approval: required, none sent"} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
	// nothing of the token and no whole challenge is in the log
	for _, part := range append(strings.Split(ap.Token, "."), ap.Entries[0].Challenge) {
		if strings.Contains(log, part) {
			t.Errorf("the log holds a part of the token or the whole challenge")
		}
	}
}

func TestSwappedActionIsRefused(t *testing.T) {
	r := newRig(t, true)
	ap := r.approve(fanSet(0, 50))
	// the approval of a fan change presented for a shutdown, unchanged
	refused(t, "other verb", r.g.Check(power("shutdown", 10), ap), api.CodeApprovalRefused, approval.ReasonNoChallenge)
	// ... for another duty
	refused(t, "other value", r.g.Check(fanSet(0, 100), ap), api.CodeApprovalRefused, approval.ReasonNoChallenge)
	// ... with the entry rewritten to the request wanted: this machine issued that challenge for something else
	swapped := &api.Approval{Token: ap.Token, Entries: []api.ApprovalEntry{{Challenge: ap.Entries[0].Challenge, Request: "power action=shutdown delay_s=10"}}}
	refused(t, "rewritten entry", r.g.Check(power("shutdown", 10), swapped), api.CodeApprovalRefused, approval.ReasonEntries)
	// ... with a fresh challenge for the shutdown put next to the approved token: the token's nonce is not this list's
	fresh := r.entry(power("shutdown", 10))
	refused(t, "fresh challenge, old token", r.g.Check(power("shutdown", 10), &api.Approval{Token: ap.Token, Entries: []api.ApprovalEntry{fresh}}),
		api.CodeApprovalRefused, approval.ReasonNonce)
	refused(t, "fresh challenge added to the list", r.g.Check(power("shutdown", 10), &api.Approval{Token: ap.Token, Entries: []api.ApprovalEntry{ap.Entries[0], fresh}}),
		api.CodeApprovalRefused, approval.ReasonNonce)
	// none of the attempts used the real approval up
	accepted(t, "the approved request itself", r.g.Check(fanSet(0, 50), ap))
}

func TestOtherMachinesApprovalIsRefused(t *testing.T) {
	a, b := newRig(t, true), newRig(t, true)
	req := power("reboot", 60)
	ap := a.approve(req)
	refused(t, "machine B, approval of machine A", b.g.Check(req, ap), api.CodeApprovalRefused, approval.ReasonNoChallenge)
	accepted(t, "machine A", a.g.Check(req, ap))
}

func TestBatchOneTokenSeveralMachines(t *testing.T) {
	a, b := newRig(t, true), newRig(t, true)
	ea1, ea2, eb := a.entry(update), a.entry(power("shutdown", 60)), b.entry(update)
	ap := a.iss.Approve(a.Now(), ea1, eb, ea2)
	accepted(t, "A update", a.g.Check(update, ap))
	accepted(t, "B update", b.g.Check(update, ap))
	accepted(t, "A shutdown", a.g.Check(power("shutdown", 60), ap))
	refused(t, "A update again", a.g.Check(update, ap), api.CodeApprovalRefused, approval.ReasonNoChallenge)
	refused(t, "B shutdown (never asked there)", b.g.Check(power("shutdown", 60), ap), api.CodeApprovalRefused, approval.ReasonNoChallenge)

	// the same request twice on one machine in one list: which entry is meant cannot be told
	e1, e2 := a.entry(update), a.entry(update)
	refused(t, "same request twice", a.g.Check(update, a.iss.Approve(a.Now(), e1, e2)), api.CodeApprovalRefused, approval.ReasonAmbiguous)
	// a challenge twice in the list
	dup := &api.Approval{Token: ap.Token, Entries: []api.ApprovalEntry{e1, e1}}
	refused(t, "challenge twice", a.g.Check(update, dup), api.CodeApprovalRefused, approval.ReasonEntries)
}

func TestChallengeExpiresAndStoreIsBounded(t *testing.T) {
	r := newRig(t, true)
	req := power("sleep", 30)
	ap := r.approve(req)
	r.wait(approval.ChallengeTTL - time.Second)
	fresh := r.iss.Approve(r.Now(), ap.Entries...) // authenticated just now, for the old challenge
	r.wait(time.Second)
	refused(t, "after its time", r.g.Check(req, fresh), api.CodeApprovalRefused, approval.ReasonExpired)
	refused(t, "and gone", r.g.Check(req, fresh), api.CodeApprovalRefused, approval.ReasonNoChallenge)

	// an update's challenge lives longer (the download is in between)
	c, _ := r.g.Challenge(update)
	if c.ExpiresInS != int(approval.UpdateChallengeTTL/time.Second) {
		t.Errorf("update challenge lives %d s", c.ExpiresInS)
	}
	e := api.ApprovalEntry{Challenge: c.Challenge, Request: c.Request}
	r.wait(approval.UpdateChallengeTTL - time.Second)
	accepted(t, "update just in time", r.g.Check(update, r.iss.Approve(r.Now(), e)))

	// 16 open challenges at most: the 17th drops the oldest
	first := r.entry(fanSet(0, 40))
	var last api.ApprovalEntry
	for i := 0; i < approval.MaxChallenges; i++ {
		last = r.entry(fanSet(1, 40+i))
	}
	refused(t, "oldest of 17", r.g.Check(fanSet(0, 40), r.iss.Approve(r.Now(), first)), api.CodeApprovalRefused, approval.ReasonNoChallenge)
	accepted(t, "newest of 17", r.g.Check(fanSet(1, 40+approval.MaxChallenges-1), r.iss.Approve(r.Now(), last)))
}

func TestFanWindow(t *testing.T) {
	r := newRig(t, true)
	refused(t, "fan, nothing approved yet", r.g.Check(fanSet(0, 50), nil), api.CodeApprovalRequired, "")
	accepted(t, "approved fan change", r.g.Check(fanMode("full"), r.approve(fanMode("full"))))
	accepted(t, "another duty, no approval", r.g.Check(fanSet(0, 60), nil))
	accepted(t, "another mode, no approval", r.g.Check(fanMode("optimal"), nil))
	if c, ref := r.g.Challenge(fanSet(1, 70)); ref != nil || c.Needed || c.Reason != "fan_window" {
		t.Errorf("challenge in the window: %+v, %v", c, ref)
	}
	// the window is for fans only
	refused(t, "shutdown in the fan window", r.g.Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	refused(t, "update in the fan window", r.g.Check(update, nil), api.CodeApprovalRequired, "")
	if c, _ := r.g.Challenge(power("shutdown", 60)); !c.Needed {
		t.Error("a shutdown needs no approval in the fan window")
	}
	// an approval that is sent is checked, window or not
	bad := &api.Approval{Token: "x.y.z", Entries: []api.ApprovalEntry{{Challenge: strings.Repeat("A", 43), Request: "fan_set zone=0 percent=55"}}}
	refused(t, "bad approval in the window", r.g.Check(fanSet(0, 55), bad), api.CodeApprovalRefused, approval.ReasonNoChallenge)
	// further changes do not move the window's end
	r.wait(29 * time.Second)
	accepted(t, "second 29", r.g.Check(fanSet(0, 61), nil))
	r.wait(time.Second)
	refused(t, "second 30", r.g.Check(fanSet(0, 62), nil), api.CodeApprovalRequired, "")
	if !strings.Contains(r.log.String(), "approval: not needed, fan window") {
		t.Errorf("the log does not say the window was used:\n%s", r.log.String())
	}
	// an approved shutdown opens no fan window
	accepted(t, "approved shutdown", r.g.Check(power("shutdown", 60), r.approve(power("shutdown", 60))))
	refused(t, "fan after a shutdown's approval", r.g.Check(fanSet(0, 50), nil), api.CodeApprovalRequired, "")
}

// setLocal changes the machine's trust the way the administrator's command does.
func (r *rig) setLocal(change func(t *approval.Trust)) {
	r.t.Helper()
	_, old, _, err := r.files.Load()
	if err != nil || old == nil {
		r.t.Fatalf("no trust to change: %v", err)
	}
	change(old)
	nt, err := approval.NewTrust(*old)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.files.Replace(nt); err != nil {
		r.t.Fatal(err)
	}
	r.wait(6 * time.Second) // the gate looks at the file again within 5 s
}

func TestFanWindowSettingAndTrustChange(t *testing.T) {
	r := newRig(t, true)
	pending := r.approve(power("reboot", 60)) // approved under the old trust, not yet used
	r.setLocal(func(tr *approval.Trust) { tr.FanWindowS = ip(0) })
	if st := r.g.Status(); *st.FanWindowS != 0 {
		t.Fatalf("status %+v", st)
	}
	// a change of the trust file drops what was open
	refused(t, "approval from before the change", r.g.Check(power("reboot", 60), pending), api.CodeApprovalRefused, approval.ReasonNoChallenge)
	accepted(t, "approved fan change", r.g.Check(fanSet(0, 50), r.approve(fanSet(0, 50))))
	refused(t, "window off", r.g.Check(fanSet(0, 60), nil), api.CodeApprovalRequired, "")
	if _, err := approval.NewTrust(approval.Trust{Issuer: r.iss.URL, ClientID: r.iss.ClientID, Keys: r.iss.Init().Keys,
		Users: []string{"u"}, FanWindowS: ip(61)}); err == nil {
		t.Error("a fan window of 61 s was accepted")
	}
}

func TestShutdownShortlyAfterBoot(t *testing.T) {
	r := newRig(t, true)
	r.mu.Lock()
	r.uptime = 100 * time.Second
	r.mu.Unlock()
	refused(t, "setting off (default)", r.g.Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	r.setLocal(func(tr *approval.Trust) { tr.BootShutdownS = 600 }) // uptime is now 106 s
	if st := r.g.Status(); *st.BootShutdownS != 600 {
		t.Fatalf("status %+v", st)
	}
	refused(t, "reboot", r.g.Check(power("reboot", 60), nil), api.CodeApprovalRequired, "")
	refused(t, "sleep", r.g.Check(power("sleep", 60), nil), api.CodeApprovalRequired, "")
	refused(t, "fan", r.g.Check(fanSet(0, 50), nil), api.CodeApprovalRequired, "")
	refused(t, "update", r.g.Check(update, nil), api.CodeApprovalRequired, "")
	if c, ref := r.g.Challenge(power("shutdown", 60)); ref != nil || c.Needed || c.Reason != "boot_shutdown" {
		t.Errorf("challenge: %+v, %v", c, ref)
	}
	accepted(t, "the one shutdown", r.g.Check(power("shutdown", 60), nil))
	refused(t, "a second one", r.g.Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	if c, _ := r.g.Challenge(power("shutdown", 60)); !c.Needed {
		t.Error("after the one shutdown a challenge says none is needed")
	}
	if !strings.Contains(r.log.String(), "UNAPPROVED shutdown accepted shortly after boot") || !strings.Contains(r.log.String(), "uptime_s=106") {
		t.Errorf("the log does not mark the unapproved shutdown:\n%s", r.log.String())
	}
	// too late after boot: a new process (helper restarted) at uptime 600 s
	late := newRig(t, true)
	late.mu.Lock()
	late.uptime = 594 * time.Second
	late.mu.Unlock()
	late.setLocal(func(tr *approval.Trust) { tr.BootShutdownS = 600 })
	refused(t, "at 600 s", late.g.Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	// uptime unknown: never
	blind := approval.NewGate(approval.Options{Files: late.files, Now: late.Now, Log: slog.New(slog.NewTextHandler(late.log, nil)),
		Uptime: func() (time.Duration, error) { return 0, errors.New("no uptime") }})
	refused(t, "uptime unknown", blind.Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	if _, err := approval.NewTrust(approval.Trust{Issuer: r.iss.URL, ClientID: r.iss.ClientID, Keys: r.iss.Init().Keys,
		Users: []string{"u"}, BootShutdownS: 901}); err == nil {
		t.Error("boot_shutdown_s of 901 was accepted")
	}
}

func TestSameApprovalAtTheSameTime(t *testing.T) {
	r := newRig(t, true)
	req := power("shutdown", 60)
	ap := r.approve(req)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.g.Check(req, ap) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Errorf("%d of 16 requests with the same approval were accepted, want exactly 1", ok)
	}
}

func TestFirstTimeSetThenLocked(t *testing.T) {
	r := newRig(t, false)
	other := *r.iss
	other.URL, other.Key, other.Kid = "https://evil.test.invalid", approvaltest.Key(1), "evil"
	st, ref := r.g.Init(r.iss.Init("user-a", "user-b"))
	if ref != nil || st.State != api.ApprovalRequired || st.Users != 2 || *st.FanWindowS != 30 || *st.BootShutdownS != 0 {
		t.Fatalf("first-time set: %+v, %v", st, ref)
	}
	before, _ := os.ReadFile(r.files.Path)
	// locked: the same values, other values, from this gate or a new one (restart)
	for name, g := range map[string]*approval.Gate{"same gate": r.g, "after a restart": r.gate()} {
		for _, in := range []api.TrustInit{r.iss.Init("user-a", "user-b"), other.Init()} {
			st, ref := g.Init(in)
			refused(t, name, ref, api.CodeTrustAlreadySet, "")
			if ref != nil && ref.Status != 409 {
				t.Errorf("%s: status %d", name, ref.Status)
			}
			if st.Issuer != r.iss.URL {
				t.Errorf("%s: status after a refused set: %+v", name, st)
			}
		}
	}
	after, _ := os.ReadFile(r.files.Path)
	if !bytes.Equal(before, after) {
		t.Error("a refused set changed the trust file")
	}
	tr, err := approval.ParseTrust(after)
	if err != nil || tr.SetBy != "panel" || tr.SetAt == "" {
		t.Errorf("trust file: %+v, %v", tr, err)
	}
	if !strings.Contains(r.log.String(), "trust set for the first time, from the panel") || !strings.Contains(r.log.String(), "reason=already_set") {
		t.Errorf("log:\n%s", r.log.String())
	}
	// the evil issuer's tokens are worth nothing here
	req := power("shutdown", 60)
	e := r.entry(req)
	refused(t, "token of another issuer and key", r.g.Check(req, other.Approve(r.Now(), e)), api.CodeApprovalRefused, approval.ReasonKey)

	// only removing the file on the machine (helper-trust clear) opens the first-time set again
	if err := r.files.Remove(); err != nil {
		t.Fatal(err)
	}
	r.wait(6 * time.Second)
	if st := r.g.Status(); st.State != api.ApprovalOff {
		t.Fatalf("after the local clear: %+v", st)
	}
	accepted(t, "off again", r.g.Check(req, nil))
	if st, ref := r.g.Init(other.Init()); ref != nil || st.Issuer != other.URL {
		t.Errorf("set after a local clear: %+v, %v", st, ref)
	}
}

func TestFirstTimeSetExactlyOneWins(t *testing.T) {
	r := newRig(t, false)
	// 12 requests at once through 4 gates on the same file (one process, and others that got there some other way)
	gates := []*approval.Gate{r.g, r.gate(), r.gate(), r.gate()}
	var wg sync.WaitGroup
	var mu sync.Mutex
	won, lost := []string{}, 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			iss := *r.iss
			iss.ClientID = "client-" + string(rune('a'+i))
			_, ref := gates[i%len(gates)].Init(iss.Init())
			mu.Lock()
			defer mu.Unlock()
			switch {
			case ref == nil:
				won = append(won, iss.ClientID)
			case ref.Code == api.CodeTrustAlreadySet:
				lost++
			default:
				t.Errorf("request %d: %v", i, ref)
			}
		}()
	}
	wg.Wait()
	if len(won) != 1 || lost != 11 {
		t.Fatalf("%d won, %d lost; want 1 and 11", len(won), lost)
	}
	_, tr, _, err := r.files.Load()
	if err != nil || tr.ClientID != won[0] {
		t.Errorf("the file holds %+v (%v), the winner sent %s", tr, err, won[0])
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(r.files.Path), ".approval-trust-*"))
	if len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestFirstTimeSetRefusesBadValues(t *testing.T) {
	good := approvaltest.New().Init()
	small := approval.KeyFromRSA("small", &mustKey(t, 1024).PublicKey)
	for name, c := range map[string]struct {
		change func(in *api.TrustInit)
		code   string
	}{
		"http issuer":          {func(in *api.TrustInit) { in.Issuer = "http://id.test.invalid" }, api.CodeTrustInvalid},
		"issuer with query":    {func(in *api.TrustInit) { in.Issuer += "?a=b" }, api.CodeTrustInvalid},
		"issuer with fragment": {func(in *api.TrustInit) { in.Issuer += "#x" }, api.CodeTrustInvalid},
		"issuer with user":     {func(in *api.TrustInit) { in.Issuer = "https://u:p@id.test.invalid" }, api.CodeTrustInvalid},
		"issuer without host":  {func(in *api.TrustInit) { in.Issuer = "https://" }, api.CodeTrustInvalid},
		"issuer with space":    {func(in *api.TrustInit) { in.Issuer = "https://id.test.invalid/a b" }, api.CodeTrustInvalid},
		"empty issuer":         {func(in *api.TrustInit) { in.Issuer = "" }, api.CodeTrustInvalid},
		"long issuer":          {func(in *api.TrustInit) { in.Issuer = "https://id.test.invalid/" + strings.Repeat("a", 250) }, api.CodeTrustInvalid},
		"empty client":         {func(in *api.TrustInit) { in.ClientID = "" }, api.CodeTrustInvalid},
		"client with quote":    {func(in *api.TrustInit) { in.ClientID = `a"b` }, api.CodeTrustInvalid},
		"no users":             {func(in *api.TrustInit) { in.Users = nil }, api.CodeTrustInvalid},
		"empty user":           {func(in *api.TrustInit) { in.Users = []string{""} }, api.CodeTrustInvalid},
		"user with space":      {func(in *api.TrustInit) { in.Users = []string{"a b"} }, api.CodeTrustInvalid},
		"user twice":           {func(in *api.TrustInit) { in.Users = []string{"a", "a"} }, api.CodeTrustInvalid},
		"too many users":       {func(in *api.TrustInit) { in.Users = strings.Fields(strings.Repeat("u ", 33)) }, api.CodeTrustInvalid},
		"no keys":              {func(in *api.TrustInit) { in.Keys = nil }, api.CodeTrustInvalid},
		"five keys": {func(in *api.TrustInit) {
			for _, kid := range []string{"b", "c", "d", "e"} {
				k := in.Keys[0]
				k.Kid = kid
				in.Keys = append(in.Keys, k)
			}
		}, api.CodeTrustInvalid},
		"kid twice":        {func(in *api.TrustInit) { in.Keys = append(in.Keys, in.Keys[0]) }, api.CodeTrustInvalid},
		"empty kid":        {func(in *api.TrustInit) { in.Keys[0].Kid = "" }, api.CodeTrustInvalid},
		"kid with space":   {func(in *api.TrustInit) { in.Keys[0].Kid = "a b" }, api.CodeTrustInvalid},
		"use enc":          {func(in *api.TrustInit) { in.Keys[0].Use = "enc" }, api.CodeTrustInvalid},
		"padded n":         {func(in *api.TrustInit) { in.Keys[0].N += "=" }, api.CodeTrustInvalid},
		"n not base64url":  {func(in *api.TrustInit) { in.Keys[0].N = "+" + in.Keys[0].N[1:] }, api.CodeTrustInvalid},
		"n with a newline": {func(in *api.TrustInit) { in.Keys[0].N = in.Keys[0].N[:100] + "\n" + in.Keys[0].N[100:] }, api.CodeTrustInvalid},
		"n with zero byte": {func(in *api.TrustInit) { in.Keys[0].N = "AA" + in.Keys[0].N }, api.CodeTrustInvalid},
		"even n":           {func(in *api.TrustInit) { in.Keys[0].N = in.Keys[0].N[:len(in.Keys[0].N)-1] + "A" }, api.CodeTrustInvalid},
		"EC key":           {func(in *api.TrustInit) { in.Keys[0].Kty = "EC" }, api.CodeTrustUnsupportedKey},
		"OKP key":          {func(in *api.TrustInit) { in.Keys[0].Kty = "OKP" }, api.CodeTrustUnsupportedKey},
		"symmetric key":    {func(in *api.TrustInit) { in.Keys[0].Kty = "oct" }, api.CodeTrustUnsupportedKey},
		"alg ES256":        {func(in *api.TrustInit) { in.Keys[0].Alg = "ES256" }, api.CodeTrustUnsupportedKey},
		"alg HS256":        {func(in *api.TrustInit) { in.Keys[0].Alg = "HS256" }, api.CodeTrustUnsupportedKey},
		"alg none":         {func(in *api.TrustInit) { in.Keys[0].Alg = "none" }, api.CodeTrustUnsupportedKey},
		"alg missing":      {func(in *api.TrustInit) { in.Keys[0].Alg = "" }, api.CodeTrustUnsupportedKey},
		"exponent 3":       {func(in *api.TrustInit) { in.Keys[0].E = "Aw" }, api.CodeTrustUnsupportedKey},
		"1024-bit key":     {func(in *api.TrustInit) { in.Keys[0] = small }, api.CodeTrustUnsupportedKey},
		"huge modulus":     {func(in *api.TrustInit) { in.Keys[0].N = strings.Repeat("_", 1400) }, api.CodeTrustUnsupportedKey},
	} {
		r := newRig(t, false)
		in := good
		in.Keys = append([]api.TrustKey(nil), good.Keys...)
		c.change(&in)
		st, ref := r.g.Init(in)
		refused(t, name, ref, c.code, "")
		if ref != nil && ref.Status != 400 {
			t.Errorf("%s: status %d", name, ref.Status)
		}
		if st.State != api.ApprovalOff {
			t.Errorf("%s: state %s after a refused set", name, st.State)
		}
		if _, err := os.Lstat(r.files.Path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: a refused set left a trust file", name)
		}
		// and the machine still takes a good one
		if _, ref := r.g.Init(good); ref != nil {
			t.Errorf("%s: a good set after the refused one: %v", name, ref)
		}
	}
}

func TestBrokenTrustFailsClosed(t *testing.T) {
	good := approvaltest.New().Init()
	gt, _ := approval.FromInit(good, time.Unix(1794000000, 0))
	unknown := bytes.Replace(gt.Marshal(), []byte(`"version"`), []byte(`"extra": 1, "version"`), 1)
	twice := bytes.Replace(gt.Marshal(), []byte(`"version": 1`), []byte(`"version": 1, "Version": 1`), 1)
	for name, damage := range map[string]func(t *testing.T, path string){
		"empty file":     func(t *testing.T, p string) { must(t, os.WriteFile(p, nil, 0o600)) },
		"not JSON":       func(t *testing.T, p string) { must(t, os.WriteFile(p, []byte("issuer: x\n"), 0o600)) },
		"cut off":        func(t *testing.T, p string) { must(t, os.WriteFile(p, gt.Marshal()[:200], 0o600)) },
		"trailing data":  func(t *testing.T, p string) { must(t, os.WriteFile(p, append(gt.Marshal(), '{', '}'), 0o600)) },
		"unknown member": func(t *testing.T, p string) { must(t, os.WriteFile(p, unknown, 0o600)) },
		"a member twice": func(t *testing.T, p string) { must(t, os.WriteFile(p, twice, 0o600)) },
		"no users": func(t *testing.T, p string) {
			must(t, os.WriteFile(p, bytes.Replace(gt.Marshal(), []byte(approvaltest.User), nil, 1), 0o600))
		},
		"version 2": func(t *testing.T, p string) {
			must(t, os.WriteFile(p, bytes.Replace(gt.Marshal(), []byte(`"version": 1`), []byte(`"version": 2`), 1), 0o600))
		},
		"too large": func(t *testing.T, p string) {
			must(t, os.WriteFile(p, append(gt.Marshal(), bytes.Repeat([]byte(" "), 70<<10)...), 0o600))
		},
		"a folder":        func(t *testing.T, p string) { must(t, os.Mkdir(p, 0o700)) },
		"a dangling link": func(t *testing.T, p string) { must(t, os.Symlink(filepath.Join(filepath.Dir(p), "nowhere"), p)) },
		"a link to a file": func(t *testing.T, p string) {
			must(t, os.WriteFile(p+".real", gt.Marshal(), 0o600))
			must(t, os.Symlink(p+".real", p))
		},
	} {
		r := newRig(t, false)
		damage(t, r.files.Path)
		st := r.g.Status()
		if st.State != api.ApprovalBroken || st.Error == "" || st.Issuer != "" {
			t.Errorf("%s: status %+v", name, st)
			continue
		}
		for _, req := range []api.ApprovalRequest{power("shutdown", 60), fanSet(0, 50), fanMode("full"), update} {
			ref := r.g.Check(req, nil)
			refused(t, name, ref, api.CodeApprovalUnavailable, "")
			if ref != nil && ref.Status != 503 {
				t.Errorf("%s: status %d", name, ref.Status)
			}
		}
		if _, ref := r.g.Challenge(update); ref == nil || ref.Code != api.CodeApprovalUnavailable {
			t.Errorf("%s: challenge: %v", name, ref)
		}
		// not "no trust": the panel cannot set it either
		if _, ref := r.g.Init(good); ref == nil || ref.Code != api.CodeTrustAlreadySet {
			t.Errorf("%s: first-time set on a broken trust file: %v", name, ref)
		}
	}
}

func TestUnsafeFolderOrFileFailsClosed(t *testing.T) {
	r := newRig(t, true)
	bad := errors.New("others can write here")
	folder := r.files
	folder.CheckDir = func(string) error { return bad }
	file := r.files
	file.CheckFile = func(string) error { return bad }
	for name, f := range map[string]approval.Files{"folder": folder, "file": file} {
		g := approval.NewGate(approval.Options{Files: f, Now: r.Now, Log: slog.New(slog.NewTextHandler(r.log, nil))})
		if st := g.Status(); st.State != api.ApprovalBroken || !strings.Contains(st.Error, "others can write here") {
			t.Errorf("%s: %+v", name, st)
		}
		refused(t, name, g.Check(power("shutdown", 60), nil), api.CodeApprovalUnavailable, "")
	}
	// an unsafe folder WITHOUT a trust file is not "off" either: somebody may have removed the file
	empty := newRig(t, false)
	ef := empty.files
	ef.CheckDir = func(string) error { return bad }
	g := approval.NewGate(approval.Options{Files: ef, Now: empty.Now, Log: slog.New(slog.NewTextHandler(empty.log, nil))})
	if st := g.Status(); st.State != api.ApprovalBroken {
		t.Errorf("unsafe folder, no file: %+v", st)
	}
	refused(t, "unsafe folder, no file", g.Check(power("shutdown", 60), nil), api.CodeApprovalUnavailable, "")
	if _, ref := g.Init(empty.iss.Init()); ref == nil {
		t.Error("trust was set into an unsafe folder")
	}
	// no folder at all: nothing was ever set up here
	gone := approval.NewGate(approval.Options{Files: approval.Files{Path: filepath.Join(t.TempDir(), "missing", approval.TrustFileName)},
		Log: slog.New(slog.NewTextHandler(empty.log, nil))})
	if st := gone.Status(); st.State != api.ApprovalOff {
		t.Errorf("no folder: %+v", st)
	}
	if _, ref := gone.Init(empty.iss.Init()); ref == nil || ref.Status != 500 {
		t.Errorf("first-time set without a folder: %v", ref)
	}
	if st := gone.Status(); st.State != api.ApprovalOff {
		t.Errorf("after the failed set: %+v", st)
	}
}

// TestCreateNeverReplaces: the first-time write does not replace a file that appeared in the meantime (the
// administrator's command, another process), and a failed write leaves no trust file.
func TestCreateNeverReplaces(t *testing.T) {
	r := newRig(t, false)
	admin, _ := approval.NewTrust(approval.Trust{Issuer: "https://admin.test.invalid", ClientID: "admin", Keys: r.iss.Init().Keys, Users: []string{"root"}})
	must(t, r.files.Replace(admin))
	panel, _ := approval.FromInit(r.iss.Init(), r.Now())
	if err := r.files.Create(panel); !errors.Is(err, approval.ErrExists) {
		t.Fatalf("Create over an existing file: %v", err)
	}
	if _, tr, _, _ := r.files.Load(); tr == nil || tr.ClientID != "admin" {
		t.Errorf("the administrator's file was replaced: %+v", tr)
	}
	// a write that fails half-way (Prepare refuses) leaves nothing
	f := approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName), Prepare: func(string) error { return errors.New("disk full") }}
	if err := f.Create(panel); err == nil {
		t.Fatal("Create succeeded although the write failed")
	}
	if left, _ := os.ReadDir(filepath.Dir(f.Path)); len(left) != 0 {
		t.Errorf("a failed write left %d files", len(left))
	}
	if st, _, _, _ := f.Load(); st != api.ApprovalOff {
		t.Errorf("state after a failed write: %s", st)
	}
}

var nowForTests = time.Unix(1794000000, 0)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
