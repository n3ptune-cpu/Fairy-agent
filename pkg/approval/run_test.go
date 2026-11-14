package approval_test

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// sched is one shutdown the watch scheduled.
type sched struct {
	delay        time.Duration
	message, who string
	up           time.Duration // the uptime at which it was scheduled
}

// runRig is one machine that keeps runs: the gate of rig with a boot id and a small uptime, the watch, and
// fakes for the machine's power part, its updater and its guests.
type runRig struct {
	*rig
	w *approval.RunWatch

	bootID   string // "": a system without one (Windows)
	noUptime bool
	readOnly bool
	minDelay int
	dirErr   error // when set, the folder check fails: nothing can be read or written

	pending     bool // a power action is pending (another one, or the self-off once it is scheduled)
	scheduled   []sched
	shutdownErr error
	cancels     int
	updating    bool
	guests      bool
	guestsErr   error
	tokens      []string // every token this rig made, for the look at what leaks
}

const (
	runA = "00000000000000aa"
	runB = "00000000000000bb"
	runC = "00000000000000cc"
)

// newRunRig is a machine with the trust set that started 60 s ago.
func newRunRig(t testing.TB) *runRig {
	t.Helper()
	r := &runRig{rig: newRig(t, true), bootID: "boot-1"}
	r.mu.Lock()
	r.uptime = 60 * time.Second
	r.mu.Unlock()
	r.files.CheckDir = func(string) error { return r.dirErr }
	// The machine has its run record from a boot before this one, a day ago, as every machine has that a run
	// wakes: the service made it when it first looked with trust set (a record that is made anew closes its
	// boot for tickets).
	r.bootID = "boot-0"
	r.mu.Lock()
	r.now = r.now.Add(-24 * time.Hour)
	r.mu.Unlock()
	r.restart()
	r.w.Tick()
	r.mu.Lock()
	r.now = r.now.Add(24 * time.Hour)
	r.mu.Unlock()
	r.bootID = "boot-1"
	r.restart()
	return r
}

// restart is the service starting again in the same boot: a new gate and a new watch on the same files.
func (r *runRig) restart() {
	o := approval.Options{Files: r.files, EnforcedBy: api.EnforcedByHelper, Now: r.Now, Runs: !r.readOnly, ReadOnly: r.readOnly,
		MinDelayS: r.minDelay, Log: slog.New(slog.NewTextHandler(r.log, nil)),
		BootID: func() (string, error) { r.mu.Lock(); defer r.mu.Unlock(); return r.bootID, nil }}
	if !r.noUptime {
		o.Uptime = func() (time.Duration, error) { r.mu.Lock(); defer r.mu.Unlock(); return r.uptime, nil }
	}
	r.g = approval.NewGate(o)
	r.w = approval.NewRunWatch(r.g, approval.RunHooks{
		Pending: func() bool { return r.pending },
		Shutdown: func(d time.Duration, msg, who string) error {
			if r.shutdownErr != nil {
				return r.shutdownErr
			}
			r.mu.Lock()
			up := r.uptime
			r.mu.Unlock()
			r.scheduled, r.pending = append(r.scheduled, sched{d, msg, who, up}), true
			return nil
		},
		Cancel:   func() error { r.cancels++; r.pending = false; return nil },
		Updating: func() bool { return r.updating },
		Guests:   func() (bool, error) { return r.guests, r.guestsErr },
	})
}

// reboot is the machine starting again after off: a new boot id (where it has one), the uptime at up, nothing
// pending, and the service started.
func (r *runRig) reboot(off, up time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(off + up)
	r.uptime = up
	if r.bootID != "" {
		r.bootID += "+"
	}
	r.mu.Unlock()
	r.pending = false
	r.restart()
}

// jump sets the clock by d; the uptime does not move.
func (r *runRig) jump(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func (r *runRig) up() time.Duration { r.mu.Lock(); defer r.mu.Unlock(); return r.uptime }

// touched: the record holds something of a run, or this boot is closed for tickets (the record itself is there
// on every machine with trust: the checker keeps the clock in it).
func (r *runRig) touched() bool {
	r.mu.Lock()
	id := r.bootID
	r.mu.Unlock()
	return r.files.RunRecordTouched(id)
}

// stamp is this moment as the administrator's command (fairy-agent helper-run cancel) notes it.
func (r *runRig) stamp() approval.RunStamp {
	r.mu.Lock()
	defer r.mu.Unlock()
	return approval.RunStamp{BootID: r.bootID, Now: r.now, Up: r.uptime}
}

// winBoot is a boot id as the Windows helper keeps one: 32 hex characters from its registry key.
const winBoot = "5f0c1d2e3a4b59687766554433221100"

func randomChallenge() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return approvaltest.B64(b[:])
}

func armText(run string, valid, wait, notice int) string {
	text, err := (api.ApprovalRequest{Verb: api.ApproveRunArm, Run: &run, ValidS: &valid, WaitS: &wait, NoticeS: &notice}).Canonical()
	if err != nil {
		panic(err)
	}
	return text
}

// ticketEntry is the entry of a run ticket for the machine with this id: 32 random bytes of the panel's in the
// place of a challenge.
func ticketEntry(machineID, run string, valid, wait, notice int) api.MachineEntry {
	return api.MachineEntry{MachineID: machineID, Challenge: randomChallenge(), Request: armText(run, valid, wait, notice)}
}

// signed is a token of the rig's issuer for entries, signed (iat, auth_time) at the time at.
func (r *runRig) signed(at time.Time, entries ...api.MachineEntry) *api.Approval {
	ap := r.iss.Approve(at, entries...)
	r.tokens = append(r.tokens, ap.Token)
	return ap
}

// ticket is a good ticket for this machine, signed age ago: 7 minutes valid, 16 minutes wait, 2 minutes notice.
func (r *runRig) ticket(run string, age time.Duration) *api.Approval {
	return r.signed(r.Now().Add(-age), ticketEntry(approvaltest.MachineID, run, 420, 960, 120))
}

func goReq(run, to string, delay, within int) api.ApprovalRequest {
	return api.ApprovalRequest{Verb: api.ApproveRunGo, Run: &run, To: &to, ShutdownDelayS: &delay, WithinS: &within}
}

// confirm is a complete confirmation: the challenge for req, the issuer's token for it, POST /run/go.
func (r *runRig) confirm(req api.ApprovalRequest) (api.RunAnswer, *approval.Refusal) {
	r.t.Helper()
	c, ref := r.g.Challenge(req)
	if ref != nil {
		return api.RunAnswer{}, ref
	}
	if !c.Needed {
		r.t.Fatalf("challenge for a run confirmation: %+v", c)
	}
	return r.w.Go(req, r.signed(r.Now(), approvaltest.Entry(approvaltest.MachineID, c)))
}

func (r *runRig) run() *api.RunStatus { return r.g.Status().Run }

func (r *runRig) state() string {
	if s := r.run(); s != nil {
		return s.State
	}
	return ""
}

// armed arms run with a ticket signed 100 s before the machine started.
func (r *runRig) armed(run string) {
	r.t.Helper()
	ans, ref := r.w.Arm(r.ticket(run, r.up()+100*time.Second))
	if ref != nil || ans.State != api.RunArmed {
		r.t.Fatalf("arm %s: %+v, %v", run, ans, ref)
	}
}

// ticks moves time on by d in steps of one second, with the watch looking at each.
func (r *runRig) ticks(d time.Duration) {
	for ; d > 0; d -= time.Second {
		r.wait(time.Second)
		r.w.Tick()
	}
}

// runRefused checks a refusal of the run routes: status, code and the "reason" of the answer.
func runRefused(t *testing.T, what string, ref *approval.Refusal, status int, code, reason string) {
	t.Helper()
	if ref == nil {
		t.Errorf("%s: accepted, want %d %s %s", what, status, code, reason)
		return
	}
	if ref.Status != status || ref.Code != code || ref.Reason != reason {
		t.Errorf("%s: %d %s reason %q (%s), want %d %s %s", what, ref.Status, ref.Code, ref.Reason, ref.Msg, status, code, reason)
	}
}

func TestArmAcceptsAFreshMachine(t *testing.T) {
	r := newRunRig(t)
	st := r.g.Status()
	if st.Runs != api.ApprovalRuns || st.Run != nil || st.Proto != 2 {
		t.Fatalf("before: runs %d, run %+v, proto %d", st.Runs, st.Run, st.Proto)
	}
	if r.touched() {
		t.Fatal("something of a run in the record before any ticket")
	}
	ans, ref := r.w.Arm(r.ticket(runA, 160*time.Second)) // signed 100 s before the machine started
	if ref != nil || ans != (api.RunAnswer{Run: runA, State: api.RunArmed, OffInS: 960}) {
		t.Fatalf("arm: %+v, %v", ans, ref)
	}
	run := r.run()
	if run == nil || run.ID != runA || run.State != api.RunArmed || run.OffAt != r.Now().Add(960*time.Second).Unix() {
		t.Fatalf("run block %+v, want armed until %d", run, r.Now().Add(960*time.Second).Unix())
	}
	if exists, err := r.files.RunRecordCheck(); !exists || err != nil {
		t.Fatalf("the record after arming: %v, %v", exists, err)
	}
	if !strings.Contains(r.log.String(), `msg="approval: run armed"`) || !strings.Contains(r.log.String(), "run="+runA) ||
		!strings.Contains(r.log.String(), "sub="+approvaltest.User) || !strings.Contains(r.log.String(), "kid="+approvaltest.Kid) {
		t.Errorf("log: %s", r.log.String())
	}
	if len(r.scheduled) != 0 {
		t.Errorf("a shutdown was scheduled at once: %+v", r.scheduled)
	}
}

// Every reason a ticket is refused for. After each, nothing is armed and no record was written; and the good
// ticket is still taken, so a refusal used nothing up.
func TestArmRefusals(t *testing.T) {
	type tc struct {
		name   string
		setup  func(r *runRig)
		ticket func(r *runRig) *api.Approval
		status int
		code   string
		reason string
		lost   bool // the machine cannot be armed afterwards either (the setup is what refuses)
	}
	good := func(r *runRig) *api.Approval { return r.ticket(runA, r.up()+100*time.Second) }
	claims := func(change func(r *runRig, c map[string]any)) func(r *runRig) *api.Approval {
		return func(r *runRig) *api.Approval {
			e := []api.MachineEntry{ticketEntry(approvaltest.MachineID, runA, 420, 960, 120)}
			nonce, _ := api.ApprovalNonce(e)
			c := r.iss.Claims(nonce, r.Now().Add(-r.up()-100*time.Second))
			change(r, c)
			tok := r.iss.Token(c)
			r.tokens = append(r.tokens, tok)
			return &api.Approval{Token: tok, Entries: e}
		}
	}
	other := func(change func(i *approvaltest.Issuer)) func(r *runRig) *api.Approval {
		return func(r *runRig) *api.Approval {
			iss := *r.iss
			change(&iss)
			return iss.Approve(r.Now().Add(-r.up()-100*time.Second), ticketEntry(approvaltest.MachineID, runA, 420, 960, 120))
		}
	}
	cases := []tc{
		{name: "no approval", ticket: func(*runRig) *api.Approval { return nil }, status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonFormat},
		{name: "an ordinary approval of a challenge", ticket: func(r *runRig) *api.Approval { return r.approve(power("shutdown", 60)) },
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonNoTicket},
		{name: "a ticket for another machine id", ticket: func(r *runRig) *api.Approval {
			return r.signed(r.Now().Add(-160*time.Second), ticketEntry("another-machine-BBBBBBBBBB", runA, 420, 960, 120))
		}, status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonNonce},
		{name: "this machine's id written into another machine's ticket", ticket: func(r *runRig) *api.Approval {
			ap := r.signed(r.Now().Add(-160*time.Second), ticketEntry("another-machine-BBBBBBBBBB", runA, 420, 960, 120))
			ap.Entries[0].MachineID = approvaltest.MachineID // what was signed stays what it was
			return ap
		}, status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonNonce},
		{name: "another run id than the one signed", ticket: func(r *runRig) *api.Approval {
			ap := good(r)
			ap.Entries[0].Request = armText(runB, 420, 960, 120)
			return ap
		}, status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonNonce},
		{name: "a longer validity than the one signed", ticket: func(r *runRig) *api.Approval {
			ap := good(r)
			ap.Entries[0].Request = armText(runA, 600, 960, 120)
			return ap
		}, status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonNonce},
		{name: "a shorter wait than the one signed", ticket: func(r *runRig) *api.Approval {
			ap := good(r)
			ap.Entries[0].Request = armText(runA, 420, 120, 30)
			return ap
		}, status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonNonce},
		{name: "older than valid_s", setup: func(r *runRig) { r.wait(400 * time.Second) }, // up 460 s
			ticket: func(r *runRig) *api.Approval { return r.ticket(runA, 481*time.Second) },
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonClock},
		{name: "the passkey check older than valid_s", ticket: claims(func(r *runRig, c map[string]any) {
			c["auth_time"] = r.Now().Add(-481 * time.Second).Unix()
		}), status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonAuthTime},
		{name: "signed in this machine's future", ticket: func(r *runRig) *api.Approval { return r.ticket(runA, -61*time.Second) },
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonClock},
		{name: "the token has expired", ticket: claims(func(r *runRig, c map[string]any) { c["exp"] = r.Now().Add(-61 * time.Second).Unix() }),
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonTokenExp},
		{name: "another audience", ticket: claims(func(_ *runRig, c map[string]any) { c["aud"] = "fairy-panel-test" }),
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonAudience},
		{name: "another azp", ticket: claims(func(_ *runRig, c map[string]any) { c["azp"] = "fairy-panel-test" }),
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonAudience},
		{name: "another issuer", ticket: claims(func(_ *runRig, c map[string]any) { c["iss"] = "https://id2.test.invalid" }),
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonIssuer},
		{name: "a user who may not approve", ticket: claims(func(_ *runRig, c map[string]any) { c["sub"] = "99999999-2222-4333-8444-555555555555" }),
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonUser},
		{name: "not a passkey sign-in", ticket: claims(func(_ *runRig, c map[string]any) { c["amr"] = []string{"pwd"} }),
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonAMR},
		{name: "no auth_time", ticket: claims(func(_ *runRig, c map[string]any) { delete(c, "auth_time") }),
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonAuthTime},
		{name: "a key that is not pinned", ticket: other(func(i *approvaltest.Issuer) { i.Kid = "another-key" }),
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonKey},
		{name: "signed by somebody else's key under the pinned key id", ticket: other(func(i *approvaltest.Issuer) { i.Key = approvaltest.Key(1) }),
			status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonSignature},
		{name: "a token that is too large", ticket: func(r *runRig) *api.Approval {
			ap := good(r)
			ap.Token += strings.Repeat("A", api.MaxApprovalToken)
			return ap
		}, status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonFormat},
		{name: "a run_arm text that is not canonical", ticket: func(r *runRig) *api.Approval {
			e := api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: randomChallenge(), Request: "run_arm run=" + runA + " valid_s=420 wait_s=5 notice_s=1"}
			return r.signed(r.Now().Add(-160*time.Second), e)
		}, status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonEntries},
		{name: "a list that is not well-formed", ticket: func(r *runRig) *api.Approval {
			ap := good(r)
			ap.Entries = append(ap.Entries, ap.Entries[0])
			return ap
		}, status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonEntries},
		{name: "two run_arm entries for this machine", ticket: func(r *runRig) *api.Approval {
			return r.signed(r.Now().Add(-160*time.Second), ticketEntry(approvaltest.MachineID, runA, 420, 960, 120), ticketEntry(approvaltest.MachineID, runA, 420, 120, 30))
		}, status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonAmbiguous},
		{name: "the entry carries an open challenge of this machine", ticket: func(r *runRig) *api.Approval {
			c, ref := r.g.Challenge(power("shutdown", 60))
			if ref != nil {
				r.t.Fatal(ref)
			}
			e := ticketEntry(approvaltest.MachineID, runA, 420, 960, 120)
			e.Challenge = c.Challenge
			return r.signed(r.Now().Add(-160*time.Second), e)
		}, status: 403, code: api.CodeApprovalRefused, reason: approval.ReasonEntries},
		{name: "up for 600 s", setup: func(r *runRig) { r.wait(540 * time.Second) },
			ticket: func(r *runRig) *api.Approval {
				return r.signed(r.Now().Add(-650*time.Second), ticketEntry(approvaltest.MachineID, runA, 600, 960, 120))
			},
			status: 409, code: api.CodeRunRefused, reason: api.RunReasonNotFresh, lost: true},
		{name: "already running when the ticket was signed", ticket: func(r *runRig) *api.Approval { return r.ticket(runA, -1*time.Second) }, // up 60 s, signed 1 s from now: 61 s after the start
			status: 409, code: api.CodeRunRefused, reason: api.RunReasonStartedBefore},
		{name: "a power action is pending", setup: func(r *runRig) { r.pending = true }, ticket: good,
			status: 409, code: api.CodeRunRefused, reason: api.RunReasonPowerPending, lost: true},
		{name: "a notice shorter than this machine's shortest delay", setup: func(r *runRig) { r.minDelay = 121; r.restart() }, ticket: good,
			status: 409, code: api.CodeRunRefused, reason: api.RunReasonLimits, lost: true},
		{name: "the uptime is not known", setup: func(r *runRig) { r.noUptime = true; r.restart() }, ticket: good,
			status: 503, code: api.CodeRunUnavailable, lost: true},
		{name: "a gate that only reads", setup: func(r *runRig) { r.readOnly = true; r.restart() }, ticket: good,
			status: 404, code: api.CodeApprovalDisabled, lost: true},
		{name: "the record's folder fails its check", setup: func(r *runRig) { r.dirErr = errors.New("others can write it") }, ticket: good,
			status: 503, code: api.CodeApprovalUnavailable, lost: true}, // the trust file is in that folder too
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRunRig(t)
			if c.setup != nil {
				c.setup(r)
			}
			ans, ref := r.w.Arm(c.ticket(r))
			runRefused(t, "arm", ref, c.status, c.code, c.reason)
			if ans != (api.RunAnswer{}) {
				t.Errorf("a refusal with an answer: %+v", ans)
			}
			r.dirErr = nil
			if r.touched() {
				t.Error("a refused ticket left something in the run record")
			}
			if run := r.run(); run != nil {
				t.Errorf("a refused ticket left a run: %+v", run)
			}
			r.ticks(1200 * time.Second)
			if len(r.scheduled) != 0 {
				t.Errorf("a refused ticket switched the machine off: %+v", r.scheduled)
			}
			if c.lost || c.setup != nil {
				return
			}
			// nothing was used up: the good ticket is still taken (on a machine that is as fresh as before)
			r2 := newRunRig(t)
			if _, ref := r2.w.Arm(c.ticket(r2)); ref == nil {
				t.Fatal("accepted on a second machine")
			}
			if _, ref := r2.w.Arm(good(r2)); ref != nil {
				t.Errorf("the good ticket after the refused one: %v", ref)
			}
		})
	}
}

// The limits of the two rules that stand in for the challenge, to the second.
func TestArmUptimeAndStartLimits(t *testing.T) {
	// up for 599 s: taken. 600 s: not.
	r := newRunRig(t)
	r.wait(539 * time.Second)
	wide := func(r *runRig, run string, age time.Duration) *api.Approval {
		return r.signed(r.Now().Add(-age), ticketEntry(approvaltest.MachineID, run, 600, 960, 120))
	}
	if _, ref := r.w.Arm(wide(r, runA, 650*time.Second)); ref != nil {
		t.Errorf("up for 599 s: %v", ref)
	}
	r = newRunRig(t)
	r.wait(540 * time.Second)
	_, ref := r.w.Arm(wide(r, runA, 650*time.Second))
	runRefused(t, "up for 600 s", ref, 409, api.CodeRunRefused, api.RunReasonNotFresh)

	// signed 60 s after the machine started (the clock allowance): taken. 61 s: not.
	r = newRunRig(t) // up 60 s
	if _, ref := r.w.Arm(r.ticket(runA, 0)); ref != nil {
		t.Errorf("signed 60 s after the start: %v", ref)
	}
	r = newRunRig(t)
	_, ref = r.w.Arm(r.ticket(runA, -time.Second))
	runRefused(t, "signed 61 s after the start", ref, 409, api.CodeRunRefused, api.RunReasonStartedBefore)

	// valid_s, to the second: 420 s plus the clock allowance of 60 s
	r = newRunRig(t)
	r.wait(400 * time.Second)
	if _, ref := r.w.Arm(r.ticket(runA, 480*time.Second)); ref != nil {
		t.Errorf("480 s old: %v", ref)
	}
	r = newRunRig(t)
	r.wait(400 * time.Second)
	_, ref = r.w.Arm(r.ticket(runA, 481*time.Second))
	runRefused(t, "481 s old", ref, 403, api.CodeApprovalRefused, approval.ReasonClock)
}

// A machine that was off for weeks. Its clock is behind: every ticket looks as if it came from the future and
// is refused, the machine stays on. Its clock is ahead: the ticket looks older than it is, and is refused once
// that is more than valid_s; within valid_s it is taken, and only the uptime rule (10 minutes) bounds it, as
// the design says.
func TestArmWithAWrongClock(t *testing.T) {
	r := newRunRig(t)
	signedAt := r.Now().Add(-160 * time.Second) // by the true time: 100 s before the machine started
	behind := r.signed(signedAt, ticketEntry(approvaltest.MachineID, runA, 420, 960, 120))
	r.jump(-10 * time.Minute)
	_, ref := r.w.Arm(behind)
	runRefused(t, "the clock is 10 minutes behind", ref, 403, api.CodeApprovalRefused, approval.ReasonClock)
	if !strings.Contains(ref.Msg, "is the clock right?") {
		t.Errorf("the refusal does not ask about the clock: %s", ref.Msg)
	}
	r.jump(10*time.Minute + 6*time.Minute) // now 6 minutes ahead: the ticket looks 520 s old
	_, ref = r.w.Arm(behind)
	runRefused(t, "the clock is 6 minutes ahead", ref, 403, api.CodeApprovalRefused, approval.ReasonClock)
	r.jump(-2 * time.Minute) // 4 minutes ahead: it looks 400 s old
	if _, ref := r.w.Arm(behind); ref != nil {
		t.Errorf("the clock is 4 minutes ahead, inside valid_s: %v", ref)
	}
	r.ticks(1200 * time.Second)
	if len(r.scheduled) != 1 {
		t.Fatalf("scheduled %+v", r.scheduled)
	}
}

// Replays: the same ticket twice, a ticket of another run in the same boot, the same run in a later boot, and
// all of it again after the service restarted.
func TestArmOncePerBootAndRun(t *testing.T) {
	r := newRunRig(t)
	ticketA := r.ticket(runA, 160*time.Second)
	ticketB := r.ticket(runB, 160*time.Second)
	if _, ref := r.w.Arm(ticketA); ref != nil {
		t.Fatal(ref)
	}
	for i := 0; i < 2; i++ {
		_, ref := r.w.Arm(ticketA)
		runRefused(t, "the same ticket again", ref, 409, api.CodeRunRefused, api.RunReasonArmedThisBoot)
		_, ref = r.w.Arm(ticketB)
		runRefused(t, "a ticket of another run in the same boot", ref, 409, api.CodeRunRefused, api.RunReasonArmedThisBoot)
		r.restart()
	}
	if r.state() != api.RunArmed || r.run().ID != runA {
		t.Fatalf("after the refused replays: %+v", r.run())
	}
	// the machine is started again within the ticket's validity: the same run does not arm it a second time
	r.reboot(20*time.Second, 40*time.Second)
	if run := r.run(); run != nil {
		t.Fatalf("a run after a new boot: %+v", run)
	}
	_, ref := r.w.Arm(ticketA)
	runRefused(t, "the same run in the next boot", ref, 409, api.CodeRunRefused, api.RunReasonRunUsed)
	if _, ref := r.w.Arm(ticketB); ref != nil {
		t.Errorf("another run in the next boot: %v", ref)
	}
	// and a boot later run A is still on record, though run B was accepted in between
	r.reboot(20*time.Second, 40*time.Second)
	_, ref = r.w.Arm(ticketA)
	runRefused(t, "the same run two boots later", ref, 409, api.CodeRunRefused, api.RunReasonRunUsed)
}

// A ticket is never the answer to a challenge, and the answer to a challenge is never a ticket.
func TestTicketAndChallengeDoNotStandInForEachOther(t *testing.T) {
	r := newRunRig(t)
	valid, wait, notice := 420, 960, 120
	run := runA
	arm := api.ApprovalRequest{Verb: api.ApproveRunArm, Run: &run, ValidS: &valid, WaitS: &wait, NoticeS: &notice}
	// no challenge is given for a ticket's text
	if c, ref := r.g.Challenge(arm); ref == nil || ref.Status != 400 || c.Challenge != "" {
		t.Errorf("challenge for run_arm: %+v, %v", c, ref)
	}
	// the gate's two questions about a request never let a run request through
	for _, req := range []api.ApprovalRequest{arm, goReq(runA, "19-abc", 30, 1500)} {
		if ref := r.g.Precheck(req, true); ref == nil || ref.Status != 400 {
			t.Errorf("Precheck(%s): %v", req.Verb, ref)
		}
		if _, ref := r.g.Admit(req, r.ticket(runA, 160*time.Second)); ref == nil || ref.Status != 400 {
			t.Errorf("Admit(%s): %v", req.Verb, ref)
		}
	}
	// a ticket sent with a shutdown: no challenge of this machine is in it
	ticket := r.ticket(runA, 160*time.Second)
	_, ref := r.g.Admit(power("shutdown", 60), ticket)
	refused(t, "a ticket as the approval of a shutdown", ref, api.CodeApprovalRefused, approval.ReasonNoChallenge)
	// a ticket whose entry carries this machine's open challenge for that shutdown: the challenge is listed
	// with another request
	c, _ := r.g.Challenge(power("shutdown", 60))
	e := ticketEntry(approvaltest.MachineID, runA, 420, 960, 120)
	e.Challenge = c.Challenge
	crossed := r.signed(r.Now().Add(-160*time.Second), e)
	_, ref = r.g.Admit(power("shutdown", 60), crossed)
	refused(t, "a ticket with the challenge of a shutdown", ref, api.CodeApprovalRefused, approval.ReasonEntries)
	_, ref = r.w.Arm(crossed)
	runRefused(t, "the same ticket as a ticket", ref, 403, api.CodeApprovalRefused, approval.ReasonEntries)
	// one list with the shutdown's entry and the ticket's: each is taken where it belongs, and only there
	both := r.signed(r.Now().Add(-10*time.Second), approvaltest.Entry(approvaltest.MachineID, c), ticketEntry(approvaltest.MachineID, runB, 420, 960, 120))
	if _, ref := r.g.Admit(power("shutdown", 60), both); ref != nil {
		t.Errorf("the shutdown's entry of a list that also holds a ticket: %v", ref)
	}
	if r.run() != nil {
		t.Errorf("an approved shutdown armed a run: %+v", r.run())
	}
	// the ticket half of it is a ticket like any other (signed 50 s after the start here, which is allowed)
	if _, ref := r.w.Arm(both); ref != nil {
		t.Errorf("the ticket's entry of that list: %v", ref)
	}
	// the confirmation's approval is not a ticket
	r2 := newRunRig(t)
	gc, ref := r2.g.Challenge(goReq(runA, "19-abc", 30, 1500))
	if ref != nil {
		t.Fatal(ref)
	}
	_, ref = r2.w.Arm(r2.signed(r2.Now(), approvaltest.Entry(approvaltest.MachineID, gc)))
	runRefused(t, "a confirmation's approval as a ticket", ref, 403, api.CodeApprovalRefused, approval.ReasonNoTicket)
}

func TestRunsAreOffWithoutTrustAndUnavailableWhenBroken(t *testing.T) {
	r := newRunRig(t)
	ticket := r.ticket(runA, 160*time.Second)
	if err := os.Remove(r.files.Path); err != nil {
		t.Fatal(err)
	}
	r.restart()
	_, ref := r.w.Arm(ticket)
	runRefused(t, "arm without trust", ref, 409, api.CodeApprovalOff, "")
	_, ref = r.w.Go(goReq(runA, "19-abc", 30, 1500), ticket)
	runRefused(t, "go without trust", ref, 409, api.CodeApprovalOff, "")
	if c, ref := r.g.Challenge(goReq(runA, "19-abc", 30, 1500)); ref != nil || c.Needed || c.Reason != "off" {
		t.Errorf("challenge for run_go without trust: %+v, %v", c, ref)
	}
	// with trust off a request that names a run runs like every other request: nothing is checked
	if _, ref := r.g.RunCovers(update, runA); ref != nil {
		t.Errorf("update with a run, trust off: %v", ref)
	}
	if _, ref := r.g.AdmitRun(power("shutdown", 30), runA); ref != nil {
		t.Errorf("shutdown with a run, trust off: %v", ref)
	}
	if st := r.g.Status(); st.State != api.ApprovalOff || st.Run != nil || st.Runs != api.ApprovalRuns {
		t.Errorf("status %+v", st)
	}
	if r.touched() {
		t.Error("something of a run in the record of a machine without trust")
	}
	if err := os.WriteFile(r.files.Path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.restart()
	_, ref = r.w.Arm(ticket)
	runRefused(t, "arm with a broken trust file", ref, 503, api.CodeApprovalUnavailable, "")
	_, ref = r.w.Go(goReq(runA, "19-abc", 30, 1500), ticket)
	runRefused(t, "go with a broken trust file", ref, 503, api.CodeApprovalUnavailable, "")
	if _, ref := r.g.AdmitRun(update, runA); ref == nil || ref.Code != api.CodeApprovalUnavailable {
		t.Errorf("update with a run, trust broken: %v", ref)
	}
}

// What the machine says of itself never holds a token or a piece of one: the log, the answers, the status,
// the record.
func (r *runRig) noTokenAnywhere(t *testing.T, more ...string) {
	t.Helper()
	st, _ := json.Marshal(r.g.Status())
	file, _ := os.ReadFile(r.files.RunPath())
	places := map[string]string{"the log": r.log.String(), "the status": string(st), "the record": string(file)}
	for i, m := range more {
		places[fmt.Sprintf("answer %d", i)] = m
	}
	for _, tok := range r.tokens {
		for _, part := range strings.Split(tok, ".") {
			for where, text := range places {
				if len(part) >= 24 && (strings.Contains(text, part) || strings.Contains(text, part[:24]) || strings.Contains(text, part[len(part)-24:])) {
					t.Errorf("%s holds a piece of a token", where)
				}
			}
		}
	}
}

func TestNoTokenInLogStatusRecordOrAnswers(t *testing.T) {
	r := newRunRig(t)
	var said []string
	say := func(ref *approval.Refusal) {
		if ref != nil {
			said = append(said, ref.Error()+" "+ref.Reason)
		}
	}
	_, ref := r.w.Arm(r.ticket(runA, -61*time.Second)) // refused
	say(ref)
	bad := r.ticket(runA, 160*time.Second)
	// a wrong signature, surely: its first character is another one (the last two characters hold the last
	// byte and four bits nobody reads, so "AA" in their place was the same signature once in 256 runs)
	sig := strings.LastIndex(bad.Token, ".") + 1
	other := "A"
	if bad.Token[sig] == 'A' {
		other = "B"
	}
	bad.Token = bad.Token[:sig] + other + bad.Token[sig+1:]
	r.tokens = append(r.tokens, bad.Token)
	_, ref = r.w.Arm(bad)
	say(ref)
	r.armed(runA)
	_, ref = r.w.Arm(r.ticket(runB, 160*time.Second))
	say(ref)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1500)); ref != nil {
		t.Fatal(ref)
	}
	_, ref = r.w.Go(goReq(runA, "19-abc", 30, 1500), r.ticket(runA, 0))
	say(ref)
	_, ref = r.g.AdmitRun(update, runB)
	say(ref)
	if _, ref := r.g.AdmitRun(update, runA); ref != nil {
		t.Fatal(ref)
	}
	if len(r.tokens) < 5 || len(said) < 5 {
		t.Fatalf("%d tokens, %d refusals", len(r.tokens), len(said))
	}
	r.noTokenAnywhere(t, said...)
}
