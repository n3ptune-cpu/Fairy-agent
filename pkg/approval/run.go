package approval

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// Runs: approvals inside a wake / update / shutdown run of the panel (the protocol is in pkg/agent/api, "Runs").
//
// A machine that is off cannot give a challenge. So the passkey that starts a run signs a ticket for it
// instead ("run_arm ..."), and the machine checks that ticket itself once it has started: with the same
// function every approval is checked with (verifyToken: pinned key, issuer, client, allowed user, passkey,
// times), and with rules of its own that stand in for the challenge (Arm). An accepted ticket does one thing:
// the machine switches itself off again when the ticket's wait is over, with a notice, unless a second
// passkey approval (an ordinary one, for a challenge of this machine: Go) or a cancel comes first.
//
// Everything here is counted on the system's uptime, never on the clock: a machine that was off for weeks
// gets its clock set while it waits.

// ReasonNoTicket: POST /run/arm with a list in which no entry is a run_arm request.
const ReasonNoTicket = "no_ticket"

// RunUpdateWait is how long past its time a self-off waits for an update that is being installed.
const RunUpdateWait = 15 * time.Minute

// runOffGrace is how long after the end of its countdown a self-off still counts as pending. A machine that
// is still running after that was kept on (the shutdown was aborted on the machine itself).
const runOffGrace = 60 * time.Second

// runMem is what this process knows of the run record.
type runMem struct {
	loaded bool
	file   *runFile // nil: there is no record, or it cannot be used (bad)
	sum    [32]byte // of the file's bytes as this process read or wrote them last
	exists bool
	bad    string // why the record cannot be used ("": it can)
	said   string // the bad that was logged last
	epoch  uint64 // Gate.epoch when the live run was accepted or taken over
	dirty  bool   // the last write failed: the file is behind file; every step tries again
	// lostPending: a run that was counting down ended in another way than by a cancel that stops the countdown
	// itself (the record was changed on the machine, the trust was changed). The watcher stops the countdown.
	lostPending bool
	// armedHere: this process accepted a ticket. A process does not outlive a boot, so this is "a ticket was
	// accepted in this boot" whatever the clock was set to since (the mark in the record is told from the clock
	// where the system has no boot id).
	armedHere bool
}

// armText says some reasons differently for a ticket (the others are refusalText's).
var armText = map[string]string{
	ReasonNoTicket:  "no entry of the list is a run_arm request",
	ReasonEntries:   "the list of entries is not well-formed, holds a run_arm text that is not canonical, or names a challenge of this machine",
	ReasonAmbiguous: "more than one run_arm entry of the list is for this machine",
	ReasonNonce:     "the ticket was not signed for a list with this machine's id in a run_arm entry",
	ReasonClock:     "a time in the ticket does not fit this machine's clock: it was signed longer ago than its valid_s allows, or in this machine's future (is the clock right?)",
	ReasonAuthTime:  "the passkey check of the ticket is older than its valid_s allows",
}

var runText = map[string]string{
	api.RunReasonNotFresh:      "this machine has been up for " + strconv.Itoa(api.RunArmUptimeS) + " s or longer (or cannot say how long): a ticket arms only a machine that has just started",
	api.RunReasonStartedBefore: "this machine was already running when the ticket was signed",
	api.RunReasonArmedThisBoot: "a ticket was accepted on this machine in this boot already",
	api.RunReasonRunUsed:       "a ticket of this run was accepted on this machine before",
	api.RunReasonPowerPending:  "a shutdown, reboot or sleep is pending on this machine",
	api.RunReasonLimits:        "a delay it names is shorter than this machine's power_control.min_delay_s",
	api.RunReasonOtherRun:      "another run is armed or confirmed on this machine",
	api.RunReasonConfirmed:     "this run is confirmed on this machine already",
	api.RunReasonTooLate:       "too late: the wait is over and this machine is switching itself off",
	api.RunReasonOver:          "this run was armed or confirmed on this machine before and is over here (cancelled, finished, or the machine was started again since)",
}

func runOff() *Refusal {
	return &Refusal{Status: 409, Code: api.CodeApprovalOff, Msg: "approval is off on this machine: it has no approval trust, so it takes no run ticket and no run confirmation (its part of a run needs none)"}
}

func runRefuse(reason string) *Refusal {
	return &Refusal{Status: 409, Code: api.CodeRunRefused, Reason: reason, Msg: "run refused (" + reason + "): " + runText[reason]}
}

func runUnavailable(why string) *Refusal {
	return &Refusal{Status: 503, Code: api.CodeRunUnavailable,
		Msg: "the run record on this machine cannot be used, so nothing is armed and nothing of a run is let through: " + firstLine(why) +
			" (an administrator looks on the machine: fairy-agent helper-run show)"}
}

// noRuns is the answer of a gate that keeps no runs: one that only reads the trust file (a Windows agent next
// to, or without, the helper), or on a system whose uptime it cannot read.
func noRuns() *Refusal { return NoRuns() }

// NoRuns is the answer of a machine part that keeps no runs.
func NoRuns() *Refusal {
	return &Refusal{Status: 404, Code: api.CodeApprovalDisabled, Msg: "this agent keeps no runs: on Windows the fairy-agent-helper does, elsewhere an agent on Linux"}
}

func notARun() *Refusal {
	return &Refusal{Status: 400, Code: "bad_request", Msg: "a run ticket is sent to POST " + api.PathRunArm + " and a run confirmation to POST " + api.PathRunGo}
}

func isRunVerb(verb string) bool { return verb == api.ApproveRunArm || verb == api.ApproveRunGo }

// uptime is how long the system has been up (false: not known).
func (g *Gate) uptime() (time.Duration, bool) {
	if g.o.Uptime == nil {
		return 0, false
	}
	up, err := g.o.Uptime()
	if err != nil || up < 0 {
		return 0, false
	}
	return up, true
}

func (g *Gate) bootRef(now time.Time, up time.Duration) bootRef {
	return bootRef{BootID: g.bootID(), Wall: now.Unix(), UpMS: up.Milliseconds()}
}

// sameBoot reports whether ref was certainly written in this boot: what a live run needs to count. With the
// system's own boot id that is exact. Without one (Windows) the uptime must not be smaller than it was then,
// and the moment the system started, as the clock and the uptime give it now, must be the moment they gave
// then, within bootSlack. A clock that was set by more than that in between ends the live run: the machine
// stays on and lets nothing of the run through, which is the safe side.
func (g *Gate) sameBoot(ref bootRef, now time.Time, up time.Duration) bool {
	if id := g.bootID(); id != "" || ref.BootID != "" {
		return id == ref.BootID
	}
	if up.Milliseconds() < ref.UpMS {
		return false
	}
	d := now.Add(-up).Unix() - (ref.Wall - ref.UpMS/1000)
	if d < 0 {
		d = -d
	}
	return time.Duration(d)*time.Second <= bootSlack
}

// maybeThisBoot reports whether ref may have been written in this boot: what a mark needs to refuse. Without a
// boot id on both sides it is the rule of the shutdown after boot (usedThisBoot): this boot, unless it was
// written clearly before this boot began.
func (g *Gate) maybeThisBoot(ref bootRef, now time.Time, up time.Duration) bool {
	if id := g.bootID(); id != "" && ref.BootID != "" {
		return id == ref.BootID
	}
	return !time.Unix(ref.Wall, 0).Before(now.Add(-up).Add(-bootSlack))
}

// runRead is the first look of this process at the run record (and every look of a gate that only reads). A
// live run that is not of this boot is taken out; one that is, is taken over. Caller holds g.mu.
func (g *Gate) runRead(now time.Time, up time.Duration) {
	m := &g.rs
	f, sum, exists, err := g.o.Files.readRun()
	m.loaded, m.dirty = true, false
	if err != nil {
		m.file, m.exists, m.bad = nil, true, firstLine(err.Error())
		if m.said != m.bad {
			m.said = m.bad
			g.o.Log.Error("approval: the run record cannot be used: it counts as no record (nothing is armed, nothing of a run is let through), and no ticket is accepted until it is removed (fairy-agent helper-run cancel)",
				"error", m.bad)
		}
		return
	}
	m.file, m.sum, m.exists, m.bad, m.said = f, sum, exists, "", ""
	if f == nil || f.Run == nil {
		return
	}
	if !g.sameBoot(f.At, now, up) {
		f.Run, f.Last = nil, nil
		if !g.o.ReadOnly { // a gate that only reads does not count it either; the owner of the file removes it
			g.o.Log.Warn("approval: run record of an earlier boot removed", "written_at", f.At.Wall)
			g.runWrite(now, up)
		}
		return
	}
	m.epoch = g.epoch
	if !g.o.ReadOnly {
		g.o.Log.Warn("approval: run taken over from the record (this service was restarted)", "run", f.Run.ID, "state", f.Run.State,
			"sub", f.Run.Sub, "kid", f.Run.Kid)
	}
}

// runSync brings this process's copy of the record up to date with the file, for the steps that must see what
// was done on the machine in the meantime (helper-run cancel; a record that was removed). After the first look
// the only change from outside that is taken is one that leaves no live run. A live run this process did not
// write itself is not believed: it is ended. Caller holds g.mu.
func (g *Gate) runSync(now time.Time, up time.Duration) {
	m := &g.rs
	if !m.loaded || g.o.ReadOnly {
		g.runRead(now, up)
		return
	}
	if m.dirty && g.runWrite(now, up) != nil {
		return // this process is ahead of the file: the file is not looked at
	}
	had := (*runLive)(nil)
	if m.file != nil {
		had = m.file.Run
	}
	f, sum, exists, err := g.o.Files.readRun()
	if err == nil && m.bad == "" && exists == m.exists && (!exists || sum == m.sum) {
		return // as this process left it
	}
	if had != nil && had.State == api.RunOffPending {
		m.lostPending = true
	}
	if err != nil {
		m.file, m.exists, m.bad = nil, true, firstLine(err.Error())
		if m.said != m.bad {
			m.said = m.bad
			g.o.Log.Error("approval: the run record cannot be used: it counts as no record (nothing is armed, nothing of a run is let through), and no ticket is accepted until it is removed (fairy-agent helper-run cancel)",
				"error", m.bad)
		}
		return
	}
	m.file, m.sum, m.exists, m.bad, m.said = f, sum, exists, "", ""
	if f != nil && f.Run != nil {
		g.runEnd(api.RunCancelled, "the run record was changed by somebody else: its live run is not this service's", now, up)
		return
	}
	if had != nil {
		g.o.Log.Warn("approval: run cancelled", "run", had.ID, "was", had.State, "sub", had.Sub, "kid", had.Kid,
			"why", "cancelled on the machine (fairy-agent helper-run cancel, or the record was removed)")
		m.armedHere = true // a cancel: this boot is closed for tickets (runEnd)
		if f != nil {
			at := g.bootRef(now, up)
			f.Arm = &at
			g.runWrite(now, up)
		}
	}
}

// runWrite writes the record as this process holds it. Caller holds g.mu.
func (g *Gate) runWrite(now time.Time, up time.Duration) error {
	m := &g.rs
	m.file.At = g.bootRef(now, up)
	sum, err := g.o.Files.writeRun(m.file)
	if err != nil {
		m.dirty = true
		g.o.Log.Error("approval: the run record could not be written", "error", firstLine(err.Error()))
		return err
	}
	m.sum, m.exists, m.dirty = sum, true, false
	return nil
}

// runNow is the live run at this moment (nil: none), after everything that ends one by itself: the trust was
// changed or removed since it was accepted, the uptime went backwards, the time of a confirmation is over.
// Caller holds g.mu, and has called g.reload.
func (g *Gate) runNow(now time.Time, up time.Duration) *runLive {
	m := &g.rs
	if !m.loaded || g.o.ReadOnly { // a gate that only reads has nothing of its own: the file is the helper's
		g.runRead(now, up)
	}
	if m.file == nil {
		return nil
	}
	if m.dirty {
		g.runWrite(now, up)
	}
	r := m.file.Run
	if r == nil {
		return nil
	}
	if g.o.ReadOnly {
		if r.State == api.RunConfirmed && up.Milliseconds() >= r.GoUpMS+int64(r.WithinS)*1000 {
			return nil
		}
		return r
	}
	switch {
	case g.state != api.ApprovalRequired || m.epoch != g.epoch:
		g.runEnd(api.RunCancelled, "the approval trust of this machine was changed or removed", now, up)
	case up.Milliseconds() < m.file.At.UpMS:
		g.runEnd(api.RunCancelled, "the uptime is smaller than when the record was written: another boot", now, up)
	case r.State == api.RunConfirmed && up.Milliseconds() >= r.GoUpMS+int64(r.WithinS)*1000:
		g.runEnd(api.RunDone, "the time of the confirmation is over", now, up)
	default:
		return r
	}
	return nil
}

// runEnd takes the live run out of the record and notes how it ended. The error is that of the write: the run
// is over for this process either way, and the write is tried again at every step. Caller holds g.mu.
func (g *Gate) runEnd(state, why string, now time.Time, up time.Duration) error {
	m := &g.rs
	r := m.file.Run
	m.file.Run, m.file.Last = nil, &runLast{ID: r.ID, State: state}
	if r.State == api.RunOffPending {
		m.lostPending = true
	}
	msg := "approval: run done"
	if state == api.RunCancelled {
		// Nothing arms this machine again in this boot, also when the run that was cancelled had been confirmed
		// without a ticket: the boot is closed for tickets from here on.
		at := g.bootRef(now, up)
		m.file.Arm, m.armedHere = &at, true
		msg = "approval: run cancelled"
	}
	g.o.Log.Warn(msg, "run", r.ID, "was", r.State, "sub", r.Sub, "kid", r.Kid, "why", why)
	return g.runWrite(now, up)
}

// runGate is what Arm and Go start with: trust is set, this gate keeps runs, the uptime is known and the
// record can be used. Caller holds g.mu.
func (g *Gate) runGate() (now time.Time, up time.Duration, ref *Refusal) {
	g.reload(false)
	now = g.o.Now()
	switch {
	case g.state == api.ApprovalOff:
		return now, 0, runOff()
	case g.state != api.ApprovalRequired:
		return now, 0, unavailable(g.loadErr)
	case g.trust == nil || g.trust.MachineID == "":
		return now, 0, unavailable(ErrNoMachineID.Msg)
	case g.o.ReadOnly || !g.o.Runs:
		return now, 0, noRuns()
	}
	up, ok := g.uptime()
	if !ok {
		return now, 0, runUnavailable("this machine cannot say how long it has been up")
	}
	g.runSync(now, up) // as the file is now: an administrator may have cancelled or removed it
	switch {
	case g.rs.bad != "":
		return now, up, runUnavailable(g.rs.bad)
	case g.rs.dirty:
		return now, up, runUnavailable("the run record could not be written")
	}
	return now, up, nil
}

// ticket finds the run_arm entry of ap that is this machine's and checks the token for it. Nothing of the
// token is believed before verifyToken has checked its signature; what ties the ticket to this machine is, as
// for every approval, the nonce made here with this machine's own id in the entry (ownNonce). The entry's
// challenge member is 32 bytes the panel made up; it must not be a challenge this machine has open.
func (g *Gate) ticket(ap *api.Approval, now time.Time) (api.ApprovalRequest, claims, string) {
	var none api.ApprovalRequest
	if ap == nil || len(ap.Token) > api.MaxApprovalToken {
		return none, claims{}, ReasonFormat
	}
	if _, err := api.ApprovalNonce(ap.Entries); err != nil {
		return none, claims{}, ReasonEntries
	}
	type cand struct {
		req   api.ApprovalRequest
		nonce string
	}
	var cands []cand
	for at, e := range ap.Entries {
		if !strings.HasPrefix(e.Request, api.ApproveRunArm+" ") {
			continue
		}
		req, err := api.ParseRunRequest(e.Request)
		if err != nil || req.Verb != api.ApproveRunArm {
			return none, claims{}, ReasonEntries
		}
		id, err := api.DecodeChallenge(e.Challenge)
		if err != nil || g.find(id) >= 0 {
			return none, claims{}, ReasonEntries
		}
		nonce, err := ownNonce(ap.Entries, at, g.trust.MachineID, e.Request)
		if err != nil {
			return none, claims{}, ReasonEntries
		}
		cands = append(cands, cand{req, nonce})
	}
	if len(cands) == 0 {
		return none, claims{}, ReasonNoTicket
	}
	for i, c := range cands {
		if slices.ContainsFunc(cands[:i], func(o cand) bool { return o.nonce == c.nonce }) {
			continue // the same list with this machine's id in another entry: looked at already
		}
		// "issued" is the earliest moment a ticket that is still good was signed: iat and auth_time must not be
		// older than valid_s (plus the clock allowance)
		cl, why := verifyToken(ap.Token, g.trust, c.nonce, now, now.Add(-time.Duration(*c.req.ValidS)*time.Second))
		if why == ReasonNonce {
			continue
		}
		if why != "" {
			return c.req, cl, why
		}
		for _, o := range cands[i+1:] {
			if o.nonce == c.nonce { // two run_arm entries with this machine's id: which one was meant?
				return c.req, cl, ReasonAmbiguous
			}
		}
		return c.req, cl, ""
	}
	return none, claims{}, ReasonNonce
}

// Arm answers POST /run/arm: ap is a run ticket. pending says whether a power action of Fairy's is pending on
// this machine. The ticket is accepted when all of this holds:
//
//   - trust is set, and this gate keeps runs;
//   - exactly one entry of the list is a canonical run_arm text for which the token carries the nonce made
//     with this machine's id, and the token passes verifyToken with "issued" = now - valid_s;
//   - the notice is not shorter than this machine's shortest delay (Options.MinDelayS);
//   - the machine has been up for less than api.RunArmUptimeS;
//   - it started (clock minus uptime) not before the ticket was signed (iat, less the clock allowance);
//   - no ticket was accepted in this boot, no ticket of this run before, and no run is confirmed;
//   - no power action is pending.
//
// The record is written before the answer; if it cannot be, nothing is armed.
func (g *Gate) Arm(ap *api.Approval, pending bool) (api.RunAnswer, *Refusal) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now, up, ref := g.runGate()
	if ref != nil {
		return api.RunAnswer{}, ref
	}
	req, cl, reason := g.ticket(ap, now)
	if reason != "" {
		g.o.Log.Warn("approval: run ticket refused", "result", "refused", "reason", reason, "run", deref(req.Run), "sub", cl.Sub, "kid", cl.Kid)
		text := armText[reason]
		if text == "" {
			text = refusalText[reason]
		}
		ref := refuse(reason, text)
		ref.Reason = reason
		return api.RunAnswer{}, ref
	}
	id := *req.Run
	no := func(reason string) (api.RunAnswer, *Refusal) {
		g.o.Log.Warn("approval: run ticket refused", "result", "refused", "reason", reason, "run", id, "sub", cl.Sub, "kid", cl.Kid,
			"uptime_s", int(up/time.Second))
		return api.RunAnswer{}, runRefuse(reason)
	}
	f := g.rs.file
	if f == nil {
		f = &runFile{Version: 1}
	}
	live := g.runNow(now, up)
	switch {
	case *req.NoticeS < g.o.MinDelayS:
		return no(api.RunReasonLimits)
	case up >= api.RunArmUptimeS*time.Second:
		return no(api.RunReasonNotFresh)
	case now.Add(-up).Before(cl.Iat.Add(-ClockAllowance)):
		return no(api.RunReasonStartedBefore)
	case g.rs.armedHere || (f.Arm != nil && g.maybeThisBoot(*f.Arm, now, up)):
		return no(api.RunReasonArmedThisBoot)
	case slices.Contains(f.Used, id):
		return no(api.RunReasonRunUsed)
	case live != nil:
		return no(api.RunReasonOtherRun)
	case pending:
		return no(api.RunReasonPowerPending)
	}
	at, prev, nf := g.bootRef(now, up), g.rs.file, *f
	nf.Arm, nf.Used, nf.Last = &at, append(slices.Clone(f.Used), id), nil
	nf.Run = &runLive{ID: id, State: api.RunArmed, Sub: cl.Sub, Name: cl.Name, Kid: cl.Kid, ArmedUpMS: up.Milliseconds(), WaitS: *req.WaitS, NoticeS: *req.NoticeS}
	g.rs.file, g.rs.epoch = &nf, g.epoch
	if err := g.runWrite(now, up); err != nil { // not recorded: not armed
		g.rs.file, g.rs.dirty = prev, false
		return api.RunAnswer{}, runUnavailable(err.Error())
	}
	g.rs.armedHere = true
	g.o.Log.Warn("approval: run armed", "result", "accepted", "run", id, "sub", cl.Sub, "name", cl.Name, "kid", cl.Kid,
		"wait_s", *req.WaitS, "notice_s", *req.NoticeS, "uptime_s", int(up/time.Second))
	return api.RunAnswer{Run: id, State: api.RunArmed, OffInS: *req.WaitS}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// goCheck says whether a confirmation of req (run_go) can be taken at this moment, before any approval is
// looked at: for the challenge and for Go. Caller holds g.mu, after runGate.
func (g *Gate) goCheck(req api.ApprovalRequest, now time.Time, up time.Duration) *Refusal {
	id := *req.Run
	f := g.rs.file
	live := g.runNow(now, up)
	reason := ""
	switch {
	case *req.ShutdownDelayS < g.o.MinDelayS:
		reason = api.RunReasonLimits
	case live != nil && live.ID != id:
		reason = api.RunReasonOtherRun
	case live != nil && live.State == api.RunConfirmed:
		reason = api.RunReasonConfirmed
	case live != nil && (live.State != api.RunArmed || up.Milliseconds() >= live.ArmedUpMS+int64(live.WaitS)*1000):
		reason = api.RunReasonTooLate
	case live == nil && f != nil && slices.Contains(f.Used, id):
		reason = api.RunReasonOver
	}
	if reason == "" {
		return nil
	}
	g.o.Log.Warn("approval: run confirmation refused", "result", "refused", "reason", reason, "run", id)
	return runRefuse(reason)
}

// Go answers POST /run/go: req is a run_go request and ap the approval of a challenge of this machine for it,
// checked exactly like every approval (verify: the challenge is found among the open ones and used up). It is
// taken for the run that is armed here, and also on a machine that no ticket armed (the panel could not arm
// it, and the person confirmed all the same). It is not taken once the wait of an armed run is over, for a
// run that this machine had before and that is over here (cancelled, finished, or ended by a new boot), or
// while another run is live.
//
// An accepted confirmation ends the self-off and puts into the record: one update (to exactly req.To; none
// with "-"), one shutdown with exactly req.ShutdownDelayS, until req.WithinS from now by the uptime, in this
// boot. The record is written before the answer.
func (g *Gate) Go(req api.ApprovalRequest, ap *api.Approval) (api.RunAnswer, *Refusal) {
	canon, err := req.Canonical()
	if err != nil || req.Verb != api.ApproveRunGo {
		msg := "not a run confirmation"
		if err != nil {
			msg += ": " + err.Error()
		}
		return api.RunAnswer{}, &Refusal{Status: 400, Code: "bad_request", Msg: msg}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now, up, ref := g.runGate()
	if ref != nil {
		return api.RunAnswer{}, ref
	}
	if ap == nil {
		g.o.Log.Warn("approval: required, none sent", "result", "refused", "request", canon)
		return api.RunAnswer{}, noneSent()
	}
	if ref := g.goCheck(req, now, up); ref != nil { // before the approval: a refusal here costs no challenge
		return api.RunAnswer{}, ref
	}
	c, cl, reason, other := g.verify(g.trust, g.trust.MachineID, canon, ap, now)
	if reason != "" {
		attrs := []any{"result", "refused", "reason", reason, "request", canon, "sub", cl.Sub, "kid", cl.Kid, "challenge", c}
		if other {
			attrs = append(attrs, "note", "the entry with this machine's challenge names another machine id than this machine's")
		}
		g.o.Log.Warn("approval: refused", attrs...)
		ref := refuse(reason, refusalText[reason])
		ref.Reason = reason
		return api.RunAnswer{}, ref
	}
	id := *req.Run
	f := g.rs.file
	if f == nil {
		f = &runFile{Version: 1}
	}
	prev, prevEpoch, nf, was := g.rs.file, g.rs.epoch, *f, f.Run
	if !slices.Contains(f.Used, id) {
		nf.Used = append(slices.Clone(f.Used), id)
	}
	nf.Run = &runLive{ID: id, State: api.RunConfirmed, Sub: cl.Sub, Name: cl.Name, Kid: cl.Kid, GoUpMS: up.Milliseconds(),
		WithinS: *req.WithinS, To: *req.To, ShutdownDelayS: *req.ShutdownDelayS, Shutdown: 1}
	if *req.To != api.RunNoUpdate {
		nf.Run.Update = 1
	}
	nf.Last = nil
	g.rs.file, g.rs.epoch = &nf, g.epoch
	if err := g.runWrite(now, up); err != nil {
		// The approval is spent and nothing is recorded: nothing of the run is let through. A run that was armed
		// stays armed, and the machine switches itself off as the ticket said.
		g.rs.file, g.rs.epoch, g.rs.dirty = prev, prevEpoch, false
		return api.RunAnswer{}, runUnavailable(err.Error())
	}
	g.o.Log.Warn("approval: run confirmed", "result", "accepted", "run", id, "request", canon, "sub", cl.Sub, "name", cl.Name, "kid", cl.Kid,
		"challenge", c, "was_armed", was != nil)
	return api.RunAnswer{Run: id, State: api.RunConfirmed, WithinS: *req.WithinS}, nil
}

// runCover says why the confirmed run does not cover req for the run id ("": it does). Caller holds g.mu.
func (g *Gate) runCover(req api.ApprovalRequest, id string, now time.Time) (*runLive, string) {
	up, ok := g.uptime()
	if !ok {
		return nil, "this machine cannot say how long it has been up"
	}
	live := g.runNow(now, up)
	switch {
	case g.rs.bad != "":
		return nil, "the run record on this machine cannot be used"
	case live == nil || live.State != api.RunConfirmed:
		return nil, "no run is confirmed on this machine in this boot"
	case live.ID != id || api.CheckRunID(id) != nil:
		return nil, "another run is confirmed on this machine"
	}
	switch {
	case req.Verb == api.ApproveApplyUpdate:
		if live.Update < 1 {
			return nil, "the confirmation of this run lets no update through, or its one update was used"
		}
	case isShutdown(req):
		if live.Shutdown < 1 {
			return nil, "the one shutdown of this run was used"
		}
		if req.DelayS == nil || *req.DelayS != live.ShutdownDelayS {
			return nil, "the confirmation of this run names a shutdown with delay_s " + strconv.Itoa(live.ShutdownDelayS) + " and no other"
		}
	default:
		return nil, "a run lets one update and one shutdown through, nothing else"
	}
	return live, ""
}

// noneSentRun is noneSent for a request that named a run which does not cover it: the same status and code
// as every request without approval, and why the run did not help.
func noneSentRun(why string) *Refusal {
	return &Refusal{Status: 403, Code: api.CodeApprovalRequired,
		Msg: "this needs a passkey approval (Pocket ID) and the request carried none; the run it names does not cover it: " + why}
}

// RunCovers is Precheck for a request that carries no approval and names a run: POST /update {"run": id} and
// POST /power {"action":"shutdown","delay_s":n,"run":id}. It uses nothing up. A request that the confirmed run
// of this id covers passes; every other one is refused like any request without approval (403
// approval_required), and neither the fan window nor the shutdown after boot is asked: a request that names a
// run stands on the run alone. With trust off nothing is checked, as ever. to is the version the confirmation
// named (for an update).
func (g *Gate) RunCovers(req api.ApprovalRequest, id string) (to string, ref *Refusal) {
	if g == nil {
		return "", nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.runAdmit(req, id, false)
}

// AdmitRun is Admit for such a request, asked when it is about to be carried out: the one update, or the one
// shutdown, of the confirmed run is used up, and the record is written before the request is let through (if
// it cannot be written, the request is refused). The shutdown ends the run.
func (g *Gate) AdmitRun(req api.ApprovalRequest, id string) (to string, ref *Refusal) {
	if g == nil {
		return "", nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.runAdmit(req, id, true)
}

func (g *Gate) runAdmit(req api.ApprovalRequest, id string, use bool) (string, *Refusal) {
	canon, on, ref := g.enforced(req)
	if !on || ref != nil {
		return "", ref
	}
	now := g.o.Now()
	live, why := g.runCover(req, id, now)
	if why == "" && use && g.o.ReadOnly {
		why = "this agent cannot record that it was used"
	}
	if why != "" {
		g.o.Log.Warn("approval: required, none sent; the run named does not cover it", "result", "refused", "request", canon, "run", cleanForLog(id), "why", why)
		return "", noneSentRun(why)
	}
	to := live.To
	if !use {
		return to, nil
	}
	up, _ := g.uptime()
	var err error
	if isShutdown(req) {
		live.Shutdown, live.Update = 0, 0
		g.o.Log.Warn("approval: accepted, the one shutdown of the run", "result", "accepted", "request", canon, "run", id, "sub", live.Sub, "kid", live.Kid)
		err = g.runEnd(api.RunDone, "the run's shutdown was let through", now, up)
	} else {
		live.Update = 0
		g.o.Log.Warn("approval: accepted, the one update of the run", "result", "accepted", "request", canon, "run", id, "to", to, "sub", live.Sub, "kid", live.Kid)
		err = g.runWrite(now, up)
	}
	if err != nil { // used up for this process, and not let through: a restart must not find it unused
		return "", &Refusal{Status: 503, Code: api.CodeRunUnavailable, Msg: "not run: the run record could not be written (" + firstLine(err.Error()) + ")"}
	}
	return to, nil
}

// DisarmRun ends the live run: the machine does not switch itself off, and nothing of the run is let through
// any more. Nothing arms again in this boot (the mark stays). was is the state the run was in ("": there was
// none, and nothing changed); with api.RunOffPending the caller stops the countdown. An error: the record
// could not be written; the run is over for this process, and a restart of the service would find it again.
func (g *Gate) DisarmRun(why string) (was string, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.o.ReadOnly || !g.o.Runs {
		return "", nil
	}
	now := g.o.Now()
	up, _ := g.uptime()
	if !g.rs.loaded {
		g.runRead(now, up)
	}
	if g.rs.file == nil || g.rs.file.Run == nil {
		if g.rs.dirty {
			return "", g.runWrite(now, up)
		}
		return "", nil
	}
	was = g.rs.file.Run.State
	err = g.runEnd(api.RunCancelled, why, now, up)
	g.rs.lostPending = false // the caller stops the countdown
	return was, err
}

// runPoll is the watcher's look, once a second: while a run is live the record is read again, so a cancel
// made on the machine (helper-run cancel) is seen. stop says that a countdown this service started must be
// stopped: the run it belonged to ended in another way than by a cancel that stops it itself.
func (g *Gate) runPoll() (live *runLive, up time.Duration, stop bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.o.ReadOnly || !g.o.Runs {
		return nil, 0, false
	}
	m := &g.rs
	defer func() { stop, m.lostPending = m.lostPending, false }()
	now := g.o.Now()
	up, ok := g.uptime()
	if !m.loaded {
		g.reload(false)
		g.runRead(now, up)
	}
	if m.file == nil || m.file.Run == nil { // nothing live: no file is read, and nothing else is done
		if m.dirty {
			g.runWrite(now, up)
		}
		return nil, up, false
	}
	g.reload(false)
	if !ok {
		g.runEnd(api.RunCancelled, "this machine cannot say how long it has been up", now, up)
		return nil, up, false
	}
	g.runSync(now, up)
	if r := g.runNow(now, up); r != nil {
		c := *r
		return &c, up, false
	}
	return nil, up, false
}

// runBeginOff turns the armed run id into one that is counting down, and writes that down before the shutdown
// is scheduled: a service that restarts in between schedules no second one. false: it is not armed any more
// (confirmed or cancelled in this moment), or the record could not be written; nothing is scheduled then.
func (g *Gate) runBeginOff(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.o.Now()
	up, ok := g.uptime()
	if !ok {
		return false
	}
	r := g.runNow(now, up)
	if r == nil || r.ID != id || r.State != api.RunArmed || g.rs.dirty {
		return false
	}
	r.State, r.OffUpMS = api.RunOffPending, max(up.Milliseconds(), r.ArmedUpMS, 1)
	if err := g.runWrite(now, up); err != nil {
		r.State, r.OffUpMS = api.RunArmed, 0
		g.rs.dirty = false
		return false
	}
	return true
}

// runOffEnded ends the run id that was counting down: the shutdown could not be scheduled, or the machine is
// still running after its time.
func (g *Gate) runOffEnded(id, why string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.o.Now()
	up, _ := g.uptime()
	if f := g.rs.file; f != nil && f.Run != nil && f.Run.ID == id && f.Run.State == api.RunOffPending {
		g.runEnd(api.RunCancelled, why, now, up)
		g.rs.lostPending = false // there is no countdown (any more)
	}
}

// runStatus is the "run" of the approval block. Caller holds g.mu.
func (g *Gate) runStatus() *api.RunStatus {
	if !g.o.Runs || g.o.ReadOnly || g.state != api.ApprovalRequired {
		return nil
	}
	up, ok := g.uptime()
	if !ok {
		return nil
	}
	now := g.o.Now()
	r := g.runNow(now, up)
	f := g.rs.file
	if r == nil {
		if f != nil && f.Last != nil && g.maybeThisBoot(f.At, now, up) {
			return &api.RunStatus{ID: f.Last.ID, State: f.Last.State}
		}
		return nil
	}
	st := &api.RunStatus{ID: r.ID, State: r.State}
	at := func(upMS int64) int64 {
		return now.Add(time.Duration(upMS)*time.Millisecond - up).Unix()
	}
	switch r.State {
	case api.RunArmed:
		st.OffAt = at(r.ArmedUpMS + int64(r.WaitS)*1000)
	case api.RunOffPending:
		st.OffAt = at(r.OffUpMS + int64(r.NoticeS)*1000)
	}
	return st
}
