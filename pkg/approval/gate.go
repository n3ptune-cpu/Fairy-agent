package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// Limits of the gate.
const (
	// ChallengeTTL is how long a challenge can be answered. UpdateChallengeTTL is for apply_update, where the
	// download happens between the approval and the request the helper sees.
	ChallengeTTL       = 180 * time.Second
	UpdateChallengeTTL = 900 * time.Second
	// MaxChallenges open at a time. One more is given only when the oldest open one is at least
	// ChallengeProtect old (that one is then dropped); otherwise it is refused (too_many_challenges).
	MaxChallenges = 16
	// ChallengeProtect is how long a challenge is safe from being dropped for a newer one: half the life of an
	// ordinary challenge. Somebody may be confirming it at Pocket ID at that moment. See Gate.Challenge.
	ChallengeProtect = ChallengeTTL / 2
	// reloadEvery: the trust file is looked at again at most this often, so a change made on the machine
	// (helper-trust set / clear) is in effect within this time.
	reloadEvery = 5 * time.Second
	// BootShutdownMaxDelayS is the longest delay the one shutdown without approval shortly after boot
	// (boot_shutdown_s in the trust file) may ask for: it is for "switch off again now", not for a shutdown
	// that is scheduled in the first minutes and happens a day later.
	BootShutdownMaxDelayS = 600
	// bootSlack: a recorded shutdown after boot counts for this boot when it was accepted no earlier than this
	// long before the boot began, by this machine's clock (used only where the system has no id of its boot).
	bootSlack = 2 * time.Minute
)

// Options build a Gate.
type Options struct {
	Files      Files
	EnforcedBy string // api.EnforcedByHelper or api.EnforcedByAgent
	// Now is the clock (nil: time.Now, whose values also carry the monotonic clock).
	Now func() time.Time
	// Uptime is how long the system has been up (nil or an error: the shutdown-after-boot setting never applies).
	Uptime func() (time.Duration, error)
	// BootID is the system's own id of this boot, where it has one (Linux). nil, "" or an error: whether the
	// one shutdown after boot was used in this boot is told from the recorded time and the uptime instead.
	BootID func() (string, error)
	// ReadOnly: this gate reads a trust file it cannot write and does not own (a Windows agent next to the
	// helper, whose file it is). It checks requests and gives challenges for them; it never sets the trust,
	// gives no challenge for that, never accepts the shutdown after boot (it could not record it), and never
	// adds a machine id to a trust file that has none (the owner does).
	ReadOnly bool
	// Rand is the source of challenges and of a machine id that is made up here (nil: crypto/rand).
	Rand io.Reader
	// Log gets one line for every accepted and every refused approval (nil: slog.Default()).
	Log *slog.Logger
}

// Refusal is a request the gate does not let through: the HTTP status, the code and the text of the answer.
type Refusal struct {
	Status int
	Code   string
	Msg    string
	// RetryAfterS, when not 0, is in how many seconds the same request can be sent again with a chance of
	// another answer (too_many_challenges): the answer's Retry-After header and its "retry_after_s".
	RetryAfterS int
}

func (r *Refusal) Error() string { return r.Code + ": " + r.Msg }

func refuse(reason, detail string) *Refusal {
	return &Refusal{Status: 403, Code: api.CodeApprovalRefused, Msg: "approval refused (" + reason + "): " + detail}
}

type challenge struct {
	id      [32]byte
	request string    // canonical
	issued  time.Time // the gate's clock when it was issued (wall and, with time.Now, monotonic)
	ttl     time.Duration
}

// Gate decides whether a request that needs an approval may run.
type Gate struct {
	o Options

	mu       sync.Mutex
	state    string
	trust    *Trust
	loadErr  string
	rawSum   [32]byte
	loadedAt time.Time
	loaded   bool
	open     []challenge
	fanAt    time.Time // when the approval that opened the fan window was accepted (zero: closed)
	epoch    uint64    // counts the changes of the trust file's content: what was given under one does not count under the next
	bootUsed bool      // the one shutdown after boot was accepted in this boot (by this process, or recorded)
}

// Pass is a request the gate let through (Admit). Whoever carries the request out tells the pass when it was
// really applied: only then does an approved fan change open the fan window. A request that the machine then
// refuses, or that changes nothing, opens nothing.
type Pass struct {
	g       *Gate
	request string    // canonical
	at      time.Time // the gate's clock when the approval was accepted
	epoch   uint64    // Gate.epoch at that moment
	applied bool
}

// Applied says that the request the pass was given for has been carried out and changed what it asked for
// (the fan controller answered 200). If the pass is an accepted approval of a fan change, the fan window is
// open from now on, counted from the moment that approval was accepted (so it never ends later than
// fan_window_s after the passkey check was accepted, however long the change itself took). It does nothing for
// a nil pass (a request that needed no approval: trust off, inside the window, the shutdown after boot), when
// called a second time, and when the trust file changed in between.
func (p *Pass) Applied() {
	if p == nil {
		return
	}
	g := p.g
	g.mu.Lock()
	defer g.mu.Unlock()
	if p.applied || p.epoch != g.epoch || g.trust == nil {
		return
	}
	p.applied = true
	if g.fanAt.IsZero() || elapsed(g.fanAt, p.at) > 0 {
		g.fanAt = p.at
	}
	if w := g.trust.FanWindow(); w > 0 {
		g.o.Log.Info("approval: fan window open, the approved fan change was applied", "request", p.request, "window_s", w)
	}
}

// NewGate returns the gate. The trust file is read at the first question.
func NewGate(o Options) *Gate {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Gate{o: o}
}

// elapsed is the time from since to now by whichever of the two clocks says more: the monotonic clock (which
// does not jump, but on some systems stands still while the machine sleeps) and the wall clock (which keeps
// counting through sleep, but can be set). A deadline measured with it is never later than intended.
func elapsed(since, now time.Time) time.Duration {
	return max(now.Sub(since), now.Round(0).Sub(since.Round(0)))
}

// reload reads the trust file again when the last look is older than reloadEvery (or force). When the file's
// content changed, open challenges and the fan window are dropped: they were given under the old trust.
//
// A trust file without a machine id (one from the test build of 2026-11-11) gets one here, the first time the
// gate that owns the file sees it, which is when the service starts (Files.AddMachineID: that one member is
// added, nothing else changes). A gate that only reads the file, or one that cannot write it, does not use the
// file: the state is broken, with the reason, until the id is there. Caller holds g.mu.
func (g *Gate) reload(force bool) {
	now := g.o.Now()
	if g.loaded && !force && elapsed(g.loadedAt, now) < reloadEvery && elapsed(g.loadedAt, now) >= 0 {
		return
	}
	state, t, raw, err := g.o.Files.Load()
	if errors.Is(err, ErrNoMachineID) && !g.o.ReadOnly {
		id, aerr := g.o.Files.AddMachineID(g.o.Rand)
		if aerr == nil {
			g.o.Log.Warn("approval: the trust file had no machine id (it is from before approvals were bound to the machine); one was added, nothing else in it changed",
				"enforced_by", g.o.EnforcedBy, "machine_id", id)
			state, t, raw, err = g.o.Files.Load()
		} else { // the answer's text is cut after 300 characters: a long reason gives way, what to do stays
			const pre, post = ": the trust file has no machine_id, and adding one failed: ", " (the file is as it was; repair on the machine: fairy-agent helper-trust set)"
			why := firstLine(aerr.Error())
			if room := 300 - len(g.o.Files.Path) - len(pre) - len(post); len(why) > room && room > 3 {
				why = why[:room-3] + "..."
			}
			err = fmt.Errorf("%s%s%s%s", g.o.Files.Path, pre, why, post)
		}
	}
	if state != api.ApprovalRequired {
		t = nil // also the file without a machine id, which Load hands out for its values: never checked with
	}
	sum := sha256.Sum256(raw)
	msg := ""
	if err != nil {
		msg = err.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
	}
	if !g.loaded || state != g.state || sum != g.rawSum || msg != g.loadErr {
		if g.loaded || state != api.ApprovalOff {
			g.o.Log.Warn("approval: "+state, "enforced_by", g.o.EnforcedBy, "error", msg)
		}
		g.open, g.fanAt = nil, time.Time{}
		g.epoch++
	}
	g.state, g.trust, g.loadErr, g.rawSum, g.loadedAt, g.loaded = state, t, msg, sum, now, true
}

// Status is the "approval" block.
func (g *Gate) Status() api.ApprovalStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reload(false)
	return g.status()
}

// StatusNow is Status with the trust file read at this moment, not up to five seconds ago: for a decision that
// must not rest on an old look (the Windows agent's POST /update while its helper is not answering).
func (g *Gate) StatusNow() api.ApprovalStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reload(true)
	return g.status()
}

func (g *Gate) status() api.ApprovalStatus {
	st := api.ApprovalStatus{State: g.state, Proto: api.ApprovalProto}
	switch g.state {
	case api.ApprovalRequired:
		st = g.trust.Status()
	case api.ApprovalBroken:
		st.Error = g.loadErr
	}
	st.EnforcedBy = g.o.EnforcedBy
	return st
}

func unavailable(why string) *Refusal {
	return &Refusal{Status: 503, Code: api.CodeApprovalUnavailable,
		Msg: "the approval trust file on this machine cannot be used, so nothing that needs an approval is run: " + why +
			" (an administrator repairs it on the machine: fairy-agent helper-trust show)"}
}

func isFan(req api.ApprovalRequest) bool {
	return req.Verb == api.ApproveFanSet || req.Verb == api.ApproveFanMode
}

func isShutdown(req api.ApprovalRequest) bool {
	return req.Verb == api.ApprovePower && req.Action != nil && *req.Action == "shutdown"
}

// fanLeft is how much of the fan window is left (0: closed). Caller holds g.mu.
func (g *Gate) fanLeft(now time.Time) time.Duration {
	if g.fanAt.IsZero() || g.trust == nil {
		return 0
	}
	e := elapsed(g.fanAt, now)
	w := time.Duration(g.trust.FanWindow()) * time.Second
	if e < 0 || e >= w {
		return 0
	}
	return w - e
}

// bootWindow reports whether req, a shutdown, can be the one shutdown without approval of this boot: the
// setting is on, the delay asked for is at most BootShutdownMaxDelayS, the system has been up for less than
// the setting says, and none was accepted in this boot yet (by this process or, per the record next to the
// trust file, by one before it: a restarted service gets no second one). Caller holds g.mu.
func (g *Gate) bootWindow(req api.ApprovalRequest, now time.Time) (time.Duration, bool) {
	if g.trust == nil || g.trust.BootShutdownS <= 0 || g.bootUsed || g.o.Uptime == nil || g.o.ReadOnly {
		return 0, false
	}
	if req.DelayS == nil || *req.DelayS < 0 || *req.DelayS > BootShutdownMaxDelayS {
		return 0, false
	}
	up, err := g.o.Uptime()
	if err != nil || up < 0 || up >= time.Duration(g.trust.BootShutdownS)*time.Second {
		return 0, false
	}
	if g.usedThisBoot(now, up) {
		return 0, false
	}
	return up, true
}

func (g *Gate) bootID() string {
	if g.o.BootID == nil {
		return ""
	}
	id, err := g.o.BootID()
	if err != nil || len(id) > 128 {
		return ""
	}
	return id
}

// usedThisBoot reads the record of the last shutdown that was accepted without approval and reports whether it
// belongs to this boot. With the system's own boot id on both sides that is exact. Without one it is decided
// by the clock: the record counts for this boot unless it was made clearly before this boot began (now minus
// uptime). A record that cannot be read counts as "used": nothing unapproved is accepted on a guess.
// Caller holds g.mu.
func (g *Gate) usedThisBoot(now time.Time, up time.Duration) bool {
	m, err := g.o.Files.readBootMark()
	if err != nil {
		g.o.Log.Warn("approval: the record of the shutdown after boot cannot be read, so none is accepted without approval", "error", firstLine(err.Error()))
		return true
	}
	if m == nil {
		return false
	}
	if id := g.bootID(); id != "" && m.BootID != "" {
		if m.BootID != id {
			return false
		}
	} else if time.Unix(m.UsedAt, 0).Before(now.Add(-up).Add(-bootSlack)) {
		return false
	}
	g.bootUsed = true
	return true
}

// expire drops the challenges whose time is over. Caller holds g.mu.
func (g *Gate) expire(now time.Time) {
	keep := g.open[:0]
	for _, c := range g.open {
		if e := elapsed(c.issued, now); e >= 0 && e < c.ttl {
			keep = append(keep, c)
		}
	}
	g.open = keep
}

func prefix(id [32]byte) string { return base64.RawURLEncoding.EncodeToString(id[:])[:8] }

// Challenge answers POST /approval/challenge for req: a fresh challenge bound to it, or that it needs none now.
func (g *Gate) Challenge(req api.ApprovalRequest) (api.ChallengeResponse, *Refusal) {
	canon, err := req.Canonical()
	if err != nil {
		return api.ChallengeResponse{}, &Refusal{Status: 400, Code: "bad_request", Msg: "not a request that can be approved: " + err.Error()}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reload(false)
	out := api.ChallengeResponse{Request: canon}
	now := g.o.Now()
	switch {
	case req.Verb == api.ApproveTrustSet:
		// the one request that is approved while there is no trust: the first-time set itself (Init)
		if g.state != api.ApprovalOff {
			return out, g.notSettable()
		}
		if g.o.ReadOnly {
			return out, notHere()
		}
	case g.state == api.ApprovalOff:
		out.Reason = "off"
		return out, nil
	case g.state != api.ApprovalRequired:
		return out, unavailable(g.loadErr)
	case isFan(req) && g.fanLeft(now) > 0:
		out.Reason = "fan_window"
		return out, nil
	case isShutdown(req):
		if _, ok := g.bootWindow(req, now); ok {
			out.Reason = "boot_shutdown"
			return out, nil
		}
	}
	c := challenge{request: canon, issued: now, ttl: challengeTTL(req)}
	// The list is full (expired and used challenges are gone from it already). Whoever holds the control
	// token can ask for challenges, so a rule that always drops the oldest lets him make every approval that
	// is in flight worthless with sixteen requests, without anybody being told; and a rule that never drops
	// one lets him shut everybody out for as long as the longest challenge lives (an update's: 15 minutes)
	// with sixteen requests. So: a challenge is never dropped while it is younger than ChallengeProtect (90 s,
	// time enough for the passkey step), and the request that would need its place is refused, openly. Once
	// the oldest is older than that it makes room, as before. Keeping the list full therefore takes sixteen
	// requests every 90 s, about what using up the request budget itself takes (twelve a minute by default),
	// which whoever holds the control token can do anyway. A panel asks for one challenge per machine and
	// action (at most sixteen for one machine in one confirmation) and uses them within seconds: it never
	// sees this.
	g.expire(now)
	if len(g.open) >= MaxChallenges {
		oldest := g.open[0] // the list is in the order of issue
		if age := elapsed(oldest.issued, now); age < ChallengeProtect {
			wait := max(1, int((ChallengeProtect-age+time.Second-1)/time.Second))
			g.o.Log.Warn("approval: no challenge given, too many are open", "result", "refused", "request", canon, "open", len(g.open), "retry_s", wait)
			return out, &Refusal{Status: 429, Code: api.CodeTooManyChallenges, RetryAfterS: wait, Msg: "this machine holds " + strconv.Itoa(len(g.open)) +
				" open challenges, and none of them is dropped for a new one before it is " + strconv.Itoa(int(ChallengeProtect/time.Second)) +
				" s old (somebody may be confirming it right now). Try again in " + strconv.Itoa(wait) + " s"}
		}
		g.o.Log.Warn("approval: the oldest open challenge was dropped for a new one", "request", oldest.request, "challenge", prefix(oldest.id),
			"age_s", int(elapsed(oldest.issued, now)/time.Second))
		g.open = append(g.open[:0], g.open[1:]...)
	}
	if _, err := io.ReadFull(g.o.Rand, c.id[:]); err != nil {
		return out, &Refusal{Status: 500, Code: "failed", Msg: "no random numbers for a challenge"}
	}
	g.open = append(g.open, c)
	g.o.Log.Info("approval: challenge issued", "request", canon, "challenge", prefix(c.id))
	out.Needed, out.Challenge, out.ExpiresInS = true, base64.RawURLEncoding.EncodeToString(c.id[:]), int(c.ttl/time.Second)
	if g.trust != nil { // none yet for trust_set: its token is checked against the proposed values
		out.Issuer, out.ClientID = g.trust.Issuer, g.trust.ClientID
	}
	return out, nil
}

// find is the index of the open challenge with this id (-1: none). Every open challenge is compared, each in
// constant time. Caller holds g.mu.
func (g *Gate) find(id []byte) int {
	at := -1
	for i := range g.open {
		if subtle.ConstantTimeCompare(g.open[i].id[:], id) == 1 {
			at = i
		}
	}
	return at
}

// enforced answers what every question about a request starts with. on is false when nothing is checked (no
// trust file): the request may run. A refusal: the trust file cannot be used, or the request has no canonical
// form. Otherwise trust is set and canon is the request's text. Caller holds g.mu.
func (g *Gate) enforced(req api.ApprovalRequest) (canon string, on bool, ref *Refusal) {
	g.reload(false)
	switch g.state {
	case api.ApprovalOff:
		return "", false, nil
	case api.ApprovalRequired:
		if g.trust == nil || g.trust.MachineID == "" { // cannot happen (Files.Load); nothing is ever checked with an empty id
			g.o.Log.Error("approval: refused", "result", "refused", "reason", "the trust has no machine id", "verb", req.Verb)
			return "", true, unavailable(ErrNoMachineID.Msg)
		}
	default:
		g.o.Log.Warn("approval: refused", "result", "refused", "reason", "trust file unusable", "verb", req.Verb)
		return "", true, unavailable(g.loadErr)
	}
	canon, err := req.Canonical()
	if err != nil { // nothing without a canonical form is ever run while trust is set
		return "", true, &Refusal{Status: 400, Code: "bad_request", Msg: "not a request that can be approved: " + err.Error()}
	}
	return canon, true, nil
}

func notCarriedOut() *Refusal {
	return &Refusal{Status: 400, Code: "bad_request", Msg: "the trust is set with POST " + api.PathApprovalTrust}
}

func noneSent() *Refusal {
	return &Refusal{Status: 403, Code: api.CodeApprovalRequired,
		Msg: "this needs a passkey approval (Pocket ID) and the request carried none"}
}

// Precheck is the first of the two questions about a request, asked when the request arrives, before any of
// the request's own checks. It uses nothing up and records nothing. It refuses what can be refused without
// looking at an approval: the trust file cannot be used (503), or the request needs an approval and carries
// none (sent is false), and neither the fan window nor the one shutdown after boot would let it through now
// (403 approval_required). A request that carries an approval passes here whatever is in it: the approval is
// looked at once, by Admit, when the request has passed its own checks and is about to be carried out. So a
// request that the machine refuses for a reason of its own (a delay under the minimum, an action already
// pending, a duty the fans do not take) costs neither the approval nor the shutdown after boot.
func (g *Gate) Precheck(req api.ApprovalRequest, sent bool) *Refusal {
	if g == nil {
		return nil
	}
	if req.Verb == api.ApproveTrustSet {
		return notCarriedOut()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	canon, on, ref := g.enforced(req)
	if !on || ref != nil || sent {
		return ref
	}
	now := g.o.Now()
	if isFan(req) && g.fanLeft(now) > 0 {
		return nil
	}
	if isShutdown(req) {
		if _, ok := g.bootWindow(req, now); ok {
			return nil
		}
	}
	g.o.Log.Warn("approval: required, none sent", "result", "refused", "request", canon)
	return noneSent()
}

// Admit is the second question, asked at the moment req is about to be carried out: every check of the request
// itself has passed, and what comes next is the system call or the BMC command. ap is the approval the request
// carried (nil: none). The refusal is nil when the request may run: trust is off; or the approval was
// accepted, in which case its challenge is used up before Admit returns, whatever becomes of the request from
// here on (an action that then fails does not make the approval usable again); or the request needs none
// right now (the fan window, or the one shutdown after boot, which is recorded here). An approval that is
// sent is always checked in full. A nil Gate lets everything run.
//
// The pass is not nil when an approval of a fan change was accepted: the caller tells it when the change was
// applied (Pass.Applied), and only that opens the fan window.
func (g *Gate) Admit(req api.ApprovalRequest, ap *api.Approval) (*Pass, *Refusal) {
	if g == nil {
		return nil, nil
	}
	if req.Verb == api.ApproveTrustSet { // not a request that is carried out: Init checks its own approval
		return nil, notCarriedOut()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	canon, on, ref := g.enforced(req)
	if !on || ref != nil {
		return nil, ref
	}
	now := g.o.Now()
	if ap == nil {
		if left := g.fanLeft(now); isFan(req) && left > 0 {
			g.o.Log.Warn("approval: not needed, fan window", "result", "accepted", "request", canon, "left_s", int(left/time.Second))
			return nil, nil
		}
		if isShutdown(req) {
			if up, ok := g.bootWindow(req, now); ok {
				// recorded first: a service that is restarted in this boot finds the record and gives no second one
				err := g.o.Files.writeBootMark(bootMark{BootID: g.bootID(), UsedAt: now.Unix(), UptimeS: int64(up / time.Second)})
				if err == nil {
					g.bootUsed = true
					g.o.Log.Warn("approval: UNAPPROVED shutdown accepted shortly after boot (boot_shutdown_s in the trust file)",
						"result", "accepted", "request", canon, "uptime_s", int(up/time.Second), "limit_s", g.trust.BootShutdownS)
					return nil, nil
				}
				g.o.Log.Error("approval: the shutdown after boot was not accepted without approval: it could not be recorded",
					"result", "refused", "request", canon, "error", firstLine(err.Error()))
			}
		}
		g.o.Log.Warn("approval: required, none sent", "result", "refused", "request", canon)
		return nil, noneSent()
	}
	c, cl, reason, other := g.verify(g.trust, g.trust.MachineID, canon, ap, now)
	if reason != "" {
		attrs := []any{"result", "refused", "reason", reason, "request", canon, "sub", cl.Sub, "kid", cl.Kid, "challenge", c}
		if other {
			// The answer says "nonce" like every token that was made for another list. The log says what the
			// machine saw: this approval was built for another machine and carries this machine's challenge.
			attrs = append(attrs, "note", "the entry with this machine's challenge names another machine id than this machine's")
		}
		g.o.Log.Warn("approval: refused", attrs...)
		return nil, refuse(reason, refusalText[reason])
	}
	g.o.Log.Warn("approval: accepted", "result", "accepted", "request", canon, "sub", cl.Sub, "name", cl.Name, "kid", cl.Kid,
		"challenge", c)
	if isFan(req) { // the fan window opens when the change was applied, not here (Pass.Applied)
		return &Pass{g: g, request: canon, at: now, epoch: g.epoch}, nil
	}
	return nil, nil
}

// verify checks ap for the request canon against the trust t (the machine's own, or for the first-time set the
// proposed one) and, when everything holds, uses up its challenge. machineID is this machine's id: the one in
// its trust file, or for the first-time set the proposed one (empty when none is proposed). It returns the
// challenge's log prefix (when one was found), what is known of the token, the reason of a refusal ("" =
// accepted), and whether the entry with this machine's challenge named another machine id than machineID (for
// the log). Caller holds g.mu, so finding, checking and using up the challenge are one step: of two requests
// with the same approval one is accepted.
//
// What ties an approval to this machine is the nonce, and the nonce is made here from this machine's own
// knowledge: its open challenge, the request it is about to carry out, and machineID. The list that was sent
// says which other entries the token covers; of this machine's own entry only the challenge is believed (it is
// looked up among the open ones). The machine id is written into that entry here, whatever was sent, and the
// token must have been issued for the list that results. So a token that was issued for (this machine's
// challenge, this request, another machine's id), which is what a panel signs when it was handed this
// machine's challenge in the name of another machine, has another nonce and is refused.
func (g *Gate) verify(t *Trust, machineID, canon string, ap *api.Approval, now time.Time) (string, claims, string, bool) {
	if len(ap.Token) > api.MaxApprovalToken {
		return "", claims{}, ReasonFormat, false
	}
	// bounds the list and refuses a malformed entry and a challenge that is in it twice
	if _, err := api.ApprovalNonce(ap.Entries); err != nil {
		return "", claims{}, ReasonEntries, false
	}
	mine, at, n := -1, -1, 0
	for j, e := range ap.Entries {
		id, err := api.DecodeChallenge(e.Challenge)
		if err != nil {
			return "", claims{}, ReasonEntries, false
		}
		i := g.find(id)
		if i < 0 {
			continue // another machine's entry
		}
		if g.open[i].request != e.Request {
			return prefix(g.open[i].id), claims{}, ReasonEntries, false // this machine's challenge, listed with another request
		}
		if e.Request == canon {
			mine, at, n = i, j, n+1
		}
	}
	switch {
	case n == 0:
		return "", claims{}, ReasonNoChallenge, false
	case n > 1:
		return "", claims{}, ReasonAmbiguous, false
	}
	c := g.open[mine]
	p := prefix(c.id)
	if e := elapsed(c.issued, now); e < 0 || e >= c.ttl {
		g.open = append(g.open[:mine], g.open[mine+1:]...)
		return p, claims{}, ReasonExpired, false
	}
	other := ap.Entries[at].MachineID != machineID
	nonce, err := ownNonce(ap.Entries, at, machineID, canon)
	if err != nil { // machineID is not one: cannot happen for a trust that was loaded or a proposal that was checked
		return p, claims{}, ReasonEntries, other
	}
	cl, reason := verifyToken(ap.Token, t, nonce, now, c.issued)
	if reason != "" {
		return p, cl, reason, other
	}
	g.open = append(g.open[:mine], g.open[mine+1:]...) // used up, before anything runs
	return p, cl, "", other
}

// challengeTTL is how long a challenge for req can be answered.
func challengeTTL(req api.ApprovalRequest) time.Duration {
	if req.Verb == api.ApproveApplyUpdate {
		return UpdateChallengeTTL
	}
	return ChallengeTTL
}

// ownNonce is the nonce a token must carry for this machine to accept entries: the list as it was sent, with
// this machine's id and the request it is about to carry out written into the entry at (its own).
func ownNonce(entries []api.MachineEntry, at int, machineID, canon string) (string, error) {
	own := append([]api.MachineEntry(nil), entries...)
	own[at] = api.MachineEntry{MachineID: machineID, Challenge: entries[at].Challenge, Request: canon}
	return api.ApprovalNonce(own)
}

// Preverify looks at an approval for req the way Admit does, as far as a gate can that did not give the
// challenge, and uses nothing up. It is for the one place where the program that takes a request is not the
// one that checks it: the Windows agent, which downloads a release before it hands the approval of an update
// to the helper. There, any "approval" member made the agent download (audit 5, r2-a1-03). With this, an
// approval that the helper is certain to refuse is refused before anything is downloaded. The helper stays the
// only one that accepts an approval and uses it up.
//
// checked is false when this gate cannot say anything (no usable trust file as this process sees it): the
// caller then goes on as without this look. Otherwise ref is nil, or the refusal Admit would give.
//
// What is checked, with the functions Admit's check is made of (api.ApprovalNonce, ownNonce, verifyToken), so
// that the two cannot come apart: the list of entries is well-formed; one of its entries is for exactly this
// request; the token carries the nonce of the list with THIS machine's id in that entry; it is signed with a
// pinned key, from the issuer, for the client, by an allowed user, with a passkey, not expired, and no time in
// it is in this machine's future. What cannot be checked here is the challenge: whether it is one the checker
// gave, still open, and when it was given. So the two times that Admit compares with the challenge's (iat and
// auth_time) are compared with the earliest moment a challenge that can still be answered was given (now
// minus challengeTTL). Every approval Admit would accept at this moment or later therefore passes here; one
// that passes here may still be refused by Admit (a challenge that is used up, expired or made up).
func (g *Gate) Preverify(req api.ApprovalRequest, ap *api.Approval) (checked bool, ref *Refusal) {
	if g == nil || ap == nil {
		return false, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reload(true) // the file as it is now: the checker may have read it later than this gate's last look
	if g.state != api.ApprovalRequired || g.trust == nil || g.trust.MachineID == "" {
		return false, nil
	}
	canon, err := req.Canonical()
	if err != nil {
		return true, &Refusal{Status: 400, Code: "bad_request", Msg: "not a request that can be approved: " + err.Error()}
	}
	now := g.o.Now()
	cl, reason := preverify(g.trust, canon, ap, now, now.Add(-challengeTTL(req)))
	if reason != "" {
		g.o.Log.Warn("approval: refused before it was handed on (nothing was used up)", "result", "refused", "reason", reason, "request", canon, "sub", cl.Sub, "kid", cl.Kid)
		return true, refuse(reason, refusalText[reason])
	}
	return true, nil
}

// preverify is verify without the list of open challenges: every entry for canon is tried as this machine's
// own. earliest stands in for the moment the challenge was given.
func preverify(t *Trust, canon string, ap *api.Approval, now, earliest time.Time) (claims, string) {
	if len(ap.Token) > api.MaxApprovalToken {
		return claims{}, ReasonFormat
	}
	if _, err := api.ApprovalNonce(ap.Entries); err != nil {
		return claims{}, ReasonEntries
	}
	reason := ReasonNoChallenge // no entry is for this request
	for at, e := range ap.Entries {
		if e.Request != canon {
			continue
		}
		nonce, err := ownNonce(ap.Entries, at, t.MachineID, canon)
		if err != nil {
			return claims{}, ReasonEntries
		}
		cl, why := verifyToken(ap.Token, t, nonce, now, earliest)
		if why != ReasonNonce { // accepted, or refused for something that is the same for every entry
			return cl, why
		}
		reason = ReasonNonce
	}
	return claims{}, reason
}

// refusalText says each reason in a sentence (the answer's text; the reason word is in front of it).
var refusalText = map[string]string{
	ReasonEntries:     "the list of entries is not well-formed, or names this machine's challenge with another request",
	ReasonNoChallenge: "no entry holds an open challenge of this machine for this exact request (used already, expired, or issued for another request)",
	ReasonAmbiguous:   "more than one entry matches this request",
	ReasonExpired:     "the challenge is too old; ask again",
	ReasonFormat:      "the token is not a compact ID token of at most 8192 bytes",
	ReasonHeader:      "the token's header is not acceptable",
	ReasonAlg:         "the token is not signed with RS256",
	ReasonKey:         "the token's signing key is not one this machine has pinned (after a key rotation at Pocket ID: fairy-agent helper-trust set on the machine)",
	ReasonSignature:   "the token's signature is wrong",
	ReasonClaims:      "the token's content is not well-formed",
	ReasonIssuer:      "the token is from another issuer",
	ReasonAudience:    "the token was issued for another client",
	ReasonUser:        "this user may not approve actions on this machine",
	ReasonTokenExp:    "the token has expired",
	ReasonClock:       "a time in the token does not fit this machine's clock (is the clock right?)",
	ReasonAuthTime:    "the passkey check is older than the request for approval",
	ReasonAMR:         "the sign-in was not made with a passkey",
	ReasonNonce:       "the token was not issued for this list of entries on this machine",
}

// proofText says some reasons differently for the proof of a first-time set, where "this machine's trust" is
// the proposed one (the others are refusalText's).
var proofText = map[string]string{
	ReasonNoChallenge: "no entry holds an open challenge of this machine for exactly this proposed trust (used already, expired, or asked for other values: ask for a challenge with the verb trust_set and the hash of the values that are sent)",
	ReasonKey:         "the token's signing key is not one of the proposed keys (take the keys from the issuer's jwks_uri)",
	ReasonIssuer:      "the token's issuer is not the proposed issuer (use Pocket ID's own spelling, mind a trailing slash)",
	ReasonAudience:    "the token was issued for another client than the proposed client_id",
	ReasonUser:        "the user who approved is not in the proposed users",
	ReasonNonce:       "the token was not issued for this list of entries with the proposed machine_id in this machine's entry (the entry's machine_id is the machine_id that is sent, or empty when none is sent)",
}

// Init is the first-time set of the trust from the panel. It is accepted only while there is no trust file
// (once a file exists, usable or not, every call is refused with already_set, also one with a valid
// approval and also one that asks for nothing but another machine id), and only together with a proof that the
// proposed trust works: an approval of the request
// "trust_set hash=<api.TrustHash of the proposed values>" for a challenge this machine gave for exactly that
// request, whose token verifies against the PROPOSED values the way every approval verifies against the
// trust file (verifyToken: signed by a proposed key, iss, aud, a proposed user, amr, auth_time, the times
// against this machine's clock, the nonce of the entry list). Only then is the file written, and the machine
// is locked.
//
// What the proof is for: a wrong issuer spelling, client id, user id or key, or a clock that is off, is found
// out while the machine still has no trust, instead of locking it with local repair as the only way out. What
// it is not: a defence against a panel that is already hostile at this moment. Such a panel proposes its own
// issuer and proves against it; before the first-time set it has every control request anyway.
func (g *Gate) Init(in api.TrustInit) (api.ApprovalStatus, *Refusal) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reload(true)
	if g.state != api.ApprovalOff {
		g.o.Log.Warn("approval: trust set from the panel refused", "result", "refused", "reason", api.CodeTrustAlreadySet)
		return g.status(), g.notSettable()
	}
	if g.o.ReadOnly {
		return g.status(), notHere()
	}
	now := g.o.Now()
	t, err := FromInit(in, now, g.o.Rand)
	if err != nil {
		var ve *ValueError
		if !errors.As(err, &ve) { // no random numbers for a machine id
			g.o.Log.Error("approval: trust set from the panel failed", "result", "refused", "error", err.Error())
			return g.status(), &Refusal{Status: 500, Code: "failed", Msg: err.Error()}
		}
		g.o.Log.Warn("approval: trust set from the panel refused", "result", "refused", "reason", ve.Code, "error", err.Error())
		return g.status(), &Refusal{Status: 400, Code: ve.Code, Msg: err.Error()}
	}
	if in.Approval == nil {
		g.o.Log.Warn("approval: trust set from the panel refused", "result", "refused", "reason", api.CodeTrustProofRequired)
		return g.status(), &Refusal{Status: 403, Code: api.CodeTrustProofRequired,
			Msg: "a first-time set of the trust needs a passkey approval that proves it works: ask for a challenge with the verb trust_set and the hash of these values, have it approved at Pocket ID, and send the approval with the values. Nothing was written"}
	}
	canon, err := api.TrustSetRequest(in).Canonical()
	if err != nil { // cannot happen: the hash is 43 characters by construction
		return g.status(), &Refusal{Status: 500, Code: "failed", Msg: "no request text for this trust"}
	}
	// The proof is checked against what was proposed, the machine id included: in.MachineID as it was sent,
	// empty when the panel left the choice to this machine. A proof that was given for one id sets no other.
	c, cl, reason, _ := g.verify(t, in.MachineID, canon, in.Approval, now)
	if reason != "" {
		g.o.Log.Warn("approval: trust set from the panel refused: its proof does not verify against the proposed trust", "result", "refused",
			"reason", reason, "request", canon, "issuer", t.Issuer, "client_id", t.ClientID, "sub", cl.Sub, "kid", cl.Kid, "challenge", c)
		text := proofText[reason]
		if text == "" {
			text = refusalText[reason]
		}
		return g.status(), &Refusal{Status: 403, Code: api.CodeTrustProofRefused, Msg: "proof refused (" + reason + "): " + text + ". Nothing was written"}
	}
	err = g.o.Files.Create(t)
	g.reload(true) // whatever happened, the file on disk is what counts from here on
	switch {
	case errors.Is(err, ErrExists):
		g.o.Log.Warn("approval: trust set from the panel refused", "result", "refused", "reason", api.CodeTrustAlreadySet)
		return g.status(), alreadySet()
	case err != nil:
		g.o.Log.Error("approval: trust set from the panel failed", "result", "refused", "error", err.Error(), "state", g.state)
		return g.status(), &Refusal{Status: 500, Code: "failed", Msg: "the trust file could not be written: " + firstLine(err.Error())}
	case g.state != api.ApprovalRequired:
		g.o.Log.Error("approval: trust was written but cannot be used", "state", g.state, "error", g.loadErr)
		return g.status(), unavailable(g.loadErr)
	}
	kids := make([]string, 0, len(t.Keys))
	for _, k := range t.Keys {
		kids = append(kids, k.Kid)
	}
	g.o.Log.Warn("approval: trust set for the first time, from the panel, proven by a passkey approval; it can now be changed only on this machine",
		"result", "accepted", "machine_id", t.MachineID, "issuer", t.Issuer, "client_id", t.ClientID, "kids", strings.Join(kids, ","), "users", len(t.Users),
		"sub", cl.Sub, "name", cl.Name, "kid", cl.Kid, "challenge", c)
	return g.status(), nil
}

// notHere is the answer of a gate that only reads the trust file when it is asked to set the trust.
func notHere() *Refusal {
	return &Refusal{Status: 404, Code: api.CodeApprovalDisabled,
		Msg: "this agent cannot set the approval trust of this machine; it is set on the machine, by an administrator: fairy-agent helper-trust set"}
}

func alreadySet() *Refusal {
	return &Refusal{Status: 409, Code: api.CodeTrustAlreadySet,
		Msg: "this machine already has a trust file; it is changed only on the machine, by an administrator: fairy-agent helper-trust set"}
}

// notSettable is alreadySet for the one state other than off in which there is no trust file: the folder it
// would be in fails its check (broken, by the rule of Files). The status and the code are alreadySet's, for a
// panel that goes by them: nothing can be set from the network here either. The text says what is true: there
// is no file, and why none can be written (audit 5, r2-a1-07: it said "already has a trust file"). Any other
// state, also one in which it cannot be told whether a file is there, answers alreadySet. Caller holds g.mu.
func (g *Gate) notSettable() *Refusal {
	if g.state != api.ApprovalBroken || g.o.Files.exists() {
		return alreadySet()
	}
	why := firstLine(g.loadErr)
	if why == "" {
		why = "the folder of the trust file cannot be used"
	}
	return &Refusal{Status: 409, Code: api.CodeTrustAlreadySet,
		Msg: "this machine has no trust file, and none can be set from the network: " + why + ". Repair that on the machine, as an administrator; the trust can be set after that (there: fairy-agent helper-trust set)"}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
