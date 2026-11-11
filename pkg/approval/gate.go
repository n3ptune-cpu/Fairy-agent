package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
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
	// MaxChallenges open at a time; one more drops the oldest.
	MaxChallenges = 16
	// reloadEvery: the trust file is looked at again at most this often, so a change made on the machine
	// (helper-trust set / clear) is in effect within this time.
	reloadEvery = 5 * time.Second
)

// Options build a Gate.
type Options struct {
	Files      Files
	EnforcedBy string // api.EnforcedByHelper or api.EnforcedByAgent
	// Now is the clock (nil: time.Now, whose values also carry the monotonic clock).
	Now func() time.Time
	// Uptime is how long the system has been up (nil or an error: the shutdown-after-boot setting never applies).
	Uptime func() (time.Duration, error)
	// Rand is the source of challenges (nil: crypto/rand).
	Rand io.Reader
	// Log gets one line for every accepted and every refused approval (nil: slog.Default()).
	Log *slog.Logger
}

// Refusal is a request the gate does not let through: the HTTP status, the code and the text of the answer.
type Refusal struct {
	Status int
	Code   string
	Msg    string
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
	fanAt    time.Time // when the fan window was opened (zero: closed)
	bootUsed bool      // the one shutdown after boot was accepted
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
// Caller holds g.mu.
func (g *Gate) reload(force bool) {
	now := g.o.Now()
	if g.loaded && !force && elapsed(g.loadedAt, now) < reloadEvery && elapsed(g.loadedAt, now) >= 0 {
		return
	}
	state, t, raw, err := g.o.Files.Load()
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

// bootWindow reports whether the one shutdown after boot is still to be had. Caller holds g.mu.
func (g *Gate) bootWindow() (time.Duration, bool) {
	if g.trust == nil || g.trust.BootShutdownS <= 0 || g.bootUsed || g.o.Uptime == nil {
		return 0, false
	}
	up, err := g.o.Uptime()
	if err != nil || up < 0 || up >= time.Duration(g.trust.BootShutdownS)*time.Second {
		return 0, false
	}
	return up, true
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
	switch g.state {
	case api.ApprovalOff:
		out.Reason = "off"
		return out, nil
	case api.ApprovalRequired:
	default:
		return out, unavailable(g.loadErr)
	}
	now := g.o.Now()
	if isFan(req) && g.fanLeft(now) > 0 {
		out.Reason = "fan_window"
		return out, nil
	}
	if isShutdown(req) {
		if _, ok := g.bootWindow(); ok {
			out.Reason = "boot_shutdown"
			return out, nil
		}
	}
	c := challenge{request: canon, issued: now, ttl: ChallengeTTL}
	if req.Verb == api.ApproveApplyUpdate {
		c.ttl = UpdateChallengeTTL
	}
	if _, err := io.ReadFull(g.o.Rand, c.id[:]); err != nil {
		return out, &Refusal{Status: 500, Code: "failed", Msg: "no random numbers for a challenge"}
	}
	g.expire(now)
	if len(g.open) >= MaxChallenges {
		g.open = append(g.open[:0], g.open[len(g.open)-MaxChallenges+1:]...)
	}
	g.open = append(g.open, c)
	g.o.Log.Info("approval: challenge issued", "request", canon, "challenge", prefix(c.id))
	out.Needed, out.Challenge, out.ExpiresInS = true, base64.RawURLEncoding.EncodeToString(c.id[:]), int(c.ttl/time.Second)
	out.Issuer, out.ClientID = g.trust.Issuer, g.trust.ClientID
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

// Check decides whether req may run now. ap is the approval the request carried (nil: none). It returns nil
// when the request may run: trust is off; or the approval was accepted, in which case its challenge is used up
// before Check returns, whatever the request then does; or the request needs none right now (fan window, the
// one shutdown after boot). An approval that is sent is always checked in full. A nil Gate lets everything run.
func (g *Gate) Check(req api.ApprovalRequest, ap *api.Approval) *Refusal {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reload(false)
	switch g.state {
	case api.ApprovalOff:
		return nil
	case api.ApprovalRequired:
	default:
		g.o.Log.Warn("approval: refused", "result", "refused", "reason", "trust file unusable", "verb", req.Verb)
		return unavailable(g.loadErr)
	}
	canon, err := req.Canonical()
	if err != nil { // nothing without a canonical form is ever run while trust is set
		return &Refusal{Status: 400, Code: "bad_request", Msg: "not a request that can be approved: " + err.Error()}
	}
	now := g.o.Now()
	if ap == nil {
		if left := g.fanLeft(now); isFan(req) && left > 0 {
			g.o.Log.Warn("approval: not needed, fan window", "result", "accepted", "request", canon, "left_s", int(left/time.Second))
			return nil
		}
		if isShutdown(req) {
			if up, ok := g.bootWindow(); ok {
				g.bootUsed = true
				g.o.Log.Warn("approval: UNAPPROVED shutdown accepted shortly after boot (boot_shutdown_s in the trust file)",
					"result", "accepted", "request", canon, "uptime_s", int(up/time.Second), "limit_s", g.trust.BootShutdownS)
				return nil
			}
		}
		g.o.Log.Warn("approval: required, none sent", "result", "refused", "request", canon)
		return &Refusal{Status: 403, Code: api.CodeApprovalRequired,
			Msg: "this needs a passkey approval (Pocket ID) and the request carried none"}
	}
	c, cl, reason := g.verify(canon, ap, now)
	if reason != "" {
		g.o.Log.Warn("approval: refused", "result", "refused", "reason", reason, "request", canon, "sub", cl.Sub, "kid", cl.Kid,
			"challenge", c)
		return refuse(reason, refusalText[reason])
	}
	if isFan(req) {
		g.fanAt = now
	}
	g.o.Log.Warn("approval: accepted", "result", "accepted", "request", canon, "sub", cl.Sub, "name", cl.Name, "kid", cl.Kid,
		"challenge", c)
	return nil
}

// verify checks ap for the request canon and, when everything holds, uses up its challenge. It returns the
// challenge's log prefix (when one was found), what is known of the token, and the reason of a refusal ("" =
// accepted). Caller holds g.mu, so finding, checking and using up the challenge are one step: of two requests
// with the same approval one is accepted.
func (g *Gate) verify(canon string, ap *api.Approval, now time.Time) (string, claims, string) {
	if len(ap.Token) > api.MaxApprovalToken {
		return "", claims{}, ReasonFormat
	}
	nonce, err := api.ApprovalNonce(ap.Entries) // also bounds the list and refuses a challenge that is in it twice
	if err != nil {
		return "", claims{}, ReasonEntries
	}
	mine, n := -1, 0
	for _, e := range ap.Entries {
		id, err := api.DecodeChallenge(e.Challenge)
		if err != nil {
			return "", claims{}, ReasonEntries
		}
		i := g.find(id)
		if i < 0 {
			continue // another machine's entry
		}
		if g.open[i].request != e.Request {
			return prefix(g.open[i].id), claims{}, ReasonEntries // this machine's challenge, listed with another request
		}
		if e.Request == canon {
			mine, n = i, n+1
		}
	}
	switch {
	case n == 0:
		return "", claims{}, ReasonNoChallenge
	case n > 1:
		return "", claims{}, ReasonAmbiguous
	}
	c := g.open[mine]
	p := prefix(c.id)
	if e := elapsed(c.issued, now); e < 0 || e >= c.ttl {
		g.open = append(g.open[:mine], g.open[mine+1:]...)
		return p, claims{}, ReasonExpired
	}
	cl, reason := verifyToken(ap.Token, g.trust, nonce, now, c.issued)
	if reason != "" {
		return p, cl, reason
	}
	g.open = append(g.open[:mine], g.open[mine+1:]...) // used up, before anything runs
	return p, cl, ""
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
	ReasonNonce:       "the token was not issued for this list of entries",
}

// Init is the first-time set of the trust from the panel: accepted only while there is no trust file. Once a
// file exists, usable or not, every call is refused with already_set.
func (g *Gate) Init(in api.TrustInit) (api.ApprovalStatus, *Refusal) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reload(true)
	if g.state != api.ApprovalOff {
		g.o.Log.Warn("approval: trust set from the panel refused", "result", "refused", "reason", api.CodeTrustAlreadySet)
		return g.status(), alreadySet()
	}
	t, err := FromInit(in, g.o.Now())
	if err != nil {
		code := api.CodeTrustInvalid
		var ve *ValueError
		if errors.As(err, &ve) {
			code = ve.Code
		}
		g.o.Log.Warn("approval: trust set from the panel refused", "result", "refused", "reason", code, "error", err.Error())
		return g.status(), &Refusal{Status: 400, Code: code, Msg: err.Error()}
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
	g.o.Log.Warn("approval: trust set for the first time, from the panel; it can now be changed only on this machine",
		"result", "accepted", "issuer", t.Issuer, "client_id", t.ClientID, "kids", strings.Join(kids, ","), "users", len(t.Users))
	return g.status(), nil
}

func alreadySet() *Refusal {
	return &Refusal{Status: 409, Code: api.CodeTrustAlreadySet,
		Msg: "this machine already has a trust file; it is changed only on the machine, by an administrator: fairy-agent helper-trust set"}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
