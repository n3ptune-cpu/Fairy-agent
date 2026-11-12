// Package proto is the wire format between fairy-agent (the low-rights service, NT SERVICE\fairy-agent) and
// fairy-agent-helper (the LocalSystem service) on Windows: one named pipe, length-prefixed JSON frames, a fixed
// list of verbs with a strict schema each. There is no verb that takes a path, a command or free text: what the
// helper may be asked is exactly the list below, and every parameter is a small number or one word from a
// fixed list. Everything here is platform-independent and tested on Linux; the pipe itself is in winpipe.
package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// Version is the protocol version of every request that existed before approvals. Nothing about those requests
// or their frames changed, so an agent and a helper of different ages still understand each other for them.
//
// Version3 is the version of what came with approvals: the verbs challenge and trust_init, and any request
// that carries an approval. Such a request says so twice: "v": 3 in the JSON, and the FrameV3 bit in the
// frame's length prefix (only frames with that bit may be longer than MaxRequest). Each request has exactly one
// version: a Version3 frame holds only requests that need Version3, a plain frame only the others.
//
// There is no version 2 any more. It was the same requests in the test build of 2026-11-11, never released,
// whose approvals were not bound to a machine: its entries had no machine id, its trust file none, and its
// nonce was another. Nothing of it is spoken, by either side: a helper of this version refuses a request
// marked 2, and an agent of this version treats a helper that says 2 like one from before approvals (it hands
// it nothing that needs an approval; the machine's answer is approval_unavailable). A machine with that test
// build gets this version of both services installed.
//
// How the ages fail: a helper from before approvals reads a FrameV3 length as a frame of over 2 GiB, answers
// too_large and closes the connection, having run nothing. The test build's helper reads the frame and refuses
// the request for its version number, having run nothing. A helper of this version refuses, while trust is
// set, every request that needs an approval and carries none, whatever version or age the agent has.
const (
	Version  = 1
	Version3 = 3
	// MaxVersion is what this build speaks (StatusData.Proto).
	MaxVersion = Version3
)

// versionRetired is the version number of the test build of 2026-11-11 (see Version3).
const versionRetired = 2

// FrameV3 is set in the 4-byte length prefix of a Version3 request frame (the same bit the test build's
// version 2 used: a frame says how long it may be, the request in it says which version it is).
const FrameV3 = 1 << 31

// ServiceName is the helper's Windows service.
const ServiceName = "fairy-agent-helper"

// PipeName is the helper's named pipe (local only: remote clients are refused by the pipe and its DACL).
const PipeName = `\\.\pipe\fairy-agent-helper`

// Size limits of one frame (the 4-byte length prefix not counted).
const (
	MaxRequest = 512 // a Version request: the largest valid one is well under 200 bytes
	// MaxRequestV3 is the limit of a Version3 request: an ID token of at most 8192 bytes, at most 64 entries of
	// about 200 bytes, or a first trust (4 keys of 8192 bits, 32 users).
	MaxRequestV3 = 32 << 10
	MaxResponse  = 1 << 20 // the BMC's sensor list; Core Temp's block is under 7 KB
)

// Verbs.
const (
	VerbPing         = "ping"
	VerbStatus       = "status"
	VerbCoreTempRead = "coretemp_read"
	VerbIPMISensors  = "ipmi_sensors"
	VerbFanStatus    = "fan_status"
	VerbFanSet       = "fan_set"
	VerbFanMode      = "fan_mode"
	VerbFanAuto      = "fan_auto"
	VerbPower        = "power"
	VerbApplyUpdate  = "apply_update"
	// Version3 only.
	VerbChallenge = "challenge"  // a challenge for one exact fan_set, fan_mode, power or apply_update request, or for trust_init
	VerbTrustInit = "trust_init" // the first trust, accepted only while the helper has none and with an approval that proves it
)

// ForTrustSet is the "for" of a challenge for the first-time set of the trust (api.ApproveTrustSet): the
// request that will follow is trust_init, and the challenge is bound to the hash of the trust it will propose
// ("trust_hash").
const ForTrustSet = api.ApproveTrustSet

// MinDuty is the lowest fan duty any request may ask for, whatever config.yaml says.
const MinDuty = 30

// FanModes a fan_mode request may name.
var FanModes = []string{"standard", "full", "optimal", "heavyio"}

// PowerActions a power request may name.
var PowerActions = []string{"shutdown", "reboot", "sleep", "cancel"}

// Delay limits of a power request (seconds).
const (
	MinDelayS = 10
	MaxDelayS = 86400
)

// Request is one call. Only the fields its verb takes may be present (see Validate).
type Request struct {
	V       int     `json:"v"`
	Verb    string  `json:"verb"`
	Zone    *int    `json:"zone,omitempty"`
	Percent *int    `json:"percent,omitempty"`
	Mode    *string `json:"mode,omitempty"`
	Action  *string `json:"action,omitempty"`
	DelayS  *int    `json:"delay_s,omitempty"`
	By      *string `json:"by,omitempty"` // who asked (for the audit log): letters, digits, " ._@-", up to 64
	// Version3 only.
	Approval *api.Approval  `json:"approval,omitempty"` // fan_set, fan_mode, power (not cancel), apply_update
	For      *string        `json:"for,omitempty"`      // challenge: the verb the challenge is for, with that verb's fields
	Trust    *api.TrustInit `json:"trust,omitempty"`    // trust_init: the proposed trust with the approval that proves it
	// TrustHash (challenge for trust_set): api.TrustHash of the trust that will be proposed.
	TrustHash *string `json:"trust_hash,omitempty"`
}

// Control reports whether the verb changes something (the helper's control rate limit and audit log).
func Control(verb string) bool {
	switch verb {
	case VerbFanSet, VerbFanMode, VerbFanAuto, VerbPower, VerbApplyUpdate, VerbChallenge, VerbTrustInit:
		return true
	}
	return false
}

// fields each verb takes ("by" is allowed on every control verb).
var verbFields = map[string][]string{
	VerbPing: {}, VerbStatus: {}, VerbCoreTempRead: {}, VerbIPMISensors: {}, VerbFanStatus: {},
	VerbFanSet:      {"zone", "percent", "by", "approval"},
	VerbFanMode:     {"mode", "by", "approval"},
	VerbFanAuto:     {"by"},
	VerbPower:       {"action", "delay_s", "by", "approval"},
	VerbApplyUpdate: {"by", "approval"},
	VerbChallenge:   {"for", "zone", "percent", "mode", "action", "delay_s", "trust_hash", "by"},
	VerbTrustInit:   {"trust", "by"},
}

// ApprovalRequestOf is r as the request an approval is given for, when r is one that needs an approval while
// trust is set: fan_set, fan_mode, power other than cancel, apply_update. For a challenge it is the request the
// challenge is asked for (which may also be the first-time set of the trust). ok is false for every other
// request (reads, fan_auto, power cancel; trust_init checks its own approval).
func ApprovalRequestOf(r Request) (api.ApprovalRequest, bool) {
	verb := r.Verb
	if verb == VerbChallenge && r.For != nil {
		if verb = *r.For; verb == ForTrustSet {
			return api.ApprovalRequest{Verb: api.ApproveTrustSet, TrustHash: r.TrustHash}, true
		}
	}
	switch verb {
	case VerbFanSet:
		return api.ApprovalRequest{Verb: api.ApproveFanSet, Zone: r.Zone, Percent: r.Percent}, true
	case VerbFanMode:
		return api.ApprovalRequest{Verb: api.ApproveFanMode, Mode: r.Mode}, true
	case VerbPower:
		if r.Action != nil && *r.Action != "cancel" {
			return api.ApprovalRequest{Verb: api.ApprovePower, Action: r.Action, DelayS: r.DelayS}, true
		}
	case VerbApplyUpdate:
		return api.ApprovalRequest{Verb: api.ApproveApplyUpdate}, true
	}
	return api.ApprovalRequest{}, false
}

// Verbs lists every verb, sorted.
func Verbs() []string {
	out := make([]string, 0, len(verbFields))
	for v := range verbFields {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

var byRe = regexp.MustCompile(`^[A-Za-z0-9 ._@-]{1,64}$`)

// Error codes of a Response.
const (
	CodeBadRequest  = "bad_request"
	CodeUnknownVerb = "unknown_verb"
	CodeTooLarge    = "too_large"
	CodeRateLimited = "rate_limited"
	CodeDisabled    = "disabled"    // the feature is off in config.yaml
	CodeUnavailable = "unavailable" // e.g. Core Temp is not running
	CodeDenied      = "denied"      // e.g. Core Temp's memory refused the helper
	CodeFailed      = "failed"
	// Approval (the texts are pkg/agent/api's, so the panel reads the same code whoever refused).
	CodeApprovalRequired    = api.CodeApprovalRequired    // trust is set and the request carried no approval
	CodeApprovalRefused     = api.CodeApprovalRefused     // the approval it carried was not accepted
	CodeApprovalUnavailable = api.CodeApprovalUnavailable // the trust file cannot be used: nothing is approved
	CodeTrustAlreadySet     = api.CodeTrustAlreadySet     // trust_init when a trust file exists
	CodeTrustInvalid        = api.CodeTrustInvalid
	CodeTrustUnsupportedKey = api.CodeTrustUnsupportedKey
	CodeTrustProofRequired  = api.CodeTrustProofRequired // trust_init without the approval that proves the trust
	CodeTrustProofRefused   = api.CodeTrustProofRefused  // that approval does not verify against the proposed trust
)

// Error is a refused request: a code from the list above and a short message.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func bad(f string, a ...any) *Error { return &Error{Code: CodeBadRequest, Msg: fmt.Sprintf(f, a...)} }

// Validate checks a request against its verb's schema.
func (r *Request) Validate() error {
	if r.V == versionRetired {
		return bad("protocol version %d was a test build's and is not spoken any more: install the same version of fairy-agent and fairy-agent-helper", r.V)
	}
	if r.V != Version && r.V != Version3 {
		return bad("protocol version %d, want %d or %d", r.V, Version, Version3)
	}
	allowed, ok := verbFields[r.Verb]
	if !ok {
		return &Error{Code: CodeUnknownVerb, Msg: "unknown verb"}
	}
	present := map[string]bool{"zone": r.Zone != nil, "percent": r.Percent != nil, "mode": r.Mode != nil,
		"action": r.Action != nil, "delay_s": r.DelayS != nil, "by": r.By != nil,
		"approval": r.Approval != nil, "for": r.For != nil, "trust": r.Trust != nil, "trust_hash": r.TrustHash != nil}
	for f, p := range present {
		if p && !slices.Contains(allowed, f) {
			return bad("%s does not take %s", r.Verb, f)
		}
	}
	if want := FrameVersion(*r); r.V != want {
		return bad("this %s request is protocol version %d, not %d", r.Verb, want, r.V)
	}
	if r.By != nil && !byRe.MatchString(*r.By) {
		return bad("by must be 1-64 letters, digits, spaces or ._@-")
	}
	switch r.Verb {
	case VerbFanSet:
		if r.Zone == nil || r.Percent == nil {
			return bad("fan_set needs zone and percent")
		}
		if *r.Zone != 0 && *r.Zone != 1 {
			return bad("zone must be 0 or 1")
		}
		if *r.Percent < MinDuty || *r.Percent > 100 {
			return bad("percent must be %d-100", MinDuty)
		}
	case VerbFanMode:
		if r.Mode == nil || !slices.Contains(FanModes, *r.Mode) {
			return bad("mode must be one of %s", strings.Join(FanModes, ", "))
		}
	case VerbPower:
		if r.Action == nil || !slices.Contains(PowerActions, *r.Action) {
			return bad("action must be one of %s", strings.Join(PowerActions, ", "))
		}
		if *r.Action == "cancel" {
			if r.DelayS != nil {
				return bad("cancel takes no delay_s")
			}
			if r.Approval != nil {
				return bad("cancel takes no approval")
			}
		} else if r.DelayS == nil || *r.DelayS < MinDelayS || *r.DelayS > MaxDelayS {
			return bad("delay_s must be %d-%d", MinDelayS, MaxDelayS)
		}
	case VerbChallenge:
		// the request the challenge is for must itself be a valid request, and one that needs an approval
		if r.For == nil {
			return bad("challenge needs for")
		}
		if *r.For == ForTrustSet { // the first-time set: the hash of the trust that will be proposed and nothing else
			if r.Zone != nil || r.Percent != nil || r.Mode != nil || r.Action != nil || r.DelayS != nil {
				return bad("a challenge for trust_set takes trust_hash only")
			}
			if _, err := (api.ApprovalRequest{Verb: api.ApproveTrustSet, TrustHash: r.TrustHash}).Canonical(); err != nil {
				return bad("%s", err.Error())
			}
			break
		}
		if r.TrustHash != nil {
			return bad("trust_hash is for a challenge for trust_set")
		}
		inner := Request{V: Version, Verb: *r.For, Zone: r.Zone, Percent: r.Percent, Mode: r.Mode, Action: r.Action, DelayS: r.DelayS}
		if _, ok := ApprovalRequestOf(inner); !ok || inner.Verb == VerbChallenge {
			return bad("a challenge is for fan_set, fan_mode, power (not cancel), apply_update or trust_set")
		}
		if err := inner.Validate(); err != nil {
			return err
		}
	case VerbTrustInit:
		if r.Trust == nil {
			return bad("trust_init needs trust")
		}
	}
	for _, ap := range []*api.Approval{r.Approval, trustApproval(r.Trust)} {
		if ap != nil && (len(ap.Token) > api.MaxApprovalToken || len(ap.Entries) > api.MaxApprovalEntries) {
			return &Error{Code: CodeTooLarge, Msg: "approval too large"}
		}
	}
	return nil
}

func trustApproval(t *api.TrustInit) *api.Approval {
	if t == nil {
		return nil
	}
	return t.Approval
}

// FrameVersion is the one protocol version r is sent in: Version3 for challenge, trust_init and a request with
// an approval, Version for everything else.
func FrameVersion(r Request) int {
	if r.Verb == VerbChallenge || r.Verb == VerbTrustInit || r.Approval != nil {
		return Version3
	}
	return Version
}

// DecodeRequest parses and validates one plain (Version) request frame: exactly one JSON object, no unknown
// fields, no duplicate or extra data, at most MaxRequest bytes.
func DecodeRequest(b []byte) (Request, error) { return decodeRequest(b, Version) }

// DecodeRequestV3 is DecodeRequest for a frame that arrived with FrameV3: at most MaxRequestV3 bytes, and a
// request that needs Version3.
func DecodeRequestV3(b []byte) (Request, error) { return decodeRequest(b, Version3) }

func decodeRequest(b []byte, version int) (Request, error) {
	var r Request
	limit := MaxRequest
	if version == Version3 {
		limit = MaxRequestV3
	}
	if len(b) > limit {
		return r, &Error{Code: CodeTooLarge, Msg: "request too large"}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Request{}, bad("invalid request: %s", firstLine(err.Error()))
	}
	if dec.More() {
		return Request{}, bad("one request per frame")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Request{}, bad("one request per frame")
	}
	if err := r.Validate(); err != nil {
		return Request{}, err
	}
	if r.V != version { // Validate made sure r.V is the request's one version; the frame must be of the same
		return Request{}, bad("a protocol version %d request in a version %d frame", r.V, version)
	}
	return r, nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// EncodeRequest validates and encodes a request (the agent side).
func EncodeRequest(r Request) ([]byte, error) {
	if r.V == 0 { // the old version for everything the old protocol has, so an older helper still understands it
		r.V = FrameVersion(r)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	limit := MaxRequest
	if r.V == Version3 {
		limit = MaxRequestV3
	}
	if len(b) > limit {
		return nil, &Error{Code: CodeTooLarge, Msg: "request too large"}
	}
	return b, nil
}

// Response is the answer to one request. Status follows HTTP (200 ok; the fan and power verbs return the
// status the agent's HTTP API answers with); Code and Error are set when the request was refused or failed;
// Data is the verb's result.
type Response struct {
	Status int             `json:"status"`
	Code   string          `json:"code,omitempty"`
	Error  string          `json:"error,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	// RetryAfterS: with a refusal that says when to ask again (too_many_challenges), in how many seconds. The
	// agent passes it on as the Retry-After header of its HTTP answer.
	RetryAfterS int `json:"retry_after_s,omitempty"`
}

// OK is a 200 response with data.
func OK(data any) Response { return WithStatus(200, data) }

// WithStatus is a response with a status and data.
func WithStatus(status int, data any) Response {
	b, err := json.Marshal(data)
	if err != nil {
		return Fail(CodeFailed, "cannot encode the answer")
	}
	return Response{Status: status, Data: b}
}

// Fail is a refusal. The status is derived from the code.
func Fail(code, msg string) Response {
	st := 500
	switch code {
	case CodeBadRequest, CodeUnknownVerb, CodeTrustInvalid, CodeTrustUnsupportedKey:
		st = 400
	case CodeApprovalRequired, CodeApprovalRefused, CodeTrustProofRequired, CodeTrustProofRefused:
		st = 403
	case CodeTrustAlreadySet:
		st = 409
	case CodeApprovalUnavailable:
		st = 503
	case CodeTooLarge:
		st = 413
	case CodeRateLimited:
		st = 429
	case CodeDisabled:
		st = 404
	case CodeUnavailable, CodeDenied:
		st = 503
	}
	return Response{Status: st, Code: code, Error: msg}
}

// FromError turns a validation error into a response.
func FromError(err error) Response {
	var e *Error
	if errors.As(err, &e) {
		return Fail(e.Code, e.Msg)
	}
	return Fail(CodeFailed, firstLine(err.Error()))
}

// DecodeResponse parses one response frame.
func DecodeResponse(b []byte) (Response, error) {
	var r Response
	if len(b) > MaxResponse {
		return r, errors.New("helper answer too large")
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return Response{}, errors.New("invalid answer from the helper")
	}
	if r.Status < 100 || r.Status > 599 {
		return Response{}, errors.New("invalid answer from the helper")
	}
	return r, nil
}

// WriteFrame writes a 4-byte big-endian length and the payload in one write.
func WriteFrame(w io.Writer, b []byte, limit int) error {
	if len(b) > limit {
		return fmt.Errorf("frame of %d bytes exceeds %d", len(b), limit)
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err := w.Write(buf)
	return err
}

// WriteRequest writes one request frame of the given version (FrameVersion): a Version3 frame has FrameV3 set
// in its length prefix and may be MaxRequestV3 bytes long.
func WriteRequest(w io.Writer, b []byte, version int) error {
	limit, flag := MaxRequest, uint32(0)
	if version == Version3 {
		limit, flag = MaxRequestV3, FrameV3
	}
	if len(b) > limit {
		return fmt.Errorf("frame of %d bytes exceeds %d", len(b), limit)
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b))|flag)
	copy(buf[4:], b)
	_, err := w.Write(buf)
	return err
}

// ReadRequest reads one request frame and returns its version: Version for a plain frame (at most MaxRequest
// bytes, exactly as before Version3), Version3 for one with FrameV3 (at most MaxRequestV3). A longer one is
// ErrFrameTooLarge, and nothing of it is read.
func ReadRequest(r io.Reader) ([]byte, int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, err
	}
	n, version, limit := binary.BigEndian.Uint32(hdr[:]), Version, uint32(MaxRequest)
	if n&FrameV3 != 0 {
		n, version, limit = n&^FrameV3, Version3, MaxRequestV3
	}
	if n > limit {
		return nil, version, ErrFrameTooLarge
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, version, err
	}
	return b, version, nil
}

// ErrFrameTooLarge is a frame whose length prefix exceeds the limit (nothing of it is read).
var ErrFrameTooLarge = errors.New("frame too large")

// ReadFrame reads one frame of at most limit bytes. An oversized length prefix is refused before reading the
// body, so a peer cannot make the reader allocate more than limit.
func ReadFrame(r io.Reader, limit int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > uint32(limit) {
		return nil, ErrFrameTooLarge
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return b, nil
}

// Limiter allows n events per window (sliding), per class of request. No class can use up another's budget.
type Limiter struct {
	mu     sync.Mutex
	n      map[string]int
	window time.Duration
	hits   map[string][]time.Time
	Now    func() time.Time
}

// Default rate limits of the helper, a minute: reads (the agent polls Core Temp every 2 s and the BMC every
// 10 s, the panel asks for the fan status), changes (the agent itself allows 12 control requests a minute by
// default), challenges (the agent passes on at most control_rate_per_min a minute, 60 at most) and the two
// requests that only make things safer.
const (
	ReadsPerMinute      = 300
	ChangesPerMinute    = 30
	ChallengesPerMinute = 60
	SafePerMinute       = 30
)

// The classes of request a Limiter counts separately.
const (
	classRead   = "read"
	classChange = "change" // fan_set, fan_mode, power (not cancel), apply_update, trust_init
	// classChallenge: the verb challenge. It changes nothing but the helper's list of open challenges, and it
	// must not be able to use up the budget of the requests it is asked for, nor that of a cancel.
	classChallenge = "challenge"
	// classSafe: power cancel and fan_auto, the two requests that only make things safer (and that the agent
	// sends with nobody present). Nothing but themselves can keep them out.
	classSafe = "safe"
)

// NewLimiter returns a limiter with reads and changes per window; challenges and the safe requests each get a
// budget of their own (ChallengesPerMinute and SafePerMinute, or changes if that is more).
func NewLimiter(reads, changes int, window time.Duration) *Limiter {
	return &Limiter{n: map[string]int{classRead: reads, classChange: changes, classChallenge: max(changes, ChallengesPerMinute),
		classSafe: max(changes, SafePerMinute)}, window: window, hits: map[string][]time.Time{}, Now: time.Now}
}

// classOf is the class a request counts in.
func classOf(r Request) string {
	switch {
	case !Control(r.Verb):
		return classRead
	case r.Verb == VerbChallenge:
		return classChallenge
	case r.Verb == VerbFanAuto, r.Verb == VerbPower && r.Action != nil && *r.Action == "cancel":
		return classSafe
	}
	return classChange
}

// Allow counts one request of verb and reports whether it is within the limit. It knows only the verb, so a
// power request counts as a change whatever its action; AllowRequest tells a cancel apart.
func (l *Limiter) Allow(verb string) bool { return l.AllowRequest(Request{Verb: verb}) }

// AllowRequest counts one request in its class and reports whether it is within that class's limit.
func (l *Limiter) AllowRequest(r Request) bool {
	c := classOf(r)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	h := l.hits[c]
	i := 0
	for i < len(h) && now.Sub(h[i]) >= l.window {
		i++
	}
	h = h[i:]
	if len(h) >= l.n[c] {
		l.hits[c] = h
		return false
	}
	l.hits[c] = append(h, now)
	return true
}
