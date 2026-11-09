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
)

// Version is the protocol version; a request with another "v" is refused.
const Version = 1

// ServiceName is the helper's Windows service.
const ServiceName = "fairy-agent-helper"

// PipeName is the helper's named pipe (local only: remote clients are refused by the pipe and its DACL).
const PipeName = `\\.\pipe\fairy-agent-helper`

// Size limits of one frame (the 4-byte length prefix not counted).
const (
	MaxRequest  = 512     // the largest valid request is well under 200 bytes
	MaxResponse = 1 << 20 // the BMC's sensor list; Core Temp's block is under 7 KB
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
)

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
}

// Control reports whether the verb changes something (the helper's control rate limit and audit log).
func Control(verb string) bool {
	switch verb {
	case VerbFanSet, VerbFanMode, VerbFanAuto, VerbPower, VerbApplyUpdate:
		return true
	}
	return false
}

// fields each verb takes ("by" is allowed on every control verb).
var verbFields = map[string][]string{
	VerbPing: {}, VerbStatus: {}, VerbCoreTempRead: {}, VerbIPMISensors: {}, VerbFanStatus: {},
	VerbFanSet:      {"zone", "percent", "by"},
	VerbFanMode:     {"mode", "by"},
	VerbFanAuto:     {"by"},
	VerbPower:       {"action", "delay_s", "by"},
	VerbApplyUpdate: {"by"},
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
	if r.V != Version {
		return bad("protocol version %d, want %d", r.V, Version)
	}
	allowed, ok := verbFields[r.Verb]
	if !ok {
		return &Error{Code: CodeUnknownVerb, Msg: "unknown verb"}
	}
	present := map[string]bool{"zone": r.Zone != nil, "percent": r.Percent != nil, "mode": r.Mode != nil,
		"action": r.Action != nil, "delay_s": r.DelayS != nil, "by": r.By != nil}
	for f, p := range present {
		if p && !slices.Contains(allowed, f) {
			return bad("%s does not take %s", r.Verb, f)
		}
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
		} else if r.DelayS == nil || *r.DelayS < MinDelayS || *r.DelayS > MaxDelayS {
			return bad("delay_s must be %d-%d", MinDelayS, MaxDelayS)
		}
	}
	return nil
}

// DecodeRequest parses and validates one request frame: exactly one JSON object, no unknown fields, no
// duplicate or extra data, at most MaxRequest bytes.
func DecodeRequest(b []byte) (Request, error) {
	var r Request
	if len(b) > MaxRequest {
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
	if r.V == 0 {
		r.V = Version
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxRequest {
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
	case CodeBadRequest, CodeUnknownVerb:
		st = 400
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

// Limiter allows n events per window (sliding), per class of verb.
type Limiter struct {
	mu     sync.Mutex
	n      map[bool]int
	window time.Duration
	hits   map[bool][]time.Time
	Now    func() time.Time
}

// Default rate limits of the helper: reads (the agent polls Core Temp every 2 s and the BMC every 10 s, the
// panel asks for the fan status) and changes (the agent itself allows 12 control requests a minute).
const (
	ReadsPerMinute   = 300
	ChangesPerMinute = 30
)

// NewLimiter returns a limiter with reads and changes per window.
func NewLimiter(reads, changes int, window time.Duration) *Limiter {
	return &Limiter{n: map[bool]int{false: reads, true: changes}, window: window,
		hits: map[bool][]time.Time{}, Now: time.Now}
}

// Allow counts one request of verb and reports whether it is within the limit.
func (l *Limiter) Allow(verb string) bool {
	c := Control(verb)
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
