// Package plugs is everything in fairy-agent that asks a Home Assistant about a plug's sockets, and the only
// code in it that can change something there: it reads the state of a socket's switch and, for a request that
// carries a passkey approval, turns one switch on or off.
//
// What this package can make a Home Assistant do, in full (this file):
//
//   - GET  <url>/api/states/<entity>               read one state (through devices.ReadJSON, which has no other method)
//   - POST <url>/api/services/switch/turn_on       with the body {"entity_id": "<entity>"}
//   - POST <url>/api/services/switch/turn_off      with the body {"entity_id": "<entity>"}
//
// and nothing else. <url> is the agent's own home_assistant.url, checked when the config is read. <entity> is
// always the id of a switch (power.HASwitchEntity: `switch.` and then lower-case letters, digits and
// underscores), checked again here before every request, so it can change neither the path nor the JSON text.
// The two service paths are constants: there is no toggle, no other domain, no service named by a caller, and
// no function that takes a path. Neither the entity nor the address ever comes from a request to the agent:
// both come from config.yaml on this machine.
//
// A Home Assistant token carries no limits (whoever holds it can do everything its user can), so what Fairy
// does with it is limited by what this file can send.
package plugs

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// The states of a socket as this package reports them. Home Assistant says "on" or "off" for a switch that it
// reaches, "unavailable" for one it does not, and "unknown" for one it has no state for; anything else it may
// say is reported as StateUnknown.
const (
	StateOn          = "on"
	StateOff         = "off"
	StateUnavailable = "unavailable"
	StateUnknown     = "unknown"
)

// The two requests that change something. They are constants, not built from anything.
const (
	pathStates  = "/api/states/"
	pathTurnOn  = "/api/services/switch/turn_on"
	pathTurnOff = "/api/services/switch/turn_off"
)

// maxSwitchAnswer is how much of the answer to a switch request is read before it is thrown away. The answer
// is a JSON list of the states that changed; nothing in it is used (it is 200 with an empty list also when
// Home Assistant left the entity out because it is not available), so it is not decoded at all.
const maxSwitchAnswer = 64 << 10

// HA is one Home Assistant: its address, the name of the variable that holds the token, and for https the
// certificate check. It keeps no token: the variable is read for every request.
type HA struct {
	scheme, host string          // http | https, host[:port]
	base         string          // scheme://host[:port]
	tokenEnv     string          // the NAME of the variable
	tlsCfg       *tls.Config     // https: always verified, with ca_file when one is set; nil for http
	tr           *http.Transport // https: the transport of the state reads (connections kept); nil for http
}

// NewHA checks the address, the variable's name and the ca_file by the rules of config.yaml (the caller has
// checked them already; nothing is sent to an address or with a variable that does not pass here) and returns
// the Home Assistant. Its errors repeat no value but the ca_file's path when that file cannot be used.
func NewHA(rawURL, tokenEnv, caFile string) (*HA, error) {
	scheme, host, ok := power.HAAddress(rawURL)
	if !ok {
		return nil, errors.New("home_assistant.url must be the address of Home Assistant itself, http(s)://host[:port], with nothing after it")
	}
	if problem := power.HATokenEnvProblem(tokenEnv); problem != "" {
		return nil, errors.New("home_assistant." + problem)
	}
	h := &HA{scheme: scheme, host: host, base: scheme + "://" + host, tokenEnv: tokenEnv}
	if caFile != "" && scheme != "https" {
		return nil, errors.New("home_assistant.ca_file is only for an https url")
	}
	if scheme == "https" {
		tc, err := power.TLSConfig(true, caFile) // always verified: neither the token nor a switch request goes to whoever answers
		if err != nil {
			return nil, errors.New("home_assistant.ca_file: " + err.Error())
		}
		h.tlsCfg, h.tr = tc, devices.TLSTransport(tc)
	}
	return h, nil
}

// Scheme is http or https; Host is host[:port]; TokenEnv is the name of the token's variable. For the config
// check's lines.
func (h *HA) Scheme() string   { return h.scheme }
func (h *HA) Host() string     { return h.host }
func (h *HA) TokenEnv() string { return h.tokenEnv }

// What the token's variable holds, as far as anybody is told (TokenState). Nothing else about the value is
// ever said: not the value, not a part of it, not how long it is.
const (
	TokenOK       = iota // a value that is sent as the token
	TokenMissing         // nothing
	TokenUnusable        // a value that is never sent: a space, a line break, another control character or a byte that is not plain ASCII is in it
)

// TokenState says what the token's variable holds right now, by the rule a request goes by (token): TokenOK
// only for a value that a request would send.
func (h *HA) TokenState() int {
	_, err := h.token()
	var nt *NoToken
	switch {
	case err == nil:
		return TokenOK
	case errors.As(err, &nt) && nt.Unusable:
		return TokenUnusable
	}
	return TokenMissing
}

// TokenSet reports whether the token's variable holds a token that a request would send. A value that token
// refuses is not "set": /metrics then says no_token for the sockets, no challenge is given for a switch, and
// check-config does not say "present" for it.
func (h *HA) TokenSet() bool { return h.TokenState() == TokenOK }

// Close gives up the kept connections.
func (h *HA) Close() {
	if h.tr != nil {
		h.tr.CloseIdleConnections()
	}
}

// refusal is the error for a token that Home Assistant did not accept (401 or 403). power.Refused is true for
// it: after it the states are asked for again much later, not at the next round (power.RefusedWait).
type refusal struct{ err *devices.Error }

func (e *refusal) Error() string { return e.err.Msg }
func (e *refusal) Unwrap() error { return e.err }
func (e *refusal) Refused() bool { return true }

// errRefused is the one refusal there is. Its text is fixed.
func errRefused() error {
	return &refusal{err: &devices.Error{Msg: "home assistant refused the token"}}
}

// NoToken is the error of a request that was not made because the token's variable holds nothing that can be a
// token: nothing at all, or (Unusable) a value that is never sent. Its text names the variable, never a value.
type NoToken struct {
	Env      string
	Unusable bool
}

func (e *NoToken) Error() string {
	holds := "holds no token"
	if e.Unusable {
		holds = "holds a value that cannot be a token"
	}
	return "the variable " + e.Env + " " + holds + " for Home Assistant (fairy-agent secret set " + e.Env + ", then restart the agent)"
}

// token reads the token from the environment, for one request. It is never kept, logged or put into an error.
func (h *HA) token() (string, error) {
	tok := os.Getenv(h.tokenEnv)
	if tok == "" {
		return "", &NoToken{Env: h.tokenEnv}
	}
	for i := 0; i < len(tok); i++ { // what cannot be sent in a header as it is, is not a token
		if tok[i] <= ' ' || tok[i] >= 0x7f {
			return "", &NoToken{Env: h.tokenEnv, Unusable: true}
		}
	}
	return tok, nil
}

// asNoToken reports whether err is a NoToken.
func asNoToken(err error, target **NoToken) bool { return errors.As(err, target) }

// Describe is a short fixed text for an error of this package that is safe to show and to log: never a
// header, an address or anything Home Assistant sent.
func Describe(err error) string {
	var nt *NoToken
	if errors.As(err, &nt) {
		return nt.Error()
	}
	var se *SwitchError
	if errors.As(err, &se) {
		return se.Error()
	}
	return devices.Describe(err)
}

// safe passes on the errors that are fixed texts of pkg/devices ("timeout", "connection failed", "http 500",
// "invalid JSON from device") and gives the two refusals of Home Assistant their own. An error of any other
// kind, and one whose text held the token or its header (there is none today), becomes a fixed word.
func safe(err error, tok string) error {
	var he *devices.HTTPStatusError
	if errors.As(err, &he) {
		switch he.Code {
		case http.StatusUnauthorized, http.StatusForbidden:
			return errRefused()
		case http.StatusNotFound:
			return devices.Errf("entity not found")
		}
		return err
	}
	var de *devices.Error
	if !errors.As(err, &de) || strings.Contains(de.Msg, "Bearer") || (len(tok) >= 8 && strings.Contains(de.Msg, tok)) {
		return devices.Errf("request failed")
	}
	return err
}

// errNotASwitch is the error for an entity id that is not a switch's. No request is made for it.
func errNotASwitch() error { return devices.Errf("not the entity id of a switch") }

// State reads the state of one switch: one GET <url>/api/states/<entity>, within timeout. It returns StateOn,
// StateOff, StateUnavailable or StateUnknown, and an error when Home Assistant gave no state at all (a fixed
// text: Describe). The request carries the token and nothing else of this machine. A redirect is not followed
// and no proxy is used (pkg/devices).
//
// An answer that names another entity than the one asked for is not believed (an error): whatever answers
// there is not telling about this switch.
func (h *HA) State(ctx context.Context, entity string, timeout time.Duration) (string, error) {
	if !power.HASwitchEntity(entity) {
		return "", errNotASwitch()
	}
	tok, err := h.token()
	if err != nil {
		return "", err
	}
	hc := devices.LANClient(timeout)
	if h.tr != nil {
		hc = devices.ClientWith(timeout, h.tr)
	}
	state := StateUnknown
	err = devices.ReadJSON(ctx, hc, h.base+pathStates+entity, "bearer", "", tok, func(d map[string]any) error {
		if id, has := d["entity_id"]; has && id != entity {
			return devices.Errf("home assistant answered for another entity")
		}
		switch s, _ := d["state"].(string); s {
		case StateOn, StateOff, StateUnavailable:
			state = s
		}
		return nil
	})
	if err != nil {
		return "", safe(err, tok)
	}
	return state, nil
}

// SwitchError is a switch request that Home Assistant did not take, or did not answer.
type SwitchError struct {
	// Status is the HTTP status Home Assistant answered with (never 200 or 201). 0: there was no answer (no
	// connection, a timeout, the connection cut): the request may have arrived all the same.
	Status int
	// NotSent: the request was certainly not sent (no token, not a switch's id). Only then is nothing spent.
	NotSent bool
	why     string
}

func (e *SwitchError) Error() string { return e.why }

// Denied reports whether Home Assistant answered the switch request with 401 or 403. That is not the same as
// "the token is refused": it answers a service call so also when the token is good and its user may not
// control this entity. So a SwitchError is never a refusal in the sense of power.Refused (it has no method
// Refused), and nothing waits because of it; only a state read tells that the token is not accepted.
func (e *SwitchError) Denied() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
}

// Switch sends the one request that turns a switch on (on true) or off: POST
// <url>/api/services/switch/turn_on or .../turn_off with the body {"entity_id": "<entity>"}, within timeout.
// nil: Home Assistant answered 200 or 201. That says the request was taken, not that the socket switched:
// Home Assistant leaves out an entity that is not available and still answers 200. Whoever calls this reads
// the state afterwards and reports only what that shows.
//
// The request is sent once. It has a transport and a connection of its own, used for nothing else and not
// kept: Go's client sends a request again by itself only when the kept connection it was written to turned out
// to be dead, which a new connection never is; and it cannot send this one again in any case, because the
// request is given no way to produce its body a second time. A redirect is not followed (the 3xx is the
// answer, and an error here), so the request and the token go to the address of the config and nowhere else.
//
// The answer's body is read up to maxSwitchAnswer bytes and thrown away.
func (h *HA) Switch(ctx context.Context, entity string, on bool, timeout time.Duration) error {
	if !power.HASwitchEntity(entity) {
		return &SwitchError{NotSent: true, why: "not the entity id of a switch"}
	}
	tok, err := h.token()
	if err != nil {
		return &SwitchError{NotSent: true, why: err.Error()}
	}
	path := pathTurnOff
	if on {
		path = pathTurnOn
	}
	body, err := json.Marshal(struct {
		EntityID string `json:"entity_id"`
	}{entity})
	if err != nil {
		return &SwitchError{NotSent: true, why: "request failed"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.base+path, bytes.NewReader(body))
	if err != nil {
		return &SwitchError{NotSent: true, why: "request failed"}
	}
	req.GetBody = nil // nobody can send this request a second time
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	tr := devices.TLSTransport(h.tlsCfg) // a copy of the LAN transport: no proxy, HTTP/1.1, the header limit
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()
	resp, err := devices.ClientWith(timeout, tr).Do(req)
	if err != nil {
		why := "no answer"
		if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
			why = "no answer in time"
		}
		return &SwitchError{why: why}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxSwitchAnswer))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return &SwitchError{Status: resp.StatusCode, why: "home assistant refused the switch request with http " + strconv.Itoa(resp.StatusCode) +
			": its token is not accepted, or its user may not switch this socket"}
	}
	return &SwitchError{Status: resp.StatusCode, why: "home assistant answered http " + strconv.Itoa(resp.StatusCode)}
}
