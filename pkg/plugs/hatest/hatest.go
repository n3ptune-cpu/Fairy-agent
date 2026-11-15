// Package hatest is a made-up Home Assistant for tests: the two things fairy-agent ever asks of one about a
// switch (GET /api/states/<entity> and POST /api/services/switch/turn_on|turn_off), a record of every request
// it saw, and the ways a real one misbehaves. The agent's own tests use it, and the panel's contract test.
//
// Its token is put together when the test runs: no text in this file looks like a credential.
package hatest

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Token is the long-lived access token of the fake's user for switching. Made up, and put together here.
func Token() string {
	return strings.Join([]string{"fake", "ha", "switch", "token", "for", "tests"}, "-")
}

// ReadToken is the token of the fake's second user, the one the meters' sensors are read with. Like a real
// Home Assistant the fake lets either user do everything; it records which one asked (Request.TokenOK,
// Request.ReadToken), so a test can hold that the two are never mixed up.
func ReadToken() string {
	return strings.Join([]string{"fake", "ha", "read", "token", "for", "tests"}, "-")
}

// Request is one request the fake saw.
type Request struct {
	Method  string
	Path    string // the request URI as it was sent, a query included
	Body    string
	TokenOK bool // it carried "Authorization: Bearer <Token()>", the token for switching
	// ReadToken: it carried the token of the user that reads the sensors (ReadToken()).
	ReadToken bool
	Auth      string // the Authorization header as it was sent
}

// Server is the fake. The zero behaviour is an honest Home Assistant: a switch request for an entity that is
// "on" or "off" changes its state at once and is answered 200 with the list of changed states; one for an
// entity that is not available is left out and answered 200 with an empty list, as the real one does.
type Server struct {
	URL string
	srv *httptest.Server

	mu       sync.Mutex
	states   map[string]string
	units    map[string]string // sensors: entity id -> unit of measurement
	reqs     []Request
	stop     chan struct{} // closed by Close: requests that hang end
	now      func() time.Time
	pending  []pending
	settle   settle
	answer   int           // POST: answer this status and switch nothing (0: honest)
	getCode  int           // GET: answer this status (0: honest)
	redirect string        // POST and GET: answer with a redirect to this address
	redirAs  int           // the status of that redirect (0: 307)
	hang     bool          // POST: do not answer at all (until Close)
	hangGet  bool          // GET: do not answer at all (until Close)
	slowGet  time.Duration // GET: answer after this long
	cut      bool          // POST: close the connection without an answer
	late     time.Duration // POST: answer after this long
	ignore   bool          // POST: answer 200 and switch nothing
	lost     bool          // with hang, cut or late: the request does not switch either (default: it does)
	wrongID  string        // GET: answer with this entity_id in the state object
}

// settle says when a state changes after a switch request that the fake took.
type settle struct {
	after time.Duration // on the clock, 0: at once
	reads int           // or: with the n-th state read of that entity after the request (0: not by reads)
	never bool
}

type pending struct {
	entity, to string
	at         time.Time // by the clock (zero: by reads)
	reads      int       // state reads still to go before the change
}

// New starts a fake with these states (entity id -> "on", "off", "unavailable", "unknown" or anything else).
// The caller closes it.
func New(states map[string]string) *Server {
	s := &Server{states: map[string]string{}, stop: make(chan struct{}), now: time.Now}
	for k, v := range states {
		s.states[k] = v
	}
	s.srv = httptest.NewServer(s)
	s.URL = s.srv.URL
	return s
}

// NewTLS is New over https with the test server's own certificate (Certificate, for a ca_file).
func NewTLS(states map[string]string) *Server {
	s := &Server{states: map[string]string{}, stop: make(chan struct{}), now: time.Now}
	for k, v := range states {
		s.states[k] = v
	}
	s.srv = httptest.NewUnstartedServer(s)
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // a client that refuses the certificate is part of the tests
	s.srv.StartTLS()
	s.URL = s.srv.URL
	return s
}

// CertificateDER is the certificate of a NewTLS server.
func (s *Server) CertificateDER() []byte { return s.srv.Certificate().Raw }

// Close ends the server and every request that hangs.
func (s *Server) Close() {
	s.mu.Lock()
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	s.mu.Unlock()
	s.srv.CloseClientConnections()
	s.srv.Close()
}

// SetSensor gives the fake a sensor with a value and a unit ("95.5", "W"), for the meter of a plug.
func (s *Server) SetSensor(entity, value, unit string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.units == nil {
		s.units = map[string]string{}
	}
	s.states[entity], s.units[entity] = value, unit
}

// Set gives an entity a state, as if somebody pressed the button on the plug.
func (s *Server) Set(entity, state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[entity] = state
}

// Remove takes an entity away (renamed, device removed): its state then answers 404.
func (s *Server) Remove(entity string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, entity)
}

// State is the entity's state now ("" for an entity the fake does not have).
func (s *Server) State(entity string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apply()
	return s.states[entity]
}

// ChangeAfter makes a switch request change the state d after it was taken, by the clock.
func (s *Server) ChangeAfter(d time.Duration) { s.set(func() { s.settle = settle{after: d} }) }

// ChangeAfterReads makes a switch request change the state with the n-th read of that entity's state after it
// (1: the first read shows it). For tests whose clock is not the wall clock.
func (s *Server) ChangeAfterReads(n int) { s.set(func() { s.settle = settle{reads: n} }) }

// NeverChange makes switch requests be taken (200) and change nothing: a plug that does not follow.
func (s *Server) NeverChange() { s.set(func() { s.settle = settle{never: true} }) }

// AnswerSwitch makes every switch request be answered with this status (401, 404, 500 ...) and switch nothing.
// 0: honest again.
func (s *Server) AnswerSwitch(status int) { s.set(func() { s.answer = status }) }

// AnswerState makes every state read be answered with this status. 0: honest again.
func (s *Server) AnswerState(status int) { s.set(func() { s.getCode = status }) }

// Redirect makes every request be answered with a 307 to this address ("": honest again). A client that
// follows it sends the request, and the token, to that address.
func (s *Server) Redirect(to string) { s.RedirectAs(to, http.StatusTemporaryRedirect) }

// RedirectAs is Redirect with another status: 301, 302 and 303 make a client that follows them ask the new
// address with a GET, 307 and 308 with the request as it was.
func (s *Server) RedirectAs(to string, status int) {
	s.set(func() { s.redirect, s.redirAs = to, status })
}

// HangSwitch makes switch requests get no answer until Close. applied says whether the socket switches all
// the same (the request arrived, the answer was lost) or not.
func (s *Server) HangSwitch(applied bool) { s.set(func() { s.hang, s.lost = true, !applied }) }

// HangState makes state reads get no answer until Close (false: honest again).
func (s *Server) HangState(on bool) { s.set(func() { s.hangGet = on }) }

// SlowState makes state reads be answered only after d (0: at once again).
func (s *Server) SlowState(d time.Duration) { s.set(func() { s.slowGet = d }) }

// CutSwitch makes the connection of a switch request be closed without an answer.
func (s *Server) CutSwitch(applied bool) { s.set(func() { s.cut, s.lost = true, !applied }) }

// LateSwitch makes a switch request be answered (200) only after d.
func (s *Server) LateSwitch(d time.Duration, applied bool) {
	s.set(func() { s.late, s.lost = d, !applied })
}

// IgnoreSwitch makes switch requests be answered 200 with an empty list and change nothing.
func (s *Server) IgnoreSwitch(on bool) { s.set(func() { s.ignore = on }) }

// AnswerAs makes state reads answer with this entity_id in the state object, whatever was asked.
func (s *Server) AnswerAs(entity string) { s.set(func() { s.wrongID = entity }) }

// Honest takes every behaviour back.
func (s *Server) Honest() {
	s.set(func() {
		s.settle, s.answer, s.getCode, s.redirect, s.redirAs = settle{}, 0, 0, "", 0
		s.hang, s.hangGet, s.cut, s.late, s.ignore, s.lost, s.wrongID, s.slowGet = false, false, false, 0, false, false, "", 0
	})
}

func (s *Server) set(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

// Requests are all requests the fake saw, in order.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Forget drops the record of requests.
func (s *Server) Forget() { s.set(func() { s.reqs = nil }) }

// Count is how many requests the fake saw; Posts and Gets are those of one method.
func (s *Server) Count() int { return len(s.Requests()) }

// Posts are the POST requests the fake saw.
func (s *Server) Posts() []Request { return s.of(http.MethodPost) }

// Gets are the GET requests the fake saw.
func (s *Server) Gets() []Request { return s.of(http.MethodGet) }

func (s *Server) of(method string) []Request {
	var out []Request
	for _, r := range s.Requests() {
		if r.Method == method {
			out = append(out, r)
		}
	}
	return out
}

// Problems says what the requests the fake saw should never have been, "" when there is nothing: a path with
// "toggle" in it, a method other than GET and POST, a POST to anything but the two switch services, a POST
// whose body is not exactly {"entity_id": "switch.<id>"}, a GET for anything but the state of one switch or
// one sensor, a GET with a body, and a token used for the other user's work: a switch asked or switched with
// the token that reads the sensors, a sensor asked with the token for switching.
func (s *Server) Problems() string {
	var bad []string
	for _, r := range s.Requests() {
		path, _, _ := strings.Cut(r.Path, "?")
		switch {
		case strings.Contains(strings.ToLower(r.Path), "toggle"):
			bad = append(bad, "toggle: "+r.Method+" "+r.Path)
		case r.Method == http.MethodGet:
			if !(strings.HasPrefix(path, "/api/states/switch.") || strings.HasPrefix(path, "/api/states/sensor.")) || path != r.Path || r.Body != "" || strings.Count(path, "/") != 3 {
				bad = append(bad, "a GET that is not the state of one switch or sensor: "+r.Path)
			}
			if strings.HasPrefix(path, "/api/states/switch.") && r.ReadToken {
				bad = append(bad, "the state of a switch asked with the token that reads the sensors: "+r.Path)
			}
			if strings.HasPrefix(path, "/api/states/sensor.") && r.TokenOK {
				bad = append(bad, "a sensor asked with the token for switching: "+r.Path)
			}
		case r.Method == http.MethodPost:
			var b map[string]any
			_ = json.Unmarshal([]byte(r.Body), &b)
			id, _ := b["entity_id"].(string)
			if (r.Path != "/api/services/switch/turn_on" && r.Path != "/api/services/switch/turn_off") || len(b) != 1 || !strings.HasPrefix(id, "switch.") {
				bad = append(bad, "a POST that is not one switch turned on or off: "+r.Path+" "+r.Body)
			}
			if r.ReadToken {
				bad = append(bad, "a switch request with the token that reads the sensors: "+r.Path)
			}
		default:
			bad = append(bad, "a method that is never used: "+r.Method+" "+r.Path)
		}
	}
	return strings.Join(bad, "; ")
}

// apply makes the changes whose time has come. Caller holds s.mu.
func (s *Server) apply() {
	keep := s.pending[:0]
	for _, p := range s.pending {
		if !p.at.IsZero() && !s.now().Before(p.at) {
			if _, has := s.states[p.entity]; has {
				s.states[p.entity] = p.to
			}
			continue
		}
		keep = append(keep, p)
	}
	s.pending = keep
}

// read counts one state read of entity and makes the changes that were waiting for it. Caller holds s.mu.
func (s *Server) read(entity string) {
	keep := s.pending[:0]
	for _, p := range s.pending {
		if p.at.IsZero() && p.entity == entity {
			if p.reads--; p.reads <= 0 {
				if _, has := s.states[p.entity]; has {
					s.states[p.entity] = p.to
				}
				continue
			}
		}
		keep = append(keep, p)
	}
	s.pending = keep
}

// take is a switch request that arrived: the entity changes now or later, as settle says. It returns the
// entities that changed at once. Caller holds s.mu.
func (s *Server) take(entity, to string) []string {
	st, has := s.states[entity]
	if !has || (st != "on" && st != "off") { // not available: Home Assistant leaves it out, and still answers 200
		return nil
	}
	switch {
	case s.settle.never:
		return nil
	case s.settle.reads > 0:
		s.pending = append(s.pending, pending{entity: entity, to: to, reads: s.settle.reads})
		return nil
	case s.settle.after > 0:
		s.pending = append(s.pending, pending{entity: entity, to: to, at: s.now().Add(s.settle.after)})
		return nil
	}
	if st == to {
		return nil
	}
	s.states[entity] = to
	return []string{entity}
}

func stateObject(entity, state, unit string) map[string]any {
	attrs := map[string]any{"friendly_name": "Socket " + strings.TrimPrefix(entity, "switch.")}
	if unit != "" {
		attrs = map[string]any{"friendly_name": entity, "unit_of_measurement": unit, "state_class": "measurement"}
	}
	return map[string]any{"entity_id": entity, "state": state,
		"attributes":   attrs,
		"last_changed": "2026-11-15T12:00:00.000000+00:00", "last_updated": "2026-11-15T12:00:00.000000+00:00",
		"context": map[string]any{"id": "ctx-1", "parent_id": nil, "user_id": nil}}
}

func (s *Server) wait(r *http.Request, d time.Duration) {
	var t <-chan time.Time
	if d > 0 {
		timer := time.NewTimer(d)
		defer timer.Stop()
		t = timer.C
	}
	select {
	case <-s.stop:
	case <-r.Context().Done():
	case <-t:
	}
}

// ServeHTTP answers as a Home Assistant does: 401 without the token, 404 for a path or an entity it does not
// have, 405 for another method on a path it has.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	auth := r.Header.Get("Authorization")
	ok, read := auth == "Bearer "+Token(), auth == "Bearer "+ReadToken()
	s.mu.Lock()
	s.reqs = append(s.reqs, Request{Method: r.Method, Path: r.URL.RequestURI(), Body: string(body), TokenOK: ok, ReadToken: read, Auth: auth})
	s.apply()
	redirect, redirAs := s.redirect, s.redirAs
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !ok && !read {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "401: Unauthorized")
		return
	}
	if redirect != "" {
		http.Redirect(w, r, redirect+r.URL.RequestURI(), redirAs)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/states/"):
		s.serveState(w, r)
	case r.URL.Path == "/api/services/switch/turn_on" || r.URL.Path == "/api/services/switch/turn_off":
		s.serveSwitch(w, r, body)
	case strings.HasPrefix(r.URL.Path, "/api/services/"):
		// a service the fake does not have (switch/toggle among them): nothing happens, and the request is on record
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"message":"Service not found."}`)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	entity := strings.TrimPrefix(r.URL.Path, "/api/states/")
	s.mu.Lock()
	s.read(entity)
	state, has := s.states[entity]
	unit := s.units[entity]
	code, hang, as, slow := s.getCode, s.hangGet, s.wrongID, s.slowGet
	s.mu.Unlock()
	if slow > 0 {
		s.wait(r, slow)
		s.mu.Lock()
		state, has = s.states[entity] // as it is when the answer is written
		s.mu.Unlock()
	}
	switch {
	case hang:
		s.wait(r, 0)
		return
	case code != 0:
		w.WriteHeader(code)
		_, _ = io.WriteString(w, `{"message":"made up"}`)
		return
	case !has:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"Entity not found."}`)
		return
	}
	if as != "" {
		entity = as
	}
	_ = json.NewEncoder(w).Encode(stateObject(entity, state, unit))
}

func (s *Server) serveSwitch(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var b struct {
		EntityID string `json:"entity_id"`
	}
	if json.Unmarshal(body, &b) != nil || b.EntityID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"message":"Data should be valid JSON."}`)
		return
	}
	to := "off"
	if strings.HasSuffix(r.URL.Path, "/turn_on") {
		to = "on"
	}
	s.mu.Lock()
	answer, hang, cut, late, ignore, lost := s.answer, s.hang, s.cut, s.late, s.ignore, s.lost
	var changed []string
	if answer == 0 && !ignore && !((hang || cut || late > 0) && lost) {
		changed = s.take(b.EntityID, to)
	}
	s.mu.Unlock()
	switch {
	case answer != 0:
		w.WriteHeader(answer)
		_, _ = io.WriteString(w, `{"message":"made up"}`)
		return
	case hang:
		s.wait(r, 0)
		return
	case cut:
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				c.Close()
			}
		}
		return
	case late > 0:
		s.wait(r, late)
	}
	list := []map[string]any{}
	for _, e := range changed {
		list = append(list, stateObject(e, to, ""))
	}
	_ = json.NewEncoder(w).Encode(list)
}
