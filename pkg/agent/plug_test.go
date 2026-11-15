package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/plugs/hatest"
)

// POST /plug/switch and the challenge for it (PLUGS-DESIGN.md 3.4 to 3.6, 3.10; the test plan's table 7.2).
// The fake Home Assistant records every request: "nothing was asked of it" is counted, not assumed.

// the sockets of agenttest.PlugConfig as a switch request names them
type sockRef struct{ source, socket, name, entity string }

var (
	sockCh1    = sockRef{agenttest.PlugBar, "ch1", "Left monitor", agenttest.PlugBar1}
	sockCh2    = sockRef{agenttest.PlugBar, "ch2", "ch2", agenttest.PlugBar2}
	sockCh3    = sockRef{agenttest.PlugBar, "ch3", "Lamp", agenttest.PlugBar3}                      // in no list
	sockCorner = sockRef{agenttest.PlugCorner, "main", "Server corner", agenttest.PlugCornerSw}     // feeds_self
	sockOwn    = sockRef{agenttest.PlugOwn, "main", "This machine", agenttest.PlugOwnSw}            // system_hint: self
	sockGone   = sockRef{agenttest.PlugBar, "ch9", "No such socket", "switch.desk_bar_no_such_one"} // not in the config
)

func (s sockRef) tag() string { return api.SocketTag(s.source, s.socket, s.name, s.entity) }

// body is the request for this socket as the panel sends it: the four members of the request text.
func (s sockRef) body(to string) map[string]any {
	return map[string]any{"source": s.source, "socket": s.socket, "to": to, "tag": s.tag()}
}

type answer struct {
	status int
	hdr    map[string][]string
	body   map[string]any
	raw    string
}

func (a answer) code() string { c, _ := a.body["code"].(string); return c }
func (a answer) String() string {
	return strconv.Itoa(a.status) + " " + a.raw
}

func (r *plugRig) post(t *testing.T, path string, body any) answer {
	t.Helper()
	st, hdr, raw := r.call(t, "POST", path, ctlTok, body)
	a := answer{status: st, hdr: hdr, raw: raw, body: map[string]any{}}
	_ = json.Unmarshal([]byte(raw), &a.body)
	return a
}

// challenge asks the machine for a challenge for one switch.
func (r *plugRig) challenge(t *testing.T, s sockRef, to string) answer {
	t.Helper()
	body := s.body(to)
	body["verb"] = api.ApproveSocketSet
	return r.post(t, api.PathApprovalChallenge, body)
}

// entry is the entry of an approval for one switch: the machine's challenge for exactly that request.
func (r *plugRig) entry(t *testing.T, s sockRef, to string) api.MachineEntry {
	t.Helper()
	c := r.challenge(t, s, to)
	if c.status != 200 || c.body["needed"] != true {
		t.Fatalf("challenge for %s/%s %s: %s", s.source, s.socket, to, c)
	}
	want, _ := api.SocketSetRequest(s.source, s.socket, to, s.tag()).Canonical()
	if c.body["request"] != want || c.body["expires_in_s"] != float64(180) || c.body["issuer"] != r.iss.URL {
		t.Fatalf("challenge answer: %s", c)
	}
	return api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: c.body["challenge"].(string), Request: want}
}

// approve is a good approval of one switch: the challenge, then the made-up Pocket ID's token for it alone.
func (r *plugRig) approve(t *testing.T, s sockRef, to string) *api.Approval {
	t.Helper()
	return r.iss.Approve(time.Now(), r.entry(t, s, to))
}

// flip sends the switch request with an approval (nil: none).
func (r *plugRig) flip(t *testing.T, s sockRef, to string, ap *api.Approval) answer {
	t.Helper()
	body := s.body(to)
	body["requested_by"] = "alex"
	if ap != nil {
		body["approval"] = ap
	}
	return r.post(t, api.PathPlugSwitch, body)
}

func (r *plugRig) asked() []string {
	var out []string
	for _, q := range r.ha.Requests() {
		out = append(out, q.Method+" "+q.Path)
	}
	return out
}

// quiet fails the test when Home Assistant was asked anything since the last Forget.
func (r *plugRig) quiet(t *testing.T, what string) {
	t.Helper()
	if n := r.ha.Count(); n != 0 {
		t.Errorf("%s: Home Assistant was asked %v, want nothing at all", what, r.asked())
	}
}

// captureLog sends slog's default to a buffer for the test.
func captureLog(t *testing.T) *logBuf {
	t.Helper()
	buf := &logBuf{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

// One switch, end to end: challenge, approval, the one request, the state confirmed, the answer, /metrics.
func TestPlugSwitch(t *testing.T) {
	log := captureLog(t)
	r := newPlugRig(t, plugRigOpts{})
	for _, c := range []struct {
		s       sockRef
		to, was string
		path    string
	}{
		{sockCh1, "off", "on", "/api/services/switch/turn_off"},
		{sockCh2, "on", "off", "/api/services/switch/turn_on"},
	} {
		ap := r.approve(t, c.s, c.to)
		r.ha.Forget()
		a := r.flip(t, c.s, c.to, ap)
		if a.status != 200 {
			t.Fatalf("%s %s: %s", c.s.socket, c.to, a)
		}
		want := map[string]any{"source": c.s.source, "socket": c.s.socket, "to": c.to, "was": c.was, "state": c.to, "confirmed": true, "took_ms": float64(500)}
		for k, v := range want {
			if a.body[k] != v {
				t.Errorf("%s %s: answer %s = %v, want %v", c.s.socket, c.to, k, a.body[k], v)
			}
		}
		if len(a.body) != len(want) {
			t.Errorf("the answer has the members %v", a.body)
		}
		if got := r.asked(); !slices.Equal(got, []string{"GET /api/states/" + c.s.entity, "POST " + c.path, "GET /api/states/" + c.s.entity}) {
			t.Errorf("%s %s: Home Assistant was asked %v", c.s.socket, c.to, got)
		}
		if posts := r.ha.Posts(); len(posts) != 1 || posts[0].Body != `{"entity_id":"`+c.s.entity+`"}` || !posts[0].TokenOK {
			t.Errorf("%s %s: %+v", c.s.socket, c.to, posts)
		}
		if r.ha.State(c.s.entity) != c.to || r.ha.Problems() != "" {
			t.Errorf("the socket is %s; %s", r.ha.State(c.s.entity), r.ha.Problems())
		}
		// /metrics shows it at once, without waiting for the reader's next round or the kept answer's 250 ms
		st, _, raw := r.call(t, "GET", "/metrics", readTok, nil)
		var m map[string]any
		_ = json.Unmarshal([]byte(raw), &m)
		list, _ := socketsOf(t, m, c.s.source)
		for _, row := range list {
			if row["id"] == c.s.socket && (st != 200 || row["state"] != c.to) {
				t.Errorf("/metrics right after the switch says %v for %s", row["state"], c.s.socket)
			}
		}
		// used up: the same request again is refused, and nothing is asked of Home Assistant
		r.ha.Forget()
		again := r.flip(t, c.s, c.to, ap)
		if again.status != 403 || again.code() != api.CodeApprovalRefused || !strings.Contains(again.raw, "("+approval.ReasonNoChallenge+")") {
			t.Errorf("the same request a second time: %s", again)
		}
		r.quiet(t, "the same request a second time")
	}
	// the log: the gate's line with whose passkey it was, and the plug's line with what was done
	out := log.String() + r.log.String()
	for _, want := range []string{`msg="plug: switching" source=desk-bar socket=ch1 name="Left monitor" entity=` + agenttest.PlugBar1 + ` to=off was=on`,
		`msg="plug: switched" source=desk-bar socket=ch1 to=off requested_by=alex remote=127.0.0.1 name="Left monitor" entity=` + agenttest.PlugBar1 + ` was=on state=off confirmed=true took_ms=500`,
		`msg="plug: switched" source=desk-bar socket=ch2 to=on`,
		`msg="approval: accepted" result=accepted request="socket_set source=desk-bar socket=ch1 to=off tag=` + sockCh1.tag() + `" sub=` + approvaltest.User,
		`msg="plug: refused" reason=approval_refused source=desk-bar socket=ch1 to=off`} {
		if !strings.Contains(out, want) {
			t.Errorf("the log has no line with %s\n%s", want, out)
		}
	}
	for _, never := range []string{hatest.Token(), hatest.ReadToken(), "Bearer", "Authorization"} {
		if strings.Contains(out, never) {
			t.Errorf("the log holds %q", never)
		}
	}
}

// The request is sent also when the socket shows the wanted state already: Home Assistant's state can be old,
// and the person approved "make it off".
func TestPlugSwitchIsSentWhenTheStateIsThatAlready(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{})
	ap := r.approve(t, sockCh2, "off") // ch2 is off
	r.ha.Forget()
	a := r.flip(t, sockCh2, "off", ap)
	if a.status != 200 || a.body["was"] != "off" || a.body["state"] != "off" || a.body["confirmed"] != true {
		t.Fatalf("%s", a)
	}
	if posts := r.ha.Posts(); len(posts) != 1 || posts[0].Path != "/api/services/switch/turn_off" {
		t.Fatalf("Home Assistant was asked %v", r.asked())
	}
}

// A machine without a passkey check refuses: the challenge and the switch are 409 approval_off, and nothing is
// asked of Home Assistant. On the same machine every other request that needs an approval elsewhere is told
// "needs none" (the difference this route must not inherit).
func TestPlugSwitchOnAMachineWithoutThePasskeyCheck(t *testing.T) {
	log := captureLog(t)
	for name, o := range map[string]plugRigOpts{"no trust file": {trust: "none"}, "an agent without a gate": {noGate: true}} {
		r := newPlugRig(t, o)
		r.ha.Forget()
		for _, to := range []string{"on", "off"} {
			c := r.challenge(t, sockCh1, to)
			if c.status != 409 || c.code() != api.CodeApprovalOff || c.body["challenge"] != nil || c.body["needed"] != nil {
				t.Errorf("%s: challenge for %s: %s", name, to, c)
			}
			madeUp := &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{{MachineID: approvaltest.MachineID,
				Challenge: strings.Repeat("A", 43), Request: "socket_set source=desk-bar socket=ch1 to=" + to + " tag=" + sockCh1.tag()}}}
			for what, ap := range map[string]*api.Approval{"without an approval": nil, "with something as an approval": madeUp} {
				a := r.flip(t, sockCh1, to, ap)
				if a.status != 409 || a.code() != api.CodeApprovalOff {
					t.Errorf("%s: switch to %s %s: %s", name, to, what, a)
				}
			}
		}
		r.quiet(t, name)
		if r.ha.State(agenttest.PlugBar1) != "on" {
			t.Fatalf("%s: the socket was switched", name)
		}
	}
	if !strings.Contains(log.String(), `msg="plug: refused" reason=approval_off source=desk-bar socket=ch1 to=off`) {
		t.Errorf("log:\n%s", log.String())
	}
	// the difference, held on the same machine: a shutdown there needs no approval and is carried out
	r := newPlugRig(t, plugRigOpts{trust: "none"})
	c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60})
	if c.status != 200 || c.body["needed"] != false || c.body["reason"] != "off" {
		t.Errorf("the challenge for a shutdown on a machine without a trust file: %s", c)
	}
	if a := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60}); a.status != 200 || len(r.power.Scheduled) != 1 {
		t.Errorf("a shutdown on a machine without a trust file: %s", a)
	}
	// an agent that checks nothing at all: the route answers a socket's challenge, and nothing else, as before
	bare := newPlugRig(t, plugRigOpts{noGate: true})
	if c := bare.post(t, api.PathApprovalChallenge, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60}); c.status != 404 || c.code() != api.CodeApprovalDisabled {
		t.Errorf("a power challenge on an agent without any check: %s", c)
	}
	if c := bare.post(t, api.PathApprovalChallenge, "not json"); c.status != 404 || c.code() != api.CodeApprovalDisabled {
		t.Errorf("a broken challenge request on an agent without any check: %s", c)
	}
}

// A trust file that cannot be used: 503, nothing asked of Home Assistant.
func TestPlugSwitchWithATrustFileThatCannotBeUsed(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{})
	ap := r.approve(t, sockCh1, "off")
	r.breakTrust(t)
	r.ha.Forget()
	if c := r.challenge(t, sockCh1, "off"); c.status != 503 || c.code() != api.CodeApprovalUnavailable {
		t.Errorf("challenge: %s", c)
	}
	for what, a := range map[string]answer{"with the approval from before": r.flip(t, sockCh1, "off", ap), "without": r.flip(t, sockCh1, "off", nil)} {
		if a.status != 503 || a.code() != api.CodeApprovalUnavailable {
			t.Errorf("%s: %s", what, a)
		}
	}
	r.quiet(t, "a trust file that cannot be used")
}

// No approval in the body: 403 approval_required and no request to Home Assistant at all.
func TestPlugSwitchWithoutAnApproval(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{})
	r.ha.Forget()
	for _, to := range []string{"on", "off"} {
		if a := r.flip(t, sockCh1, to, nil); a.status != 403 || a.code() != api.CodeApprovalRequired {
			t.Errorf("to %s: %s", to, a)
		}
	}
	// an approval right before does not open anything for the next request
	if a := r.flip(t, sockCh1, "off", r.approve(t, sockCh1, "off")); a.status != 200 {
		t.Fatalf("%s", a)
	}
	r.ha.Forget()
	r.clk.add(time.Minute)
	for _, s := range []sockRef{sockCh1, sockCh2} {
		if a := r.flip(t, s, "on", nil); a.status != 403 || a.code() != api.CodeApprovalRequired {
			t.Errorf("%s right after an approved switch: %s", s.socket, a)
		}
	}
	r.quiet(t, "a request without an approval")
}

// An approval that does not hold: 403 approval_refused with the reason, and nothing asked of Home Assistant.
// The design let such a request read the socket's state first; here it does not get that far.
func TestPlugSwitchWithAnApprovalThatDoesNotHold(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{})
	e := r.entry(t, sockCh1, "off")
	good := r.iss.Approve(time.Now(), e)
	stranger := *r.iss
	stranger.Key = approvaltest.Key(1)
	other := *r.iss
	other.Sub = "99999999-2222-4333-8444-555555555555"
	r.ha.Forget()
	for name, c := range map[string]struct {
		s      sockRef
		to     string
		ap     *api.Approval
		reason string
	}{
		"signed with another key":          {sockCh1, "off", stranger.Approve(time.Now(), e), approval.ReasonSignature},
		"a user who may not approve":       {sockCh1, "off", other.Approve(time.Now(), e), approval.ReasonUser},
		"no token":                         {sockCh1, "off", &api.Approval{Entries: []api.MachineEntry{e}}, approval.ReasonFormat},
		"the approval of off, used for on": {sockCh1, "on", good, approval.ReasonNoChallenge},
		"used for another socket":          {sockCh2, "off", good, approval.ReasonNoChallenge},
		"a challenge that was never given": {sockCh1, "off", r.iss.Approve(time.Now(), api.MachineEntry{MachineID: e.MachineID, Challenge: strings.Repeat("B", 42) + "A", Request: e.Request}), approval.ReasonNoChallenge},
		"for another machine": {sockCh1, "off", r.iss.Approve(time.Now(), api.MachineEntry{MachineID: "another-machine-BBBBBBBBBB", Challenge: e.Challenge, Request: e.Request}),
			approval.ReasonNonce},
		"no entries": {sockCh1, "off", &api.Approval{Token: good.Token}, approval.ReasonOneEntry},
	} {
		a := r.flip(t, c.s, c.to, c.ap)
		if a.status != 403 || a.code() != api.CodeApprovalRefused || !strings.Contains(a.raw, "approval refused ("+c.reason+")") {
			t.Errorf("%s: %s", name, a)
		}
	}
	r.quiet(t, "an approval that does not hold")
	// none of it cost the good approval anything
	if a := r.flip(t, sockCh1, "off", good); a.status != 200 || a.body["confirmed"] != true {
		t.Fatalf("the good approval after all of that: %s", a)
	}
}

// One approval is one socket: an approval whose list has two entries switches neither, uses nothing up and
// asks nothing of Home Assistant. Each socket then still works with an approval of its own.
func TestPlugSwitchTakesAnApprovalOfOneEntryOnly(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{})
	e1, e2 := r.entry(t, sockCh1, "off"), r.entry(t, sockCh2, "on")
	both := r.iss.Approve(time.Now(), e1, e2) // one passkey touch for two sockets
	r.ha.Forget()
	for name, c := range map[string]struct {
		s  sockRef
		to string
	}{"the first": {sockCh1, "off"}, "the second": {sockCh2, "on"}} {
		a := r.flip(t, c.s, c.to, both)
		if a.status != 403 || a.code() != api.CodeApprovalRefused || !strings.Contains(a.raw, "approval refused ("+approval.ReasonOneEntry+")") {
			t.Errorf("%s socket with the approval of two: %s", name, a)
		}
	}
	cut := &api.Approval{Token: both.Token, Entries: []api.MachineEntry{e1}} // the list shortened after it was signed
	if a := r.flip(t, sockCh1, "off", cut); a.status != 403 || !strings.Contains(a.raw, "approval refused ("+approval.ReasonNonce+")") {
		t.Errorf("the token for two with a list of one: %s", a)
	}
	r.quiet(t, "an approval of two entries")
	if r.ha.State(agenttest.PlugBar1) != "on" || r.ha.State(agenttest.PlugBar2) != "off" {
		t.Fatal("a socket was switched")
	}
	// the challenges are still open: an approval for each alone is accepted
	if a := r.flip(t, sockCh1, "off", r.iss.Approve(time.Now(), e1)); a.status != 200 {
		t.Errorf("the first socket alone: %s", a)
	}
	if a := r.flip(t, sockCh2, "on", r.iss.Approve(time.Now(), e2)); a.status != 200 {
		t.Errorf("the second socket alone: %s", a)
	}
}

// What this machine's config does not let be switched is refused with its own code, for on and for off, at
// the challenge already and at the switch, and Home Assistant is asked nothing.
func TestPlugSwitchRefusesWhatTheConfigForbids(t *testing.T) {
	log := captureLog(t)
	r := newPlugRig(t, plugRigOpts{})
	good := r.approve(t, sockCh1, "off") // an approval that holds, for another socket
	r.ha.Forget()
	for _, c := range []struct {
		s      sockRef
		status int
		code   string
	}{
		{sockCh3, 403, api.CodeNotAllowed},
		{sockCorner, 403, api.CodeFeedsSelf},
		{sockOwn, 403, api.CodeFeedsSelf}, // in switch_allow, and its meter says system_hint: self
		{sockGone, 404, api.CodeUnknownSocket},
	} {
		for _, to := range []string{"on", "off"} {
			if ch := r.challenge(t, c.s, to); ch.status != c.status || ch.code() != c.code || ch.body["challenge"] != nil {
				t.Errorf("challenge for %s/%s %s: %s", c.s.source, c.s.socket, to, ch)
			}
			for what, ap := range map[string]*api.Approval{"without an approval": nil, "with an approval of another socket": good} {
				a := r.flip(t, c.s, to, ap)
				if a.status != c.status || a.code() != c.code {
					t.Errorf("%s/%s %s %s: %s", c.s.source, c.s.socket, to, what, a)
				}
			}
		}
	}
	r.quiet(t, "sockets the config forbids")
	for _, e := range []string{agenttest.PlugBar3, agenttest.PlugCornerSw, agenttest.PlugOwnSw} {
		if r.ha.State(e) != "on" {
			t.Errorf("%s was switched", e)
		}
	}
	if n := strings.Count(r.log.String(), `msg="approval: challenge issued" request="socket_set`); n != 1 {
		t.Errorf("%d challenges were given, want the one for the socket that may be switched", n)
	}
	for _, want := range []string{`msg="plug: refused" reason=not_allowed source=desk-bar socket=ch3 to=off`, `msg="plug: refused" reason=feeds_self source=server-corner socket=main to=on`,
		`msg="plug: refused" reason=unknown_socket`, `msg="plug: no challenge given" source=server-corner socket=main to=off reason=feeds_self`} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("the log has no line with %s", want)
		}
	}
	// the approval of the allowed socket was not touched by any of it
	if a := r.flip(t, sockCh1, "off", good); a.status != 200 {
		t.Errorf("%s", a)
	}

	// feeds_self wins over switch_allow, and the lists are exact ids: a socket whose id only begins like an
	// allowed one is not allowed
	both := newPlugRig(t, plugRigOpts{PlugOptions: agenttest.PlugOptions{Allow: []string{agenttest.PlugCornerSw, "switch.desk_bar_socket", "switch.desk_bar_socket_11"},
		FeedsSelf: []string{agenttest.PlugCornerSw}}})
	both.ha.Forget()
	if a := both.flip(t, sockCorner, "off", nil); a.status != 403 || a.code() != api.CodeFeedsSelf {
		t.Errorf("a socket in both lists: %s", a)
	}
	if a := both.flip(t, sockCh1, "off", nil); a.status != 403 || a.code() != api.CodeNotAllowed {
		t.Errorf("a socket whose id begins like an allowed one: %s", a)
	}
	both.quiet(t, "both lists")
}

// The tag: a request for a socket as it was described before is refused before anything is used up or asked.
func TestPlugSwitchWithAnotherTag(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{})
	good := r.approve(t, sockCh1, "off")
	r.ha.Forget()
	renamed := sockRef{sockCh1.source, sockCh1.socket, "Server corner", sockCh1.entity} // the same socket id under another name
	rewired := sockRef{sockCh1.source, sockCh1.socket, sockCh1.name, agenttest.PlugCornerSw}
	for name, s := range map[string]sockRef{"another name": renamed, "another switch": rewired, "the tag of another socket": {sockCh1.source, sockCh1.socket, sockCh2.name, sockCh2.entity}} {
		if c := r.challenge(t, s, "off"); c.status != 409 || c.code() != api.CodeSocketChanged {
			t.Errorf("challenge with %s: %s", name, c)
		}
		for what, ap := range map[string]*api.Approval{"without an approval": nil, "with the approval of the right tag": good} {
			if a := r.flip(t, s, "off", ap); a.status != 409 || a.code() != api.CodeSocketChanged {
				t.Errorf("%s, %s: %s", name, what, a)
			}
		}
	}
	r.quiet(t, "a request with another tag")
	if a := r.flip(t, sockCh1, "off", good); a.status != 200 {
		t.Errorf("the approval after it: %s", a)
	}
}

// A socket Home Assistant does not reach is refused after one state read, with no switch request, and the
// approval is whole: the same one works when the socket is back.
func TestPlugSwitchOfASocketWithoutAState(t *testing.T) {
	log := captureLog(t)
	for _, said := range []string{"unavailable", "unknown", "heating"} {
		r := newPlugRig(t, plugRigOpts{})
		ap := r.approve(t, sockCh1, "off")
		r.ha.Set(agenttest.PlugBar1, said)
		r.ha.Forget()
		a := r.flip(t, sockCh1, "off", ap)
		if a.status != 409 || a.code() != api.CodeSocketUnavailable {
			t.Fatalf("Home Assistant says %s: %s", said, a)
		}
		if got := r.asked(); !slices.Equal(got, []string{"GET /api/states/" + agenttest.PlugBar1}) {
			t.Errorf("Home Assistant says %s: it was asked %v, want one state read", said, got)
		}
		r.ha.Set(agenttest.PlugBar1, "on")
		r.ha.Forget()
		if a := r.flip(t, sockCh1, "off", ap); a.status != 200 || a.body["confirmed"] != true || len(r.ha.Posts()) != 1 {
			t.Errorf("the same approval when the socket is back: %s", a)
		}
	}
	if !strings.Contains(log.String(), `msg="plug: refused" reason=socket_unavailable why=unavailable source=desk-bar socket=ch1 to=off`) {
		t.Errorf("log:\n%s", log.String())
	}
}

// Home Assistant cannot be asked for the state: 502 ha_unreachable, nothing sent that changes anything, the
// approval whole. And without a token for switching: 409 no_token, nothing asked at all.
func TestPlugSwitchWhenTheStateCannotBeRead(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{quick: true})
	ap := r.approve(t, sockCh1, "off")
	for name, c := range map[string]struct {
		do  func()
		why string
	}{
		"no answer":          {func() { r.ha.HangState(true) }, "(timeout)"},
		"http 500":           {func() { r.ha.AnswerState(500) }, "(http 500)"},
		"the entity is gone": {func() { r.ha.Remove(agenttest.PlugBar1) }, "(entity not found)"},
	} {
		c.do()
		r.ha.Forget()
		a := r.flip(t, sockCh1, "off", ap)
		if a.status != 502 || a.code() != api.CodeHAUnreachable || !strings.HasSuffix(a.body["error"].(string), c.why) {
			t.Errorf("%s: %s", name, a)
		}
		if len(r.ha.Posts()) != 0 || len(r.ha.Gets()) != 1 {
			t.Errorf("%s: Home Assistant was asked %v", name, r.asked())
		}
		r.ha.Honest()
		r.ha.Set(agenttest.PlugBar1, "on")
	}
	t.Setenv(plugSwitchEnv, "")
	r.ha.Forget()
	a := r.flip(t, sockCh1, "off", ap)
	if a.status != 409 || a.code() != api.CodeNoSwitchToken || strings.Contains(a.raw, plugSwitchEnv) {
		t.Errorf("without a token: %s", a)
	}
	if c := r.challenge(t, sockCh1, "on"); c.status != 409 || c.code() != api.CodeNoSwitchToken {
		t.Errorf("challenge without a token: %s", c)
	}
	r.quiet(t, "without a token for switching") // and the meters' token was not borrowed
	t.Setenv(plugSwitchEnv, hatest.Token())
	if a := r.flip(t, sockCh1, "off", ap); a.status != 200 {
		t.Errorf("the approval after all of that: %s", a)
	}
}

// Home Assistant takes the request (200) and the socket does not follow: the answer is 200 with confirmed
// false, never "switched". When it follows late, confirmed is true.
func TestPlugSwitchIsConfirmedByTheState(t *testing.T) {
	log := captureLog(t)
	r := newPlugRig(t, plugRigOpts{})
	r.ha.IgnoreSwitch(true) // what Home Assistant does for an entity it left out: 200 and nothing
	a := r.flip(t, sockCh1, "off", r.approve(t, sockCh1, "off"))
	if a.status != 200 || a.body["confirmed"] != false || a.body["was"] != "on" || a.body["state"] != "on" || a.body["took_ms"] != float64(9500) {
		t.Fatalf("%s", a)
	}
	if !strings.Contains(log.String(), `msg="plug: not confirmed" source=desk-bar socket=ch1 to=off`) {
		t.Errorf("log:\n%s", log.String())
	}
	r.ha.Honest()
	r.ha.ChangeAfterReads(4) // the fourth look, 3.5 s after the request
	r.clk.add(time.Minute)
	r.ha.Forget()
	a = r.flip(t, sockCh1, "off", r.approve(t, sockCh1, "off"))
	if a.status != 200 || a.body["confirmed"] != true || a.body["state"] != "off" || a.body["took_ms"] != float64(3500) {
		t.Fatalf("%s", a)
	}
	if len(r.ha.Posts()) != 1 || len(r.ha.Gets()) != 5 {
		t.Errorf("Home Assistant was asked %v", r.asked())
	}
}

// The switch request gets no answer. It is never sent again; the approval is spent. 502 no_answer when the
// socket stays as it was, 200 when it shows the new state after all.
func TestPlugSwitchWithoutAnAnswer(t *testing.T) {
	log := captureLog(t)
	r := newPlugRig(t, plugRigOpts{quick: true})
	ap := r.approve(t, sockCh1, "off")
	r.ha.CutSwitch(false)
	r.ha.Forget()
	a := r.flip(t, sockCh1, "off", ap)
	if a.status != 502 || a.code() != api.CodeNoAnswer || !strings.Contains(a.raw, "It may still switch") {
		t.Fatalf("%s", a)
	}
	if len(r.ha.Posts()) != 1 || len(r.ha.Gets()) != 11 {
		t.Errorf("Home Assistant was asked %v", r.asked())
	}
	if !strings.Contains(log.String(), `level=ERROR msg="plug: failed after the approval was used" reason=no_answer`) {
		t.Errorf("log:\n%s", log.String())
	}
	r.ha.Forget()
	if again := r.flip(t, sockCh1, "off", ap); again.status != 403 || again.code() != api.CodeApprovalRefused {
		t.Errorf("the approval of a request that got no answer, used again: %s", again)
	}
	r.quiet(t, "the spent approval")

	r.clk.add(time.Minute)
	r.ha.Honest()
	r.ha.HangSwitch(true) // it arrived, the answer was lost
	ap = r.approve(t, sockCh1, "off")
	r.ha.Forget()
	a = r.flip(t, sockCh1, "off", ap)
	if a.status != 200 || a.body["confirmed"] != true || a.body["state"] != "off" || len(r.ha.Posts()) != 1 {
		t.Fatalf("%s; asked %v", a, r.asked())
	}
}

// Home Assistant refuses the switch request: 502 ha_refused, nothing more is sent, the approval is spent.
// For a refused token the sockets' reader goes into its long wait.
func TestPlugSwitchRefusedByHomeAssistant(t *testing.T) {
	for _, status := range []int{401, 500} {
		r := newPlugRig(t, plugRigOpts{})
		ap := r.approve(t, sockCh1, "off")
		r.ha.AnswerSwitch(status)
		r.ha.Forget()
		a := r.flip(t, sockCh1, "off", ap)
		if a.status != 502 || a.code() != api.CodeHARefused {
			t.Fatalf("http %d: %s", status, a)
		}
		if tokenText := strings.Contains(a.raw, "(home assistant refused the token)"); tokenText != (status == 401) || strings.Contains(a.raw, "made up") {
			t.Errorf("http %d: %s", status, a)
		}
		if got := r.asked(); !slices.Equal(got, []string{"GET /api/states/" + agenttest.PlugBar1, "POST /api/services/switch/turn_off"}) {
			t.Errorf("http %d: Home Assistant was asked %v", status, got)
		}
		r.ha.Honest()
		r.ha.Forget()
		if again := r.flip(t, sockCh1, "off", ap); again.status != 403 || again.code() != api.CodeApprovalRefused {
			t.Errorf("http %d: the approval used again: %s", status, again)
		}
		r.plugs.PollOnce(context.Background())
		if status == 401 {
			r.quiet(t, "after a refused token")
			m, _ := r.metrics(t)
			list, row := socketsOf(t, m, agenttest.PlugBar)
			if said(list[0]) != `ch1 "Left monitor" unknown true - home assistant refused the token` || row["ok"] != true {
				t.Errorf("/metrics after the refusal: %s; the meter's row %v", said(list[0]), row)
			}
		} else if len(r.ha.Gets()) != 5 {
			t.Errorf("http %d: the reader asked %v", status, r.asked())
		}
	}
}

// One socket is not switched again before min_gap_s; the answer says when.
func TestPlugSwitchTooSoon(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{}) // min_gap_s: 5
	if a := r.flip(t, sockCh1, "off", r.approve(t, sockCh1, "off")); a.status != 200 {
		t.Fatalf("%s", a)
	}
	ap := r.approve(t, sockCh1, "on")
	r.ha.Forget()
	a := r.flip(t, sockCh1, "on", ap)
	if a.status != 429 || a.code() != api.CodeTooSoon || a.hdr["Retry-After"] == nil || a.hdr["Retry-After"][0] != "5" || a.body["retry_after_s"] != float64(5) {
		t.Fatalf("%s %v", a, a.hdr["Retry-After"])
	}
	r.quiet(t, "a switch that is too soon")
	if other := r.flip(t, sockCh2, "on", r.approve(t, sockCh2, "on")); other.status != 200 { // another socket has its own gap
		t.Errorf("another socket: %s", other)
	}
	r.clk.add(5 * time.Second)
	if a := r.flip(t, sockCh1, "on", ap); a.status != 200 || a.body["confirmed"] != true { // the approval was not used by the refusal
		t.Errorf("after the gap, with the same approval: %s", a)
	}
}

// One switch at a time on this agent.
func TestPlugSwitchOneAtATime(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{})
	ap1, ap2 := r.approve(t, sockCh1, "off"), r.approve(t, sockCh2, "on")
	r.ha.HangState(true) // the first switch waits for its state read
	r.ha.Forget()
	first := make(chan answer, 1)
	go func() { first <- r.flip(t, sockCh1, "off", ap1) }()
	for i := 0; i < 400 && r.ha.Count() == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	a := r.flip(t, sockCh2, "on", ap2)
	if a.status != 409 || a.code() != api.CodeSwitchInProgress {
		t.Errorf("a second switch while one runs: %s", a)
	}
	if r.ha.Count() != 1 {
		t.Errorf("Home Assistant was asked %v", r.asked())
	}
	r.ha.HangState(false)
	r.ha.Close() // ends the read that hangs
	select {
	case a := <-first:
		if a.status != 502 || a.code() != api.CodeHAUnreachable {
			t.Errorf("the first: %s", a)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the first switch did not end")
	}
}

// What is not a switch request is refused with 400 before anything else: a member the request does not have
// (an entity, an address, a service: none can be named), a member missing, a direction that is neither on nor
// off, ids and tags of another form.
func TestPlugSwitchBadRequests(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{})
	ap := r.approve(t, sockCh1, "off")
	r.ha.Forget()
	with := func(more map[string]any) map[string]any {
		b := sockCh1.body("off")
		b["approval"] = ap
		for k, v := range more {
			if v == nil {
				delete(b, k)
			} else {
				b[k] = v
			}
		}
		return b
	}
	for name, body := range map[string]any{
		"an entity":               with(map[string]any{"entity_id": agenttest.PlugCornerSw}),
		"a switch_entity":         with(map[string]any{"switch_entity": agenttest.PlugCornerSw}),
		"an address":              with(map[string]any{"url": "http://192.0.2.99:8123"}),
		"a service":               with(map[string]any{"service": "toggle"}),
		"a domain":                with(map[string]any{"domain": "lock"}),
		"a token":                 with(map[string]any{"token": "x"}),
		"a verb":                  with(map[string]any{"verb": "socket_set"}),
		"force":                   with(map[string]any{"force": true}),
		"toggle":                  with(map[string]any{"to": "toggle"}),
		"to in capitals":          with(map[string]any{"to": "OFF"}),
		"to as a truth value":     with(map[string]any{"to": false}),
		"to as a number":          with(map[string]any{"to": 0}),
		"no to":                   with(map[string]any{"to": nil}),
		"no source":               with(map[string]any{"source": nil}),
		"no socket":               with(map[string]any{"socket": nil}),
		"no tag":                  with(map[string]any{"tag": nil}),
		"a tag of 21 characters":  with(map[string]any{"tag": sockCh1.tag()[:21]}),
		"a tag of 23 characters":  with(map[string]any{"tag": sockCh1.tag() + "A"}),
		"a source of 41":          with(map[string]any{"source": strings.Repeat("a", 41)}),
		"a socket of 17":          with(map[string]any{"socket": strings.Repeat("a", 17)}),
		"a socket that is a path": with(map[string]any{"socket": "../ch1"}),
		"the entity as socket":    with(map[string]any{"socket": agenttest.PlugBar1}),
		"a list of sockets":       with(map[string]any{"socket": []string{"ch1", "ch2"}}),
		"all sockets":             with(map[string]any{"socket": "*"}),
		"not JSON":                "source=desk-bar&socket=ch1&to=off",
		"a list":                  []any{with(nil), with(nil)},
		"nothing":                 "",
		"a member twice":          `{"source":"desk-bar","socket":"ch1","to":"on","to":"off","tag":"` + sockCh1.tag() + `"}`,
		"a member in capitals":    `{"source":"desk-bar","socket":"ch1","TO":"off","tag":"` + sockCh1.tag() + `"}`,
		"data after the object":   `{"source":"desk-bar","socket":"ch1","to":"off","tag":"` + sockCh1.tag() + `"} {"to":"on"}`,
	} {
		a := r.post(t, api.PathPlugSwitch, body)
		if a.status != 400 || a.body["code"] != nil {
			t.Errorf("%s: %s", name, a)
		}
	}
	r.quiet(t, "requests that are not switch requests")
	if a := r.post(t, api.PathPlugSwitch, with(nil)); a.status != 200 { // the approval was not touched
		t.Errorf("the good request after them: %s", a)
	}
}

// The route as every control route: the control token, POST, and 404 for everybody on an agent whose own
// config does not turn switching on.
func TestPlugSwitchRoute(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{})
	r.ha.Forget()
	body := sockCh1.body("off")
	for name, c := range map[string]struct {
		method, tok string
		status      int
	}{"no token": {"POST", "", 401}, "the read token": {"POST", readTok, 401}, "a wrong token": {"POST", ctlTok + "x", 401}, "GET": {"GET", ctlTok, 405}} {
		if st, _, raw := r.call(t, c.method, api.PathPlugSwitch, c.tok, body); st != c.status {
			t.Errorf("%s: %d %s", name, st, raw)
		}
	}
	for _, path := range []string{"/plug/toggle", "/plug/switch/", "/plug", "/plugs/set", "/plugs/candidates", "/plug/switch/all"} {
		if st, _, raw := r.call(t, "POST", path, ctlTok, body); st != 404 {
			t.Errorf("POST %s: %d %s", path, st, raw)
		}
	}
	r.quiet(t, "requests that are not for the route")

	off := newPlugRig(t, plugRigOpts{off: true})
	off.ha.Forget()
	for name, tok := range map[string]string{"with the control token": ctlTok, "without a token": ""} {
		st, _, raw := off.call(t, "POST", api.PathPlugSwitch, tok, body)
		if st != 404 || !strings.Contains(raw, `"code":"plug_switching_disabled"`) {
			t.Errorf("switching off, %s: %d %s", name, st, raw)
		}
	}
	if c := off.challenge(t, sockCh1, "off"); c.status != 404 || c.code() != api.CodePlugSwitchingDisabled {
		t.Errorf("challenge with switching off: %s", c)
	}
	off.quiet(t, "switching off")

	// the body may be as large as an approval is, and no larger
	if a := r.post(t, api.PathPlugSwitch, map[string]any{"source": "desk-bar", "socket": "ch1", "to": "off", "tag": sockCh1.tag(), "requested_by": strings.Repeat("x", 40<<10)}); a.status != 400 {
		t.Errorf("a body of 40 KiB: %s", a)
	}
}

// Switch requests count in the control budget, refused ones too: nobody fills the log or Home Assistant's
// ear with them. Challenges have their own budget: asking for them does not use up the switches', and the
// other way round.
func TestPlugSwitchCountsInTheControlBudget(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{rate: 3})
	r.ha.Forget()
	var got []int
	for i := 0; i < 4; i++ {
		got = append(got, r.challenge(t, sockCh1, "off").status)
	}
	if !slices.Equal(got, []int{200, 200, 200, 429}) {
		t.Errorf("four challenge requests with a budget of three a minute: %v", got)
	}
	got = nil
	for i := 0; i < 5; i++ {
		got = append(got, r.flip(t, sockCh1, "off", nil).status)
	}
	if !slices.Equal(got, []int{403, 403, 403, 429, 429}) {
		t.Errorf("five switch requests with a budget of three a minute, after the challenges' was used up: %v", got)
	}
	if a := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60}); a.status != 429 { // the same budget as the other control requests
		t.Errorf("a shutdown after three switch requests: %s", a)
	}
	if a := r.post(t, "/power", map[string]any{"action": "cancel"}); a.status == 429 { // the cancel of a shutdown has its own
		t.Errorf("a cancel after three switch requests: %s", a)
	}
	r.quiet(t, "requests over the budget")
}

// The approval is checked again at the last moment, when the state has been read and the request is about to
// be sent, and that check decides: an approval that held at the first look and does not hold any more sends
// nothing. (Here the trust file is damaged while the state read is under way.)
func TestPlugSwitchChecksAgainAtTheLastMoment(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{})
	ap := r.approve(t, sockCh1, "off")
	r.ha.SlowState(700 * time.Millisecond)
	r.ha.Forget()
	done := make(chan answer, 1)
	go func() { done <- r.flip(t, sockCh1, "off", ap) }()
	for i := 0; i < 400 && r.ha.Count() == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if r.ha.Count() != 1 {
		t.Fatal("the state read did not start: the first look refused the approval")
	}
	r.breakTrust(t) // between the first look and the last
	var a answer
	select {
	case a = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the switch did not end")
	}
	if a.status != 503 || a.code() != api.CodeApprovalUnavailable {
		t.Errorf("%s", a)
	}
	if len(r.ha.Posts()) != 0 || r.ha.State(agenttest.PlugBar1) != "on" {
		t.Fatalf("the request was sent: %v", r.asked())
	}
}

// requested_by is for the log, cleaned and cut; it changes nothing else.
func TestPlugSwitchRequestedBy(t *testing.T) {
	log := captureLog(t)
	r := newPlugRig(t, plugRigOpts{})
	body := sockCh1.body("off")
	body["approval"] = r.approve(t, sockCh1, "off")
	body["requested_by"] = "alex\nmsg=\"plug: switched\" source=server-corner " + strings.Repeat("x", 100)
	if a := r.post(t, api.PathPlugSwitch, body); a.status != 200 {
		t.Fatalf("%s", a)
	}
	out := log.String()
	if strings.Count(out, "\n") != strings.Count(out, "level=") || strings.Contains(out, "source=server-corner") || !strings.Contains(out, `requested_by="alexmsgplug switched sourceserver-corner x`) {
		t.Errorf("log:\n%s", out)
	}
}

// fakeChecker is a Windows helper as the agent sees it, for the one question this route asks of it: what it
// says about the trust file at this moment. It counts the challenges it is handed (none, for a socket).
type fakeChecker struct {
	*agenttest.Helper
	state      string // what the helper says about the trust file
	challenges int
}

func (h *fakeChecker) ApprovalStatus(context.Context) (api.ApprovalStatus, bool) {
	return api.ApprovalStatus{State: h.state, EnforcedBy: api.EnforcedByHelper, Proto: api.ApprovalProto}, true
}
func (h *fakeChecker) ApprovalNow(ctx context.Context) (api.ApprovalStatus, bool) {
	return h.ApprovalStatus(ctx)
}
func (h *fakeChecker) Checks(context.Context) (bool, bool) { return true, true }
func (h *fakeChecker) Challenge(context.Context, api.ApprovalRequest) (int, any) {
	h.challenges++
	return 200, api.ChallengeResponse{Needed: false, Reason: "off"}
}
func (h *fakeChecker) TrustInit(context.Context, api.TrustInit) (int, any) { return 500, nil }

// Windows: the trust file is the helper's and the agent's gate only reads it. The agent sends the request to
// Home Assistant itself, so the agent gives the challenge and checks the approval; the helper is not asked.
// /metrics names the request among the ones the agent checks itself. And the one case that lets every other
// request through, "this agent cannot read the trust file and the helper says there is none", is approval_off.
func TestPlugSwitchOnWindows(t *testing.T) {
	readOnly := func(o *approval.Options) { o.ReadOnly = true }
	t.Run("the agent checks with the helper's trust file", func(t *testing.T) {
		h := &fakeChecker{Helper: agenttest.NewHelper(), state: api.ApprovalRequired}
		r := newPlugRig(t, plugRigOpts{helper: h, gateOpt: readOnly, trust: "admin"})
		m, _ := r.metrics(t)
		blk, _ := m["approval"].(map[string]any)
		checks, _ := blk["agent_checks"].([]any)
		if blk["enforced_by"] != api.EnforcedByHelper || !slices.Contains(checks, any(api.ApproveSocketSet)) {
			t.Errorf("the approval block: %v", blk)
		}
		ap := r.approve(t, sockCh1, "off")
		if a := r.flip(t, sockCh1, "off", ap); a.status != 200 || a.body["confirmed"] != true {
			t.Fatalf("%s", a)
		}
		if a := r.flip(t, sockCh1, "off", ap); a.status != 403 || a.code() != api.CodeApprovalRefused {
			t.Errorf("the same approval again: %s", a)
		}
		if h.challenges != 0 {
			t.Errorf("the helper was asked for %d challenges", h.challenges)
		}
	})
	blind := func(o *approval.Options) {
		o.ReadOnly = true
		o.Files.CheckDir = func(string) error { return errors.New("access is denied") }
	}
	t.Run("the agent cannot read the trust file, the helper says there is none", func(t *testing.T) {
		h := &fakeChecker{Helper: agenttest.NewHelper(), state: api.ApprovalOff}
		r := newPlugRig(t, plugRigOpts{helper: h, gateOpt: blind, trust: "none"})
		r.ha.Forget()
		if c := r.challenge(t, sockCh1, "off"); c.status != 409 || c.code() != api.CodeApprovalOff {
			t.Errorf("challenge: %s", c)
		}
		if a := r.flip(t, sockCh1, "off", nil); a.status != 409 || a.code() != api.CodeApprovalOff {
			t.Errorf("switch: %s", a)
		}
		r.quiet(t, "unreadable, and the helper says off")
		m, _ := r.metrics(t)
		list, _ := socketsOf(t, m, agenttest.PlugBar)
		if said(list[0]) != `ch1 "Left monitor" on false approval_off -` {
			t.Errorf("/metrics: %s", said(list[0]))
		}
	})
	t.Run("the agent cannot read the trust file, the helper says there is one", func(t *testing.T) {
		h := &fakeChecker{Helper: agenttest.NewHelper(), state: api.ApprovalRequired}
		r := newPlugRig(t, plugRigOpts{helper: h, gateOpt: blind, trust: "none"})
		r.ha.Forget()
		if c := r.challenge(t, sockCh1, "off"); c.status != 503 || c.code() != api.CodeApprovalUnavailable {
			t.Errorf("challenge: %s", c)
		}
		if a := r.flip(t, sockCh1, "off", nil); a.status != 503 || a.code() != api.CodeApprovalUnavailable {
			t.Errorf("switch: %s", a)
		}
		r.quiet(t, "unreadable, and the helper says required")
		m, _ := r.metrics(t)
		list, _ := socketsOf(t, m, agenttest.PlugBar)
		if said(list[0]) != `ch1 "Left monitor" on false approval_unavailable -` {
			t.Errorf("/metrics: %s", said(list[0]))
		}
	})
}
