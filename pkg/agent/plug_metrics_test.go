package agent_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/plugs/hatest"
)

// The "sockets" of a power source's row in GET /metrics (PLUGS-DESIGN.md 3.8).

// said is a socket's row as one line: id name state switchable why error.
func said(s map[string]any) string {
	opt := func(v any) string {
		if v == nil {
			return "-"
		}
		return fmt.Sprint(v)
	}
	return fmt.Sprintf("%v %q %v %v %s %s", s["id"], s["name"], s["state"], s["switchable"], opt(s["why"]), opt(s["error"]))
}

func allSaid(t *testing.T, m map[string]any) string {
	t.Helper()
	var out []string
	for _, src := range []string{agenttest.PlugBar, agenttest.PlugCorner, agenttest.PlugOwn} {
		list, _ := socketsOf(t, m, src)
		for _, s := range list {
			out = append(out, src+"/"+said(s))
		}
	}
	return strings.Join(out, "\n")
}

func TestMetricsSockets(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{})
	m, body := r.metrics(t)
	want := `desk-bar/ch1 "Left monitor" on true - -
desk-bar/ch2 "ch2" off true - -
desk-bar/ch3 "Lamp" on false not_allowed -
server-corner/main "Server corner" on false feeds_self -
own-plug/main "This machine" on false feeds_self -`
	if got := allSaid(t, m); got != want {
		t.Errorf("sockets:\n%s\nwant:\n%s", got, want)
	}
	if f := m["features"].(map[string]any); f[api.FeaturePlugSwitching] != true {
		t.Errorf("features: %v", f)
	}
	// each socket has exactly these members, a tag that is the tag of its config, and no entity id
	list, row := socketsOf(t, m, agenttest.PlugBar)
	for _, s := range list {
		if len(s) != 7 {
			t.Errorf("a socket's row has the members %v", s)
		}
		for _, k := range []string{"id", "name", "state", "switchable", "why", "tag", "error"} {
			if _, has := s[k]; !has {
				t.Errorf("a socket's row has no %q", k)
			}
		}
	}
	if tag := list[0]["tag"]; tag != api.SocketTag("desk-bar", "ch1", "Left monitor", agenttest.PlugBar1) || api.CheckSocketTag(tag.(string)) != nil {
		t.Errorf("tag of ch1: %v", tag)
	}
	if list[1]["tag"] == list[0]["tag"] || list[1]["tag"] != api.SocketTag("desk-bar", "ch2", "ch2", agenttest.PlugBar2) {
		t.Errorf("tag of ch2: %v", list[1]["tag"])
	}
	for _, never := range []string{"switch.", "entity", hatest.Token(), hatest.ReadToken(), plugSwitchEnv, plugReadEnv, r.ha.URL, "home_assistant"} {
		if strings.Contains(body, never) {
			t.Errorf("/metrics holds %q", never)
		}
	}
	// the row of the meter is what its reading made it
	if row["ok"] != true || row["watts"] != 95.5 || row["type"] != "homeassistant" || row["name"] != "Monitor powerbar" {
		t.Errorf("the row of the powerbar: %v", row)
	}
	if _, own := socketsOf(t, m, agenttest.PlugOwn); own["system_hint"] != "self" || own["ok"] != true {
		t.Errorf("the row of the own plug: %v", own)
	}
	// what Home Assistant was asked: sensors with the token that reads, switches with the block's, GET only
	if p := r.ha.Problems(); p != "" || len(r.ha.Posts()) != 0 || len(r.ha.Gets()) != 8 {
		t.Errorf("%s; %d POSTs, %d GETs (want the three sensors and the five switches)", p, len(r.ha.Posts()), len(r.ha.Gets()))
	}

	// states follow the next read: the button on the plug, a socket Home Assistant lost, one it says nonsense
	// for, an entity that is gone. The meter's row stays ok with its watts whatever its sockets say.
	r.ha.Set(agenttest.PlugBar1, "off")
	r.ha.Set(agenttest.PlugBar2, "unavailable")
	r.ha.Remove(agenttest.PlugBar3)
	r.ha.Set(agenttest.PlugCornerSw, "heating")
	r.poll()
	m, _ = r.metrics(t)
	want = `desk-bar/ch1 "Left monitor" off true - -
desk-bar/ch2 "ch2" unavailable true - -
desk-bar/ch3 "Lamp" unknown false not_allowed entity not found
server-corner/main "Server corner" unknown false feeds_self -
own-plug/main "This machine" on false feeds_self -`
	if got := allSaid(t, m); got != want {
		t.Errorf("sockets:\n%s\nwant:\n%s", got, want)
	}
	if _, row := socketsOf(t, m, agenttest.PlugBar); row["ok"] != true || row["watts"] != 95.5 || row["error"] != nil {
		t.Errorf("the row of the powerbar with a socket that failed: %v", row)
	}
	// Home Assistant is gone altogether: the meters fail by themselves, every socket says why
	r.ha.HangState(true)
	r.poll()
	m, _ = r.metrics(t)
	for _, line := range strings.Split(allSaid(t, m), "\n") {
		if !strings.Contains(line, " unknown ") || !strings.HasSuffix(line, " timeout") {
			t.Errorf("with a silent Home Assistant: %s", line)
		}
	}
	// the relay's own rows were never changed: the member is added to a copy
	rows, _ := r.relay.Rows()
	for _, row := range rows {
		if _, has := row["sockets"]; has {
			t.Fatalf("the relay's row %v got the sockets", row["id"])
		}
	}
}

// Why a socket cannot be switched, for each reason there is, the first that applies.
func TestMetricsSocketsWhy(t *testing.T) {
	bar := func(t *testing.T, r *plugRig) string {
		t.Helper()
		m, _ := r.metrics(t)
		return allSaid(t, m)
	}
	t.Run("switching off", func(t *testing.T) {
		r := newPlugRig(t, plugRigOpts{off: true})
		m, _ := r.metrics(t)
		for _, line := range strings.Split(allSaid(t, m), "\n") {
			if !strings.HasSuffix(line, " false switching_off -") || strings.Contains(line, "unknown") {
				t.Errorf("%s", line)
			}
		}
		if f := m["features"].(map[string]any); f[api.FeaturePlugSwitching] != false {
			t.Errorf("features: %v", f)
		}
	})
	t.Run("no trust file", func(t *testing.T) {
		r := newPlugRig(t, plugRigOpts{trust: "none"})
		want := `desk-bar/ch1 "Left monitor" on false approval_off -
desk-bar/ch2 "ch2" off false approval_off -
desk-bar/ch3 "Lamp" on false not_allowed -
server-corner/main "Server corner" on false feeds_self -
own-plug/main "This machine" on false feeds_self -`
		if got := bar(t, r); got != want {
			t.Errorf("sockets:\n%s\nwant:\n%s", got, want)
		}
	})
	t.Run("an agent without a gate", func(t *testing.T) {
		r := newPlugRig(t, plugRigOpts{noGate: true})
		if got := bar(t, r); strings.Count(got, " false approval_off -") != 2 || strings.Contains(got, " true ") {
			t.Errorf("sockets:\n%s", got)
		}
	})
	t.Run("a trust file that cannot be used", func(t *testing.T) {
		r := newPlugRig(t, plugRigOpts{trust: "broken"})
		if got := bar(t, r); strings.Count(got, " false approval_unavailable -") != 2 || strings.Contains(got, " true ") {
			t.Errorf("sockets:\n%s", got)
		}
	})
	t.Run("no token for switching", func(t *testing.T) {
		r := newPlugRig(t, plugRigOpts{})
		t.Setenv(plugSwitchEnv, "")
		r.ha.Forget()
		r.poll()
		got := bar(t, r)
		noTok := "the variable " + plugSwitchEnv + " holds no token for Home Assistant (fairy-agent secret set " + plugSwitchEnv + ", then restart the agent)"
		want := `desk-bar/ch1 "Left monitor" unknown false no_token ` + noTok + `
desk-bar/ch2 "ch2" unknown false no_token ` + noTok + `
desk-bar/ch3 "Lamp" unknown false not_allowed ` + noTok + `
server-corner/main "Server corner" unknown false feeds_self ` + noTok + `
own-plug/main "This machine" unknown false feeds_self ` + noTok
		if got != want {
			t.Errorf("sockets:\n%s\nwant:\n%s", got, want)
		}
		// the meters go on reading with their own token, and no switch was asked about with it
		m, _ := r.metrics(t)
		if _, row := socketsOf(t, m, agenttest.PlugBar); row["ok"] != true || row["watts"] != 95.5 {
			t.Errorf("the meter without the switching token: %v", row)
		}
		for _, q := range r.ha.Requests() {
			if !q.ReadToken || !strings.HasPrefix(q.Path, "/api/states/sensor.") {
				t.Errorf("without the switching token Home Assistant was asked %s %s", q.Method, q.Path)
			}
		}
	})
	// a value that is never sent as a token (a space, a line break, a letter that is not ASCII in it) is no
	// token: nothing says "can be switched", no challenge is given, and the value is in no answer
	t.Run("a value in the variable that cannot be a token", func(t *testing.T) {
		for _, tok := range []string{"two words", "tökén-of-the-tests", hatest.Token() + "\n", " " + hatest.Token()} {
			r := newPlugRig(t, plugRigOpts{})
			t.Setenv(plugSwitchEnv, tok)
			r.ha.Forget()
			r.poll()
			m, raw := r.metrics(t)
			bad := "the variable " + plugSwitchEnv + " holds a value that cannot be a token for Home Assistant (fairy-agent secret set " + plugSwitchEnv + ", then restart the agent)"
			want := `desk-bar/ch1 "Left monitor" unknown false no_token ` + bad + `
desk-bar/ch2 "ch2" unknown false no_token ` + bad + `
desk-bar/ch3 "Lamp" unknown false not_allowed ` + bad + `
server-corner/main "Server corner" unknown false feeds_self ` + bad + `
own-plug/main "This machine" unknown false feeds_self ` + bad
			if got := allSaid(t, m); got != want {
				t.Errorf("%q in the variable: sockets:\n%s\nwant:\n%s", tok, got, want)
			}
			if strings.Contains(raw, strings.TrimSpace(tok)) {
				t.Errorf("%q in the variable: /metrics repeats it", tok)
			}
			for _, to := range []string{"on", "off"} {
				c := r.challenge(t, sockCh1, to)
				if c.status != 409 || c.code() != api.CodeNoSwitchToken || c.body["challenge"] != nil || strings.Contains(c.raw, plugSwitchEnv) || strings.Contains(c.raw, strings.TrimSpace(tok)) {
					t.Errorf("%q in the variable: challenge for %s: %s", tok, to, c)
				}
				if a := r.flip(t, sockCh1, to, nil); a.status != 409 || a.code() != api.CodeNoSwitchToken || strings.Contains(a.raw, strings.TrimSpace(tok)) {
					t.Errorf("%q in the variable: switch to %s: %s", tok, to, a)
				}
			}
			for _, q := range r.ha.Requests() {
				if !q.ReadToken || !strings.HasPrefix(q.Path, "/api/states/sensor.") {
					t.Errorf("%q in the variable: Home Assistant was asked %s %s", tok, q.Method, q.Path)
				}
			}
		}
	})
	t.Run("the meters' token is gone, the switching token is there", func(t *testing.T) {
		r := newPlugRig(t, plugRigOpts{})
		t.Setenv(plugReadEnv, "")
		r.ha.Forget()
		r.poll()
		m, _ := r.metrics(t)
		list, row := socketsOf(t, m, agenttest.PlugBar)
		if row["ok"] != false || said(list[0]) != `ch1 "Left monitor" on true - -` {
			t.Errorf("row %v, socket %s", row, said(list[0]))
		}
		for _, q := range r.ha.Requests() { // the meters did not borrow the block's token
			if !q.TokenOK || !strings.HasPrefix(q.Path, "/api/states/switch.") {
				t.Errorf("without the meters' token Home Assistant was asked %s %s", q.Method, q.Path)
			}
		}
	})
}

// An agent without the block answers as it always did: no row has "sockets", and nothing is asked about a
// switch. The one new thing is the member of "features", which says false.
func TestMetricsWithoutTheBlock(t *testing.T) {
	r := newPlugRig(t, plugRigOpts{PlugOptions: agenttest.PlugOptions{NoBlock: true}})
	if r.plugs != nil {
		t.Fatal("an agent without the block keeps sockets")
	}
	m, body := r.metrics(t)
	for _, src := range []string{agenttest.PlugBar, agenttest.PlugCorner, agenttest.PlugOwn} {
		list, row := socketsOf(t, m, src)
		if list != nil || row["ok"] != true || len(row) != 10 {
			t.Errorf("%s: %v", src, row)
		}
	}
	if strings.Contains(body, `"sockets"`) {
		t.Error("/metrics names sockets")
	}
	if f := m["features"].(map[string]any); f[api.FeaturePlugSwitching] != false {
		t.Errorf("features: %v", f)
	}
	for _, q := range r.ha.Requests() {
		if strings.Contains(q.Path, "switch") {
			t.Errorf("asked %s", q.Path)
		}
	}
}
