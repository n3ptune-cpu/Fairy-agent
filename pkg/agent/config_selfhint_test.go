package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// The lock "this plug feeds this machine": a homeassistant entry with sockets whose system_hint means the
// machine the agent runs on has every socket locked like feeds_self, without being listed there. The hint
// means this machine as the word self, in any letter case and with spaces around it, and as this machine's
// own name. Anything else is taken as another machine, and check-config says so.

// hintConf is a config whose one plug is allowed and in no feeds_self list: only its system_hint can lock it.
func hintConf(hint string) string {
	conf := "home_assistant:\n  url: \"http://192.0.2.10:8123\"\n  token_env: SOCK_SWITCH_TOKEN\n  switching: true\n" +
		"  switch_allow: [switch.own_plug]\n  feeds_self: []\npower_sources:\n" +
		haMeter("own-plug", "http://192.0.2.10:8123", "main=This machine=switch.own_plug")
	if hint != "" {
		conf += fmt.Sprintf("    system_hint: %q\n", hint)
	}
	return conf
}

func TestSystemHintThatMeansThisMachineLocksItsSockets(t *testing.T) {
	old := machineName
	machineName = func() (string, error) { return "Rack-Box.example.org", nil }
	t.Cleanup(func() { machineName = old })
	for hint, locked := range map[string]bool{
		"self": true, "Self": true, "SELF": true, "sElf": true, " self": true, "self ": true, "\tSelf \n": true,
		"rack-box.example.org": true, "Rack-Box.Example.Org": true, "rack-box": true, "RACK-BOX": true, " rack-box ": true,
		"":              false,
		"selfish":       false,
		"my self":       false,
		"other-box":     false,
		"rack":          false,
		"rack-box-2":    false,
		"example.org":   false,
		"rack-box.lan":  false,
		"self.example":  false,
		"rack-box.":     false,
		"-":             false,
		"rack-box self": false,
	} {
		cfg := mustParse(t, hintConf(hint))
		relay, err := cfg.NewRelay()
		if err != nil {
			t.Fatalf("%q: %v", hint, err)
		}
		p, err := cfg.NewPlugs(relay)
		if err != nil || p == nil {
			t.Fatalf("%q: %v", hint, err)
		}
		s, ok := p.Find("own-plug", "main")
		if !ok || !s.Allowed || s.FeedsSelf {
			t.Fatalf("%q: %+v", hint, s)
		}
		want := ""
		if locked {
			want = api.WhyFeedsSelf
		}
		if s.SelfHint != locked || p.Lock(s) != want {
			t.Errorf("system_hint %q: SelfHint %v, Lock %q; want locked %v", hint, s.SelfHint, p.Lock(s), locked)
		}
		// check-config and the start log: the socket's line, and the note for a hint that locks nothing
		rep := cfg.PlugReport(p, api.ApprovalRequired)
		line, note := strings.Join(rep.Lines, "\n"), strings.Join(rep.Notes, "\n")
		const taken = "power source own-plug: its system_hint is neither \"self\" nor this machine's name, so this plug is taken as feeding another machine: its sockets can be switched if allowed."
		switch {
		case locked && (!strings.Contains(line, `socket "own-plug/main" (This machine): switch.own_plug, never switched (`) || rep.Switchable != 0 || strings.Contains(note, "system_hint")):
			t.Errorf("system_hint %q: lines\n%s\nnotes\n%s", hint, line, note)
		case !locked && (!strings.Contains(line, `switch.own_plug, can be switched`) || rep.Switchable != 1):
			t.Errorf("system_hint %q: lines\n%s", hint, line)
		case !locked && strings.Contains(note, taken) != (strings.TrimSpace(hint) != ""):
			t.Errorf("system_hint %q: notes\n%s", hint, note)
		}
		if h := strings.TrimSpace(hint); h != "" && h != "-" && strings.Contains(note, h) && !strings.EqualFold(h, "self") {
			t.Errorf("system_hint %q: the note repeats the hint:\n%s", hint, note)
		}
	}

	// which of the two forms locked is said in the socket's line
	for hint, want := range map[string]string{"Self": "never switched (its power source says system_hint: self)",
		"RACK-BOX": "never switched (the system_hint of its power source is this machine's name)"} {
		cfg := mustParse(t, hintConf(hint))
		relay, _ := cfg.NewRelay()
		p, _ := cfg.NewPlugs(relay)
		if rep := cfg.PlugReport(p, ""); !strings.Contains(strings.Join(rep.Lines, "\n"), want) {
			t.Errorf("system_hint %q: lines %v", hint, rep.Lines)
		}
	}

	// a machine whose name cannot be asked for: only the word locks, and nothing breaks
	machineName = func() (string, error) { return "", errors.New("no name") }
	for hint, locked := range map[string]bool{"Self": true, "rack-box": false, "": false} {
		cfg := mustParse(t, hintConf(hint))
		relay, _ := cfg.NewRelay()
		p, _ := cfg.NewPlugs(relay)
		if s, _ := p.Find("own-plug", "main"); s.SelfHint != locked {
			t.Errorf("without a machine name, system_hint %q: SelfHint %v", hint, s.SelfHint)
		}
	}
}

// hintRawConf is the config of hintConf with the hint as it stands in the file, no quotes added; with
// sockets false the plug has no sockets and the file has no home_assistant block, as a config from before
// sockets.
func hintRawConf(raw string, sockets bool) string {
	if !sockets {
		return "power_sources:\n" + haMeter("own-plug", "http://192.0.2.10:8123") + "    system_hint: " + raw + "\n"
	}
	return "home_assistant:\n  url: \"http://192.0.2.10:8123\"\n  token_env: SOCK_SWITCH_TOKEN\n  switching: true\n" +
		"  switch_allow: [switch.own_plug]\n  feeds_self: []\npower_sources:\n" +
		haMeter("own-plug", "http://192.0.2.10:8123", "main=This machine=switch.own_plug") + "    system_hint: " + raw + "\n"
}

// A system_hint that YAML does not read as a text. On an entry with sockets the hint decides a lock, so it is
// never dropped without a word: a bare number or true/false counts as the text YAML reads it as (a machine
// whose name is digits only locks, quoted or not), and what has no text form (a list, a map, a date) is a
// config problem that names the entry and the key and repeats nothing of the value. An entry without sockets
// loads as it did before sockets were known: such a hint is ignored there, and the row has none.
func TestSystemHintThatIsNotATextInTheFile(t *testing.T) {
	old := machineName
	t.Cleanup(func() { machineName = old })
	const taken = "power source own-plug: its system_hint is neither \"self\" nor this machine's name, so this plug is taken as feeding another machine: its sockets can be switched if allowed."
	for _, c := range []struct {
		machine, raw, text string
		locked             bool
	}{
		{"123", "123", "123", true},
		{"123", `"123"`, "123", true},
		{"123.example.org", "123", "123", true},
		{"rack-box", "123", "123", false},
		{"rack-box", `"123"`, "123", false},
		{"true", "true", "true", true},
		{"true", `"true"`, "true", true},
		{"rack-box", "true", "true", false}, // true is not the word self
		{"rack-box", "false", "false", false},
		{"rack-box", "-5", "-5", false},
		{"1.5", "1.5", "1.5", true},
		{"rack-box", "1.5", "1.5", false},
		{"7", "007", "7", true}, // a number is the number YAML reads: 007 is 7
		{"007", "007", "7", false},
		{"007", `"007"`, "007", true},
	} {
		machineName = func() (string, error) { return c.machine, nil }
		what := fmt.Sprintf("system_hint: %s on the machine %s", c.raw, c.machine)
		cfg := mustParse(t, hintRawConf(c.raw, true))
		relay, err := cfg.NewRelay()
		if err != nil {
			t.Errorf("%s: %v", what, err)
			continue
		}
		if ss := relay.SocketSources(); len(ss) != 1 || ss[0].Hint != c.text {
			t.Errorf("%s: the relay hands on %+v, want the hint %q", what, ss, c.text)
		}
		p, err := cfg.NewPlugs(relay)
		if err != nil || p == nil {
			t.Fatalf("%s: %v", what, err)
		}
		s, _ := p.Find("own-plug", "main")
		want := ""
		if c.locked {
			want = api.WhyFeedsSelf
		}
		if s.SelfHint != c.locked || p.Lock(s) != want {
			t.Errorf("%s: SelfHint %v, Lock %q; want locked %v", what, s.SelfHint, p.Lock(s), c.locked)
		}
		rep := cfg.PlugReport(p, api.ApprovalRequired)
		line, note := strings.Join(rep.Lines, "\n"), strings.Join(rep.Notes, "\n")
		if c.locked && (!strings.Contains(line, "switch.own_plug, never switched (the system_hint of its power source is this machine's name)") || strings.Contains(note, "system_hint")) {
			t.Errorf("%s: lines\n%s\nnotes\n%s", what, line, note)
		}
		if !c.locked && (!strings.Contains(line, "switch.own_plug, can be switched") || !strings.Contains(note, taken)) { // never silent
			t.Errorf("%s: lines\n%s\nnotes\n%s", what, line, note)
		}
	}

	// no value at all is no hint: nothing locks, and nothing is said
	machineName = func() (string, error) { return "rack-box", nil }
	for _, raw := range []string{"", "~", "null", `""`} {
		cfg := mustParse(t, hintRawConf(raw, true))
		relay, err := cfg.NewRelay()
		if err != nil {
			t.Fatalf("system_hint: %s: %v", raw, err)
		}
		p, _ := cfg.NewPlugs(relay)
		rep := cfg.PlugReport(p, api.ApprovalRequired)
		if s, _ := p.Find("own-plug", "main"); s.SelfHint || relay.SocketSources()[0].Hint != "" || strings.Contains(strings.Join(rep.Notes, "\n"), "system_hint") {
			t.Errorf("system_hint: %s: SelfHint %v, hint %q, notes %v", raw, s.SelfHint, relay.SocketSources()[0].Hint, rep.Notes)
		}
	}

	// what has no text form does not load on an entry with sockets
	for _, raw := range []string{"[self]", "[]", "[rack-box, self]", "{is: self}", "{}", "2026-11-15", "\n      - self"} {
		cfg := mustParse(t, hintRawConf(raw, true))
		_, err := cfg.NewRelay()
		const want = "power source own-plug: system_hint is not a text"
		if err == nil || !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "in quotes") {
			t.Errorf("system_hint: %s on an entry with sockets: %v, want a config problem that begins %q", raw, err, want)
			continue
		}
		for _, part := range []string{"rack-box", "[", "{", "2026", "is: self"} {
			if strings.Contains(err.Error(), part) {
				t.Errorf("system_hint: %s: the config problem repeats the value: %v", raw, err)
			}
		}
	}

	// an entry without sockets: every form loads, as before; only a text is a hint
	for raw, hint := range map[string]string{"123": "", "true": "", "[self]": "", "{is: self}": "", "2026-11-15": "", "1.5": "", "~": "",
		`"123"`: "123", "self": "self", `" Self "`: " Self "} {
		cfg := mustParse(t, hintRawConf(raw, false))
		relay, err := cfg.NewRelay()
		if err != nil {
			t.Errorf("system_hint: %s on an entry without sockets: %v", raw, err)
			continue
		}
		if len(relay.sources) != 1 || relay.sources[0].hint != hint || len(relay.SocketSources()) != 0 {
			t.Errorf("system_hint: %s on an entry without sockets: the hint is %q, want %q", raw, relay.sources[0].hint, hint)
		}
		if p, err := cfg.NewPlugs(relay); err != nil || p != nil {
			t.Errorf("system_hint: %s on an entry without sockets: a keeper of sockets %v, %v", raw, p, err)
		}
	}
}

// The row of a plug without sockets, as the panel gets it: a system_hint that is a text is in it as written,
// one that is not a text is left out, as in every version before sockets.
func TestRelayRowOfAHintThatIsNotAText(t *testing.T) {
	plug := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"apower": 95.5, "voltage": 229.8, "current": 0.41, "aenergy": map[string]any{"total": 12000.0}})
	}))
	defer plug.Close()
	for raw, want := range map[string]any{"123": nil, "true": nil, "[self]": nil, "{is: self}": nil, `"123"`: "123", "self": "self"} {
		cfg := mustParse(t, fmt.Sprintf("power_sources:\n  - {id: desk-plug, type: shelly, url: %q, gen: \"2\", system_hint: %s}\n", plug.URL, raw))
		relay, err := cfg.NewRelay()
		if err != nil {
			t.Errorf("system_hint: %s: %v", raw, err)
			continue
		}
		relay.PollOnce(context.Background())
		ps, _ := relay.Rows()
		if len(ps) != 1 || ps[0]["ok"] != true || ps[0]["watts"] != 95.5 || ps[0]["system_hint"] != want {
			t.Errorf("system_hint: %s: the row is %v, want system_hint %v", raw, ps, want)
		}
	}
}
