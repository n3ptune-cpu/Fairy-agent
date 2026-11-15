package agent

import (
	"errors"
	"fmt"
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
