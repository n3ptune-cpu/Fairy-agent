package agent

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// The checks of `sockets:` that need the whole file (PLUGS-DESIGN.md 3.2, cross checks 1 and 2, and "one
// entity id is used by at most one socket in the whole file").

// haMeter is a homeassistant entry with sockets given as "id=switch.entity" (or "id=Name=switch.entity").
func haMeter(id, url string, sockets ...string) string {
	out := fmt.Sprintf("  - id: %s\n    type: homeassistant\n    url: %q\n    token_env: SOCK_READ_TOKEN\n    entity: sensor.%s_power\n",
		id, url, strings.ReplaceAll(id, "-", "_"))
	if len(sockets) > 0 {
		out += "    sockets:\n"
	}
	for _, s := range sockets {
		parts := strings.Split(s, "=")
		if len(parts) == 3 {
			out += fmt.Sprintf("      - {id: %s, name: %q, switch_entity: %s}\n", parts[0], parts[1], parts[2])
		} else {
			out += fmt.Sprintf("      - {id: %s, switch_entity: %s}\n", parts[0], parts[1])
		}
	}
	return out
}

func socketRelay(t *testing.T, conf string) (*Relay, error) {
	t.Helper()
	cfg, err := Parse([]byte(conf), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.NewRelay()
}

func TestSocketsNeedTheBlockAndItsAddress(t *testing.T) {
	const needs = ": sockets need the home_assistant block, and the entry's url must be the same address as home_assistant.url"
	block := func(url string) string {
		return "home_assistant:\n  url: \"" + url + "\"\n  token_env: SOCK_SWITCH_TOKEN\n"
	}
	bar := func(url string) string {
		return "power_sources:\n" + haMeter("desk-bar", url, "ch1=switch.desk_bar_socket_1", "ch2=switch.desk_bar_socket_2")
	}
	for name, c := range map[string]struct{ conf, want string }{
		"no block":            {bar("http://192.0.2.10:8123"), "power source desk-bar" + needs},
		"an empty block":      {"home_assistant: {}\n" + bar("http://192.0.2.10:8123"), "power source desk-bar" + needs},
		"another host":        {block("http://192.0.2.99:8123") + bar("http://192.0.2.10:8123"), "power source desk-bar" + needs},
		"another port":        {block("http://192.0.2.10:8124") + bar("http://192.0.2.10:8123"), "power source desk-bar" + needs},
		"the port left out":   {block("http://192.0.2.10") + bar("http://192.0.2.10:80"), "power source desk-bar" + needs},
		"another scheme":      {block("https://ha.example:8123") + bar("http://ha.example:8123"), "power source desk-bar" + needs},
		"a host that is part": {block("http://ha.example.org:8123") + bar("http://ha.example:8123"), "power source desk-bar" + needs},
		"the second entry elsewhere": {block("http://192.0.2.10:8123") + bar("http://192.0.2.10:8123") + haMeter("lab-plug", "http://192.0.2.20:8123", "main=switch.lab_plug"),
			"power source lab-plug" + needs},
		"no token for the sockets": {"home_assistant:\n  url: \"http://192.0.2.10:8123\"\n" + bar("http://192.0.2.10:8123"),
			"power source desk-bar: sockets need home_assistant.token_env: the states of the sockets are read with that token, not with the entry's"},
		"an id of 41 characters": {block("http://192.0.2.10:8123") + "power_sources:\n" + haMeter(strings.Repeat("a", 41), "http://192.0.2.10:8123", "ch1=switch.a"),
			"power source " + strings.Repeat("a", 41) + ": an entry with sockets needs an id of at most 40 characters"},
		"one switch in two entries": {block("http://192.0.2.10:8123") + bar("http://192.0.2.10:8123") + haMeter("lab-plug", "http://192.0.2.10:8123", "main=switch.lab_plug", "aux=switch.desk_bar_socket_2"),
			"power source lab-plug: sockets, item 2: its switch_entity is already the switch of a socket of power source desk-bar; one switch is one socket"},
	} {
		r, err := socketRelay(t, c.conf)
		if err == nil || r != nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("%s: %v\nwant %s", name, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), "192.0.2") || strings.Contains(err.Error(), "switch.") || strings.Contains(err.Error(), "SOCK_") {
			t.Errorf("%s: the problem repeats an address, an entity id or a variable: %v", name, err)
		}
	}
	for name, conf := range map[string]string{
		"the same address":                    block("http://192.0.2.10:8123") + bar("http://192.0.2.10:8123"),
		"with a slash after it":               block("http://192.0.2.10:8123/") + bar("http://192.0.2.10:8123"),
		"the host in other letters":           block("https://HA.example:8443") + bar("https://ha.Example:8443"),
		"an id of 40 characters":              block("http://192.0.2.10:8123") + "power_sources:\n" + haMeter(strings.Repeat("a", 40), "http://192.0.2.10:8123", "ch1=switch.a"),
		"an id of 63 characters, no sockets":  "power_sources:\n" + haMeter(strings.Repeat("a", 63), "http://192.0.2.10:8123"),
		"a meter elsewhere without sockets":   block("http://192.0.2.10:8123") + bar("http://192.0.2.10:8123") + haMeter("lab-plug", "http://192.0.2.20:8123"),
		"the block and no sockets anywhere":   block("http://192.0.2.10:8123") + "power_sources:\n" + haMeter("lab-plug", "http://192.0.2.20:8123"),
		"sockets shown only, the token alone": block("http://192.0.2.10:8123") + bar("http://192.0.2.10:8123"),
	} {
		if _, err := socketRelay(t, conf); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if maxSocketSourceID != 40 || api.MaxSocketSource != 40 || power.MaxHASocketID != api.MaxSocketID {
		t.Errorf("the limits of the ids differ: %d %d %d %d", maxSocketSourceID, api.MaxSocketSource, power.MaxHASocketID, api.MaxSocketID)
	}
}

// The relay hands on which sources have sockets, in config order, with the entry's name and system_hint.
func TestRelaySocketSources(t *testing.T) {
	r, err := socketRelay(t, "home_assistant:\n  url: \"http://192.0.2.10:8123\"\n  token_env: SOCK_SWITCH_TOKEN\npower_sources:\n"+
		haMeter("desk-bar", "http://192.0.2.10:8123", "ch1=Left monitor=switch.desk_bar_socket_1", "ch2=switch.desk_bar_socket_2")+
		"    name: Monitor powerbar\n"+
		haMeter("lab-plug", "http://192.0.2.10:8123")+
		`  - {id: shelly-1, type: shelly, url: "http://192.0.2.11"}`+"\n"+
		haMeter("own-plug", "http://192.0.2.10:8123/", "main=switch.own_plug")+
		"    system_hint: self\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []SocketSource{
		{ID: "desk-bar", Name: "Monitor powerbar", Scheme: "http", Host: "192.0.2.10:8123",
			Sockets: []power.Socket{{ID: "ch1", Name: "Left monitor", SwitchEntity: "switch.desk_bar_socket_1"}, {ID: "ch2", Name: "ch2", SwitchEntity: "switch.desk_bar_socket_2"}}},
		{ID: "own-plug", Name: "own-plug", Hint: "self", Scheme: "http", Host: "192.0.2.10:8123",
			Sockets: []power.Socket{{ID: "main", Name: "main", SwitchEntity: "switch.own_plug"}}},
	}
	got := r.SocketSources()
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i].ID != want[i].ID || got[i].Name != want[i].Name || got[i].Hint != want[i].Hint || got[i].Scheme != want[i].Scheme ||
			got[i].Host != want[i].Host || !slices.Equal(got[i].Sockets, want[i].Sockets) {
			t.Errorf("source %d: %+v\nwant %+v", i, got[i], want[i])
		}
	}
	var none *Relay
	if len(none.SocketSources()) != 0 {
		t.Error("no relay has sockets")
	}
	// the longest text an approval can be asked for with these limits still fits
	longest, err := api.SocketSetRequest(strings.Repeat("a", maxSocketSourceID), strings.Repeat("b", power.MaxHASocketID), "off",
		api.SocketTag("x", "y", "z", "switch.q")).Canonical()
	if err != nil || len(longest) > api.MaxApprovalRequest {
		t.Errorf("%d bytes, %v", len(longest), err)
	}
}
