package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// check-config and the home_assistant block (PLUGS-DESIGN.md 3.3): one line for the block, one for each socket
// that says whether it can be switched, the sockets that never are, and the notes. A problem is "config
// problem: ..." and exit code 1. The token is in no line.

const (
	plugReadVar   = "CHECK_PLUG_READ_TOKEN"
	plugSwitchVar = "CHECK_PLUG_SWITCH_TOKEN"
)

// plugVars skips the test when one of its two variables is set where the tests run, and takes them away again
// when the test is over.
func plugVars(t *testing.T) {
	t.Helper()
	for _, n := range []string{plugReadVar, plugSwitchVar} {
		if _, set := os.LookupEnv(n); set {
			t.Skip(n + " is set in this environment")
		}
		t.Cleanup(func() { os.Unsetenv(n) })
	}
}

// plugFiles writes a config.yaml with the made-up plugs, its env file and its tokens into a folder of the
// test, and says what check-config sees of the passkey check (trust: an api.Approval... state).
func plugFiles(t *testing.T, block, sources, envLines, trust string) (path string) {
	t.Helper()
	for _, n := range []string{plugReadVar, plugSwitchVar} {
		os.Unsetenv(n) // check-config loads env_file into this process: what the run before left is taken away
	}
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	old := plugTrustState
	plugTrustState = func(*agent.Config) string { return trust }
	t.Cleanup(func() { plugTrustState = old })
	dir := t.TempDir()
	path, env := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "secrets.env")
	for p, text := range map[string]string{path: "env_file: " + env + "\n" + block + sources, env: envLines,
		filepath.Join(dir, "token"): strings.Repeat("r", 30), filepath.Join(dir, "control-token"): strings.Repeat("c", 30)} {
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

const plugSources = `power_sources:
  - id: desk-bar
    type: homeassistant
    name: "Monitor powerbar"
    url: "http://192.0.2.10:8123"
    token_env: ` + plugReadVar + `
    entity: sensor.desk_bar_power
    sockets:
      - {id: ch1, name: "Left monitor", switch_entity: switch.desk_bar_socket_1}
      - {id: ch2, switch_entity: switch.desk_bar_socket_2}
  - id: server-corner
    type: homeassistant
    url: "http://192.0.2.10:8123"
    token_env: ` + plugReadVar + `
    entity: sensor.server_corner_power
    sockets:
      - {id: main, name: "Server corner", switch_entity: switch.server_corner_socket}
  - id: own-plug
    type: homeassistant
    url: "http://192.0.2.10:8123/"
    token_env: ` + plugReadVar + `
    entity: sensor.own_plug_power
    system_hint: self
    sockets:
      - {id: main, name: "This machine", switch_entity: switch.own_plug}
`

const plugMeterLines = `power source "desk-bar": homeassistant, host 192.0.2.10:8123 (http), sensor.desk_bar_power, token: present (` + plugReadVar + `)
power source "server-corner": homeassistant, host 192.0.2.10:8123 (http), sensor.server_corner_power, token: present (` + plugReadVar + `)
power source "own-plug": homeassistant, host 192.0.2.10:8123 (http), sensor.own_plug_power, token: present (` + plugReadVar + `)
`

func plugBlock(lines ...string) string {
	return "home_assistant:\n  url: \"http://192.0.2.10:8123\"\n  token_env: " + plugSwitchVar + "\n" + strings.Join(lines, "")
}

func TestCheckConfigPlugLines(t *testing.T) {
	plugVars(t)
	read := strings.Join([]string{"fake", "read", "token"}, "-")
	sw := strings.Join([]string{"fake", "switch", "token"}, "-")
	both := plugReadVar + "=" + read + "\n" + plugSwitchVar + "=" + sw + "\n"
	const httpNote = "note: switching goes over http: the token and every request cross that network unencrypted, and whoever is on it can read and change them. Use https with ca_file where you can.\n"
	const offNote = "note: this machine has no passkey check: every switch request is refused (approval_off) until the check is turned on.\n"
	for name, c := range map[string]struct {
		block, env, trust, want string
	}{
		"switching on": {
			plugBlock("  switching: true\n", "  switch_allow: [switch.desk_bar_socket_1, switch.own_plug]\n", "  feeds_self: [switch.server_corner_socket]\n"), both, api.ApprovalRequired,
			`home assistant: host 192.0.2.10:8123 (http), token: present (` + plugSwitchVar + `), switching: on, 10 s between two switches of one socket
socket "desk-bar/ch1" (Left monitor): switch.desk_bar_socket_1, can be switched
socket "desk-bar/ch2" (ch2): switch.desk_bar_socket_2, shown only (not in home_assistant.switch_allow)
socket "server-corner/main" (Server corner): switch.server_corner_socket, never switched (home_assistant.feeds_self)
socket "own-plug/main" (This machine): switch.own_plug, never switched (its power source says system_hint: self)
never switched (feeds_self): switch.server_corner_socket
` + httpNote},
		"switching on, no passkey check": {
			plugBlock("  switching: true\n", "  switch_allow: [switch.desk_bar_socket_1]\n", "  feeds_self: []\n", "  min_gap_s: 30\n"), both, api.ApprovalOff,
			`home assistant: host 192.0.2.10:8123 (http), token: present (` + plugSwitchVar + `), switching: on, 30 s between two switches of one socket
socket "desk-bar/ch1" (Left monitor): switch.desk_bar_socket_1, can be switched
socket "desk-bar/ch2" (ch2): switch.desk_bar_socket_2, shown only (not in home_assistant.switch_allow)
socket "server-corner/main" (Server corner): switch.server_corner_socket, shown only (not in home_assistant.switch_allow)
socket "own-plug/main" (This machine): switch.own_plug, never switched (its power source says system_hint: self)
never switched (feeds_self): none
` + httpNote + offNote},
		"the passkey check cannot be seen (not root)": {
			plugBlock("  switching: true\n", "  switch_allow: [switch.desk_bar_socket_1]\n", "  feeds_self: []\n"), both, api.ApprovalBroken,
			`home assistant: host 192.0.2.10:8123 (http), token: present (` + plugSwitchVar + `), switching: on, 10 s between two switches of one socket
socket "desk-bar/ch1" (Left monitor): switch.desk_bar_socket_1, can be switched
socket "desk-bar/ch2" (ch2): switch.desk_bar_socket_2, shown only (not in home_assistant.switch_allow)
socket "server-corner/main" (Server corner): switch.server_corner_socket, shown only (not in home_assistant.switch_allow)
socket "own-plug/main" (This machine): switch.own_plug, never switched (its power source says system_hint: self)
never switched (feeds_self): none
` + httpNote},
		"switching off": {
			plugBlock("  switch_allow: [switch.desk_bar_socket_1]\n", "  feeds_self: [switch.server_corner_socket]\n"), both, api.ApprovalOff,
			`home assistant: host 192.0.2.10:8123 (http), token: present (` + plugSwitchVar + `), switching: off (sockets are shown, nothing is ever switched)
socket "desk-bar/ch1" (Left monitor): switch.desk_bar_socket_1, shown only (home_assistant.switching is false)
socket "desk-bar/ch2" (ch2): switch.desk_bar_socket_2, shown only (not in home_assistant.switch_allow)
socket "server-corner/main" (Server corner): switch.server_corner_socket, never switched (home_assistant.feeds_self)
socket "own-plug/main" (This machine): switch.own_plug, never switched (its power source says system_hint: self)
never switched (feeds_self): switch.server_corner_socket
`},
		"no token for switching": {
			plugBlock("  switching: true\n", "  switch_allow: [switch.desk_bar_socket_1]\n", "  feeds_self: []\n"), plugReadVar + "=" + read + "\n", api.ApprovalRequired,
			`home assistant: host 192.0.2.10:8123 (http), token: missing (` + plugSwitchVar + ` is not set: fairy-agent secret set ` + plugSwitchVar + `, then restart the agent), switching: on, 10 s between two switches of one socket
socket "desk-bar/ch1" (Left monitor): switch.desk_bar_socket_1, can be switched
socket "desk-bar/ch2" (ch2): switch.desk_bar_socket_2, shown only (not in home_assistant.switch_allow)
socket "server-corner/main" (Server corner): switch.server_corner_socket, shown only (not in home_assistant.switch_allow)
socket "own-plug/main" (This machine): switch.own_plug, never switched (its power source says system_hint: self)
never switched (feeds_self): none
note: the variable ` + plugSwitchVar + ` holds no token: no socket's state is read and nothing is switched until it does. The token the power sources read with is never used in its place.
` + httpNote},
		"the lists disagree": {
			plugBlock("  switching: true\n", "  switch_allow: [switch.desk_bar_socket_1, switch.server_corner_socket, switch.no_such_socket]\n", "  feeds_self: [switch.server_corner_socket, switch.elsewhere]\n"),
			both, api.ApprovalRequired,
			`home assistant: host 192.0.2.10:8123 (http), token: present (` + plugSwitchVar + `), switching: on, 10 s between two switches of one socket
socket "desk-bar/ch1" (Left monitor): switch.desk_bar_socket_1, can be switched
socket "desk-bar/ch2" (ch2): switch.desk_bar_socket_2, shown only (not in home_assistant.switch_allow)
socket "server-corner/main" (Server corner): switch.server_corner_socket, never switched (home_assistant.feeds_self)
socket "own-plug/main" (This machine): switch.own_plug, never switched (its power source says system_hint: self)
never switched (feeds_self): switch.server_corner_socket, switch.elsewhere
` + httpNote + `note: switch.server_corner_socket is in switch_allow and in feeds_self: feeds_self counts, it is never switched.
note: switch.no_such_socket is in switch_allow and no socket in this file has that switch: nothing is switched by it.
`},
	} {
		p := plugFiles(t, c.block, plugSources, c.env, c.trust)
		var out, errb bytes.Buffer
		code := checkConfigCmd(p, &out, &errb)
		want := "config OK: " + p + "\n" + plugMeterLines + c.want
		if code != 0 || out.String() != want || errb.Len() != 0 {
			t.Errorf("%s: exit %d\nstdout:\n%s\nwant:\n%s\nstderr: %s", name, code, out.String(), want, errb.String())
		}
		if s := out.String() + errb.String(); strings.Contains(s, read) || strings.Contains(s, sw) {
			t.Errorf("%s: check-config shows a token", name)
		}
	}

	// one token for both: said, with what a second one would give
	p := plugFiles(t, strings.Replace(plugBlock("  switching: true\n", "  feeds_self: []\n"), plugSwitchVar, plugReadVar, 1), plugSources, both, api.ApprovalRequired)
	var out, errb bytes.Buffer
	if code := checkConfigCmd(p, &out, &errb); code != 0 || !strings.Contains(out.String(), "note: home_assistant.token_env names the variable the power sources read with: one token reads the sensors and switches the sockets.") {
		t.Errorf("one token for both: exit %d\n%s%s", code, out.String(), errb.String())
	}

	// https: no note about the network
	https := strings.ReplaceAll(plugSources, `"http://192.0.2.10:8123"`, `"https://ha.example:8443"`)
	https = strings.ReplaceAll(https, `"http://192.0.2.10:8123/"`, `"https://ha.example:8443"`)
	p = plugFiles(t, strings.Replace(plugBlock("  switching: true\n", "  feeds_self: []\n"), `"http://192.0.2.10:8123"`, `"https://ha.example:8443"`, 1), https, both, api.ApprovalRequired)
	out.Reset()
	errb.Reset()
	if code := checkConfigCmd(p, &out, &errb); code != 0 || strings.Contains(out.String(), "note:") ||
		!strings.Contains(out.String(), "home assistant: host ha.example:8443 (https), token: present ("+plugSwitchVar+"), switching: on") {
		t.Errorf("https: exit %d\n%s%s", code, out.String(), errb.String())
	}

	// no block: not a line more than before
	var meters []string
	for _, line := range strings.Split(plugSources, "\n") {
		if !strings.Contains(line, "sockets:") && !strings.Contains(line, "switch_entity") {
			meters = append(meters, line)
		}
	}
	p = plugFiles(t, "", strings.Join(meters, "\n"), both, api.ApprovalOff)
	out.Reset()
	errb.Reset()
	if code := checkConfigCmd(p, &out, &errb); code != 0 || out.String() != "config OK: "+p+"\n"+plugMeterLines {
		t.Errorf("no block: exit %d\n%s%s", code, out.String(), errb.String())
	}
}

// A plug whose system_hint means this machine is locked however "self" is spelled, and check-config says so in
// the socket's line. A hint that means nothing to the agent locks nothing, and that is said in a note.
func TestCheckConfigSystemHint(t *testing.T) {
	plugVars(t)
	env := plugReadVar + "=x\n" + plugSwitchVar + "=y\n"
	block := plugBlock("  switching: true\n", "  switch_allow: [switch.own_plug]\n", "  feeds_self: []\n")
	const note = "note: power source own-plug: its system_hint is neither \"self\" nor this machine's name, so this plug is taken as feeding another machine: " +
		"its sockets can be switched if allowed. If it feeds this machine, write system_hint: self, or list its switches in home_assistant.feeds_self.\n"
	for hint, c := range map[string]struct {
		line string
		note bool
	}{
		"self":            {"never switched (its power source says system_hint: self)", false},
		"Self":            {"never switched (its power source says system_hint: self)", false},
		`" SELF "`:        {"never switched (its power source says system_hint: self)", false},
		"another-machine": {"can be switched", true},
		`"not this one"`:  {"can be switched", true},
		`"selfish-thing"`: {"can be switched", true},
	} {
		p := plugFiles(t, block, strings.Replace(plugSources, "system_hint: self", "system_hint: "+hint, 1), env, api.ApprovalRequired)
		var out, errb bytes.Buffer
		code := checkConfigCmd(p, &out, &errb)
		if want := `socket "own-plug/main" (This machine): switch.own_plug, ` + c.line + "\n"; code != 0 || !strings.Contains(out.String(), want) || strings.Contains(out.String(), note) != c.note {
			t.Errorf("system_hint: %s: exit %d\n%s%s", hint, code, out.String(), errb.String())
		}
		if c.note && strings.Contains(out.String(), strings.Trim(hint, `"`)) {
			t.Errorf("system_hint: %s: check-config repeats the hint:\n%s", hint, out.String())
		}
	}
	// no hint at all: nothing is said about it
	p := plugFiles(t, block, strings.Replace(plugSources, "    system_hint: self\n", "", 1), env, api.ApprovalRequired)
	var out, errb bytes.Buffer
	if code := checkConfigCmd(p, &out, &errb); code != 0 || strings.Contains(out.String(), "system_hint") || !strings.Contains(out.String(), "switch.own_plug, can be switched\n") {
		t.Errorf("no system_hint: exit %d\n%s%s", code, out.String(), errb.String())
	}
}

func TestCheckConfigPlugProblems(t *testing.T) {
	plugVars(t)
	secret := strings.Join([]string{"made", "up", "token", "pasted", "into", "the", "file"}, "-")
	env := plugReadVar + "=x\n" + plugSwitchVar + "=y\n"
	for name, c := range map[string]struct{ block, sources, want string }{
		"switching without a feeds_self line": {plugBlock("  switching: true\n", "  switch_allow: [switch.desk_bar_socket_1]\n"), plugSources,
			"home_assistant.switching is true and there is no feeds_self line. Find out which socket feeds this machine, Home Assistant or the network, write it into feeds_self, and switch nothing before that. If no socket does, write: feeds_self: []"},
		"sockets without the block": {"", plugSources,
			"config problem: power source desk-bar: sockets need the home_assistant block, and the entry's url must be the same address as home_assistant.url"},
		"sockets at another address": {strings.Replace(plugBlock(), "192.0.2.10", "192.0.2.77", 1), plugSources,
			"config problem: power source desk-bar: sockets need the home_assistant block, and the entry's url must be the same address as home_assistant.url"},
		"two sockets with one id": {plugBlock(), strings.Replace(plugSources, "{id: ch2,", "{id: ch1,", 1),
			"config problem: power source desk-bar: sockets: two sockets have the same id"},
		"a token in switch_allow": {plugBlock("  switch_allow: [" + secret + "]\n"), plugSources,
			"home_assistant.switch_allow, item 1: must be the entity id of a switch in Home Assistant"},
		"a token as switch_entity": {plugBlock(), strings.Replace(plugSources, "switch.desk_bar_socket_2", secret, 1),
			"config problem: power source desk-bar: sockets, item 2: switch_entity must be the entity id of a switch"},
		"a url with a password": {strings.Replace(plugBlock(), "http://192.0.2.10", "http://fairy:"+secret+"@192.0.2.10", 1), plugSources,
			"home_assistant.url must be the address of Home Assistant itself"},
		"a ca_file that is not there": {strings.Replace(plugBlock("  ca_file: /nonexistent/ha.pem\n"), "http://", "https://", 1), strings.ReplaceAll(plugSources, "http://", "https://"),
			"config problem: home_assistant.ca_file: "},
	} {
		p := plugFiles(t, c.block, c.sources, env, api.ApprovalRequired)
		var out, errb bytes.Buffer
		code := checkConfigCmd(p, &out, &errb)
		if code != 1 || out.Len() != 0 || !strings.HasPrefix(errb.String(), "config problem: ") || !strings.Contains(errb.String(), c.want) {
			t.Errorf("%s: exit %d\nstdout: %s\nstderr: %s\nwant: %s", name, code, out.String(), errb.String(), c.want)
		}
		if strings.Contains(errb.String(), secret) {
			t.Errorf("%s: the problem repeats what was pasted: %s", name, errb.String())
		}
	}
	// switching on needs the control token, like every control feature
	p := plugFiles(t, plugBlock("  switching: true\n", "  feeds_self: []\n"), plugSources, env, api.ApprovalRequired)
	if err := os.Remove(filepath.Join(filepath.Dir(p), "control-token")); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := checkConfigCmd(p, &out, &errb); code != 1 || !strings.Contains(errb.String(), "control token (fan, power, Wake-on-LAN, self-update or plug switching is enabled)") {
		t.Errorf("no control token: exit %d\n%s", code, errb.String())
	}
}

// `config set` turns switching on only in a file that has the feeds_self line, and says why when it does not;
// the file is then as it was.
func TestConfigSetSwitching(t *testing.T) {
	if !isAdmin() {
		t.Skip("config set writes config.yaml only as root / Administrator")
	}
	inTestFolders(t)
	plugVars(t)
	env := plugReadVar + "=x\n" + plugSwitchVar + "=y\n"
	p := plugFiles(t, plugBlock(), plugSources, env, api.ApprovalRequired)
	before, _ := os.ReadFile(p)
	var out, errb bytes.Buffer
	if code := configCmd([]string{"set", "home_assistant.switching", "true", "--config", p}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "not changed, the result would be invalid") || !strings.Contains(errb.String(), "there is no feeds_self line") {
		t.Fatalf("switching on without the line: exit %d\n%s%s", code, out.String(), errb.String())
	}
	if now, _ := os.ReadFile(p); !bytes.Equal(now, before) {
		t.Fatal("the file was changed")
	}
	for _, step := range [][2]string{{"home_assistant.feeds_self", "switch.server_corner_socket"}, {"home_assistant.switch_allow", "switch.desk_bar_socket_1, switch.desk_bar_socket_2"},
		{"home_assistant.switching", "true"}} {
		out.Reset()
		errb.Reset()
		if code := configCmd([]string{"set", step[0], step[1], "--config", p}, &out, &errb); code != 0 {
			t.Fatalf("config set %s: exit %d\n%s%s", step[0], code, out.String(), errb.String())
		}
	}
	cfg, err := agent.Load(p)
	if err != nil || !cfg.HomeAssistant.Switching || len(cfg.HomeAssistant.SwitchAllow) != 2 || len(cfg.HomeAssistant.FeedsSelf) != 1 {
		t.Fatalf("%+v %v", cfg, err)
	}
	out.Reset()
	if code := configCmd([]string{"show", "--config", p}, &out, &errb); code != 0 || !strings.Contains(out.String(), "home_assistant.switching: true\n") ||
		!strings.Contains(out.String(), "home_assistant.feeds_self: [switch.server_corner_socket]\n") || !strings.Contains(out.String(), "home_assistant.min_gap_s: 10\n") {
		t.Fatalf("config show:\n%s", out.String())
	}
}
