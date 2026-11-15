package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// The home_assistant block of config.yaml (PLUGS-DESIGN.md 3.2): one test for each line of its table.

const haBlockPath = "/etc/fairy-agent/config.yaml"

// haBlock is a block that loads, with lines replaced or added ("" takes a line out).
func haBlock(lines map[string]string) string {
	block := map[string]string{"url": `"http://192.0.2.10:8123"`, "token_env": "HAB_SWITCH_TOKEN"}
	for k, v := range lines {
		block[k] = v
	}
	out := "home_assistant:\n"
	for _, k := range slices.Sorted(func(yield func(string) bool) {
		for k := range block {
			if !yield(k) {
				return
			}
		}
	}) {
		if block[k] != "" {
			out += "  " + k + ": " + block[k] + "\n"
		}
	}
	return out
}

func TestHomeAssistantBlockDefaults(t *testing.T) {
	// a config from before the block loads as it did: nothing is switched, no control token is asked for
	for name, y := range map[string]string{"no block": "", "an empty block": "home_assistant: {}\n", "a block with nothing after it": "home_assistant:\n"} {
		c, err := Parse([]byte(y), haBlockPath)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		h := c.HomeAssistant
		if c.HomeAssistantSet() || h.Switching || h.URL != "" || h.TokenEnv != "" || len(h.SwitchAllow) != 0 || len(h.FeedsSelf) != 0 || c.ControlEnabled() {
			t.Errorf("%s: %+v", name, h)
		}
		if h.MinGapS != 10 || DefaultSwitchGapS != 10 {
			t.Errorf("%s: min_gap_s is %d, want 10", name, h.MinGapS)
		}
		if len(c.deviceSecretEnv()) != 0 {
			t.Errorf("%s: secrets %v", name, c.deviceSecretEnv())
		}
	}
	// the block with its address and its token and nothing else: sockets can be shown, nothing is switched
	c, err := Parse([]byte(haBlock(nil)), haBlockPath)
	if err != nil {
		t.Fatal(err)
	}
	if h := c.HomeAssistant; !c.HomeAssistantSet() || h.Switching || c.ControlEnabled() || h.MinGapS != 10 || h.URL != "http://192.0.2.10:8123" || h.TokenEnv != "HAB_SWITCH_TOKEN" {
		t.Errorf("%+v", h)
	}
	// everything set
	c, err = Parse([]byte(haBlock(map[string]string{"url": `"https://ha.example:8443/"`, "ca_file": "/etc/fairy-agent/ha.pem", "switching": "true",
		"switch_allow": "[switch.desk_bar_socket_1, switch.desk_bar_socket_2]", "feeds_self": "[switch.server_corner_socket]", "min_gap_s": "30"})), haBlockPath)
	if err != nil {
		t.Fatal(err)
	}
	h := c.HomeAssistant
	if !h.Switching || !c.ControlEnabled() || h.MinGapS != 30 || h.CAFile != "/etc/fairy-agent/ha.pem" ||
		!slices.Equal(h.SwitchAllow, []string{"switch.desk_bar_socket_1", "switch.desk_bar_socket_2"}) || !slices.Equal(h.FeedsSelf, []string{"switch.server_corner_socket"}) {
		t.Errorf("%+v", h)
	}
}

// Switching is turned on only by a file that also answers which sockets are never switched: a feeds_self line
// with a list, the empty one included.
func TestSwitchingNeedsAFeedsSelfLine(t *testing.T) {
	const sentence = "home_assistant.switching is true and there is no feeds_self line. Find out which socket feeds this machine, Home Assistant or the network, " +
		"write it into feeds_self, and switch nothing before that. If no socket does, write: feeds_self: []"
	for name, lines := range map[string]map[string]string{
		"no line":                   {"switching": "true"},
		"no line, sockets allowed":  {"switching": "true", "switch_allow": "[switch.desk_bar_socket_1]"},
		"the line with no value":    {"switching": "true", "feeds_self": " "},
		"the line with a null":      {"switching": "true", "feeds_self": "~"},
		"the line as a comment":     {"switching": "true", "min_gap_s": "10 # feeds_self: []"},
		"the line in capitals":      {"switching": "true", "Feeds_self": "[]"},
		"switching as a quoted yes": {"switching": `"true"`},
	} {
		_, err := Parse([]byte(haBlock(lines)), haBlockPath)
		if err == nil {
			t.Errorf("%s: loads", name)
			continue
		}
		if name == "the line in capitals" || name == "switching as a quoted yes" { // not this block's settings at all
			continue
		}
		if want := haBlockPath + ": " + sentence; err.Error() != want {
			t.Errorf("%s: %v\nwant %s", name, err, want)
		}
	}
	for name, lines := range map[string]map[string]string{
		"the empty list":           {"switching": "true", "feeds_self": "[]"},
		"a list":                   {"switching": "true", "feeds_self": "[switch.server_corner_socket]"},
		"a list in block style":    {"switching": "true", "feeds_self": "\n    - switch.server_corner_socket"},
		"an id in both lists":      {"switching": "true", "feeds_self": "[switch.a]", "switch_allow": "[switch.a]"},
		"switching off, no line":   {"switching": "false"},
		"switching off, allow set": {"switch_allow": "[switch.desk_bar_socket_1]"},
	} {
		c, err := Parse([]byte(haBlock(lines)), haBlockPath)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if want := lines["switching"] == "true"; c.HomeAssistant.Switching != want || c.ControlEnabled() != want {
			t.Errorf("%s: switching %v, control %v", name, c.HomeAssistant.Switching, c.ControlEnabled())
		}
	}
	// a Config that was not read from a file is held to the same rule
	c := &Config{path: haBlockPath, HomeAssistant: HomeAssistantConfig{URL: "http://192.0.2.10:8123", TokenEnv: "HAB_SWITCH_TOKEN", Switching: true}}
	c.defaults()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), sentence) {
		t.Errorf("a Config made in code with switching: %v", err)
	}
}

func TestHomeAssistantBlockValidation(t *testing.T) {
	many := func(n int) string {
		ids := make([]string, n)
		for i := range ids {
			ids[i] = fmt.Sprintf("switch.s%d", i)
		}
		return "[" + strings.Join(ids, ", ") + "]"
	}
	secret := strings.Join([]string{"made", "up", "token", "written", "into", "the", "wrong", "line"}, "-")
	for name, c := range map[string]struct {
		lines map[string]string
		want  string
	}{
		"no url":                     {map[string]string{"url": ""}, "home_assistant.url is needed"},
		"only min_gap_s":             {map[string]string{"url": "", "token_env": "", "min_gap_s": "20"}, "home_assistant.url is needed"},
		"only switch_allow":          {map[string]string{"url": "", "token_env": "", "switch_allow": "[switch.a]"}, "home_assistant.url is needed"},
		"url with a path":            {map[string]string{"url": `"http://192.0.2.10:8123/api"`}, "home_assistant.url must be the address of Home Assistant itself"},
		"url with a user":            {map[string]string{"url": `"http://fairy:` + secret + `@192.0.2.10:8123"`}, "home_assistant.url must be"},
		"url with a query":           {map[string]string{"url": `"http://192.0.2.10:8123?x=1"`}, "home_assistant.url must be"},
		"url of another scheme":      {map[string]string{"url": `"ftp://192.0.2.10"`}, "home_assistant.url must be"},
		"the token as the url":       {map[string]string{"url": secret}, "home_assistant.url must be"},
		"no token_env, switching":    {map[string]string{"token_env": "", "switching": "true", "feeds_self": "[]"}, "home_assistant.token_env is needed"},
		"token_env without a url":    {map[string]string{"url": ""}, "home_assistant.url is needed"},
		"the token in token_env":     {map[string]string{"token_env": secret}, "home_assistant.token_env must be the name of the environment variable"},
		"one of Fairy's variables":   {map[string]string{"token_env": "FAIRY_AGENT_CONTROL_TOKEN"}, "home_assistant.token_env must not be one of Fairy's own variables"},
		"one of Fairy's, small":      {map[string]string{"token_env": "fairy_agent_token"}, "home_assistant.token_env must not be one of Fairy's own variables"},
		"a variable of the system":   {map[string]string{"token_env": "Path"}, "home_assistant.token_env must not be a variable of the system"},
		"ca_file with http":          {map[string]string{"ca_file": "/etc/fairy-agent/ha.pem"}, "home_assistant.ca_file is only for an https url"},
		"switch_allow: a sensor":     {map[string]string{"switch_allow": "[switch.a, sensor.desk_plug_power]"}, "home_assistant.switch_allow, item 2: must be the entity id of a switch"},
		"switch_allow: a light":      {map[string]string{"switch_allow": "[light.desk]"}, "home_assistant.switch_allow, item 1: must be the entity id of a switch"},
		"switch_allow: a pattern":    {map[string]string{"switch_allow": `["switch.desk_*"]`}, "home_assistant.switch_allow, item 1: must be"},
		"switch_allow: all":          {map[string]string{"switch_allow": "[all]"}, "home_assistant.switch_allow, item 1: must be"},
		"switch_allow: two in one":   {map[string]string{"switch_allow": `["switch.a, switch.b"]`}, "home_assistant.switch_allow, item 1: must be"},
		"switch_allow: capitals":     {map[string]string{"switch_allow": "[switch.Desk]"}, "home_assistant.switch_allow, item 1: must be"},
		"switch_allow: a path":       {map[string]string{"switch_allow": `["switch.a/../../services/lock/unlock"]`}, "home_assistant.switch_allow, item 1: must be"},
		"switch_allow: empty item":   {map[string]string{"switch_allow": `[switch.a, ""]`}, "home_assistant.switch_allow, item 2: must be"},
		"switch_allow: only domain":  {map[string]string{"switch_allow": `["switch."]`}, "home_assistant.switch_allow, item 1: must be"},
		"switch_allow: the token":    {map[string]string{"switch_allow": "[" + secret + "]"}, "home_assistant.switch_allow, item 1: must be"},
		"switch_allow: too long":     {map[string]string{"switch_allow": "[switch." + strings.Repeat("a", 249) + "]"}, "home_assistant.switch_allow, item 1: must be"},
		"switch_allow: twice":        {map[string]string{"switch_allow": "[switch.a, switch.b, switch.a]"}, "home_assistant.switch_allow, item 3: the same id as item 1"},
		"switch_allow: 33 items":     {map[string]string{"switch_allow": many(33)}, "home_assistant.switch_allow has more than 32 items"},
		"feeds_self: a sensor":       {map[string]string{"feeds_self": "[sensor.x]"}, "home_assistant.feeds_self, item 1: must be the entity id of a switch"},
		"feeds_self: twice":          {map[string]string{"feeds_self": "[switch.a, switch.a]"}, "home_assistant.feeds_self, item 2: the same id as item 1"},
		"feeds_self: 33 items":       {map[string]string{"feeds_self": many(33)}, "home_assistant.feeds_self has more than 32 items"},
		"min_gap_s 4":                {map[string]string{"min_gap_s": "4"}, "home_assistant.min_gap_s must be 5-3600"},
		"min_gap_s 3601":             {map[string]string{"min_gap_s": "3601"}, "home_assistant.min_gap_s must be 5-3600"},
		"min_gap_s negative":         {map[string]string{"min_gap_s": "-1"}, "home_assistant.min_gap_s must be 5-3600"},
		"min_gap_s 4.9":              {map[string]string{"min_gap_s": "4.9"}, "home_assistant.min_gap_s must be 5-3600"}, // the decoder cuts a fraction off, as for every whole number of this file
		"min_gap_s a word":           {map[string]string{"min_gap_s": "soon"}, "cannot unmarshal"},
		"an unknown setting":         {map[string]string{"toggle": "true"}, "field toggle not found"},
		"the token as a setting":     {map[string]string{"token": "x"}, "field token not found"},
		"switching the fourth state": {map[string]string{"switching": "maybe"}, "cannot unmarshal"},
	} {
		_, err := Parse([]byte(haBlock(c.lines)), haBlockPath)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v\nwant an error with %q", name, err, c.want)
			continue
		}
		// a problem of this block names the setting and the item's place, never what was written there
		if strings.Contains(err.Error(), "home_assistant.") && (strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "192.0.2.10")) {
			t.Errorf("%s: the problem repeats a value: %v", name, err)
		}
	}
	for name, lines := range map[string]map[string]string{
		"32 items":             {"switch_allow": many(32), "feeds_self": many(32)},
		"min_gap_s 5":          {"min_gap_s": "5"},
		"min_gap_s 3600":       {"min_gap_s": "3600"},
		"https with a ca_file": {"url": `"https://ha.example:8443"`, "ca_file": "/etc/fairy-agent/ha.pem"},
		"https without one":    {"url": `"https://ha.example"`},
		"a long id":            {"switch_allow": "[switch." + strings.Repeat("a", 248) + "]"},
		"the meters' variable": {"token_env": "HA_TOKEN"},
		"the address alone":    {"token_env": ""}, // `config set` writes the block one setting at a time, the address first
	} {
		if _, err := Parse([]byte(haBlock(lines)), haBlockPath); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Switching is a control feature like the others: with it on, the agent needs a control token, and the sentence
// that asks for one names it.
func TestSwitchingNeedsAControlToken(t *testing.T) {
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	c := mustParse(t, haBlock(map[string]string{"switching": "true", "feeds_self": "[]"}))
	if !c.ControlEnabled() {
		t.Fatal("switching is on and no control token is asked for")
	}
	if err := os.WriteFile(c.TokenFile, []byte(readTok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := c.LoadTokens()
	if err == nil || !strings.Contains(err.Error(), "control token (fan, power, Wake-on-LAN, self-update or plug switching is enabled)") {
		t.Fatalf("no control token: %v", err)
	}
	if err := os.WriteFile(c.ControlTokenFile, []byte(ctlTok), 0o600); err != nil {
		t.Fatal(err)
	}
	if tk, err := c.LoadTokens(); err != nil || tk.Control != ctlTok {
		t.Fatalf("%v", err)
	}
	// shown only: no control token is needed, and none is read
	shown := mustParse(t, haBlock(nil))
	if err := os.WriteFile(shown.TokenFile, []byte(readTok), 0o600); err != nil {
		t.Fatal(err)
	}
	if tk, err := shown.LoadTokens(); err != nil || tk.Control != "" {
		t.Fatalf("a block that switches nothing asked for a control token: %v", err)
	}
}

// The variable of the switching token is a secret of a device like every other: it is hidden from every
// program the agent starts, wherever its value came from, and stays in the agent's own environment.
func TestSwitchTokenIsNotHandedToChildPrograms(t *testing.T) {
	value := strings.Join([]string{"switch", "token", "of", "the", "service"}, "-")
	t.Setenv("HABSEC_SWITCH_TOKEN", value)
	t.Setenv("HABSEC_SWITCH_TOKEN_2", "stays")
	cfg := mustParse(t, haBlock(map[string]string{"token_env": "HABSEC_SWITCH_TOKEN"}))
	if got := cfg.deviceSecretEnv(); !slices.Equal(got, []string{"HABSEC_SWITCH_TOKEN"}) {
		t.Fatalf("device secrets: %v", got)
	}
	for name, hide := range map[string]func(){
		"loadSecrets":       func() { _ = loadSecrets(cfg) },
		"HideDeviceSecrets": func() { HideDeviceSecrets(cfg) },
	} {
		hide()
		env := strings.Join(collect.MinimalEnv(), "\n") + "\n"
		if strings.Contains(env, value) || strings.Contains(env, "HABSEC_SWITCH_TOKEN=") {
			t.Errorf("%s: a child program gets the switching token", name)
		}
		if !strings.Contains(env, "HABSEC_SWITCH_TOKEN_2=stays") {
			t.Errorf("%s: a variable with a longer name is hidden too", name)
		}
		if os.Getenv("HABSEC_SWITCH_TOKEN") != value {
			t.Errorf("%s: the agent itself lost the token", name)
		}
	}
	// a removed entry's variable that the block names is still in use: it is loaded, and its note says to leave it
	dir := t.TempDir()
	envFile := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(envFile, []byte("HABSEC_SHARED_OLD=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Parse([]byte("env_file: '"+envFile+"'\n"+haBlock(map[string]string{"token_env": "HABSEC_SHARED_OLD"})+
		"power_sources:\n  - {id: old-plug, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: HABSEC_SHARED_OLD}\n"), filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.UnusedSecret("HABSEC_SHARED_OLD") || len(c.Ignored()) != 1 || !strings.Contains(c.Ignored()[0], "leave the line HABSEC_SHARED_OLD=...") {
		t.Errorf("the block's variable counts as unused: %v", c.Ignored())
	}
}

// The token for switching has a variable of its own: with switching: true, a config in which
// home_assistant.token_env names the variable a homeassistant entry reads with does not load. The problem names
// the two places and never the variable. With switching off the same file loads (check-config has a note).
func TestSwitchingNeedsATokenVariableOfItsOwn(t *testing.T) {
	const words = ": with switching: true the token that switches the sockets needs a variable of its own, so that it can be revoked alone and is not the token the sensors are read with. " +
		"Give home_assistant.token_env a name that no power source uses, and store the second token under it (fairy-agent secret set <that name>)"
	relay := func(conf string) error {
		cfg, err := Parse([]byte(conf), filepath.Join(t.TempDir(), "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = cfg.NewRelay()
		return err
	}
	on := haBlock(map[string]string{"token_env": "TOO_HA_TOKEN", "switching": "true", "feeds_self": "[]"})
	off := haBlock(map[string]string{"token_env": "TOO_HA_TOKEN"})
	meter := func(id, env, more string) string {
		return fmt.Sprintf("  - {id: %s, type: homeassistant, url: \"http://192.0.2.10:8123\", token_env: %s, entity: sensor.%s_power%s}\n", id, env, strings.ReplaceAll(id, "-", "_"), more)
	}
	const sockets = ", sockets: [{id: main, switch_entity: switch.desk_plug}]"
	for name, c := range map[string]struct{ sources, who string }{
		"an entry with sockets":          {meter("desk-plug", "TOO_HA_TOKEN", sockets), "desk-plug"},
		"an entry without sockets":       {meter("desk-plug", "TOO_HA_TOKEN", ""), "desk-plug"},
		"in another letter case":         {meter("desk-plug", "too_ha_token", sockets), "desk-plug"},
		"the second entry of two":        {meter("desk-plug", "TOO_READ_TOKEN", sockets) + meter("lab-plug", "TOO_HA_TOKEN", ""), "lab-plug"},
		"next to a plug of another type": {`  - {id: shelly-1, type: shelly, url: "http://192.0.2.11", password_env: TOO_SHELLY}` + "\n" + meter("lab-plug", "Too_Ha_Token", ""), "lab-plug"},
	} {
		err := relay(on + "power_sources:\n" + c.sources)
		if want := "home_assistant: token_env names the same variable as token_env of power source " + c.who + words; err == nil || err.Error() != want {
			t.Errorf("switching on, %s: %v\nwant %s", name, err, want)
		}
		if err != nil && strings.Contains(strings.ToUpper(err.Error()), "TOO_") {
			t.Errorf("%s: the problem names the variable: %v", name, err)
		}
		if err := relay(off + "power_sources:\n" + c.sources); err != nil {
			t.Errorf("switching off, %s: %v", name, err)
		}
		if err := relay(strings.Replace(on, "switching: true", "switching: false", 1) + "power_sources:\n" + c.sources); err != nil {
			t.Errorf("switching: false, %s: %v", name, err)
		}
	}
	for name, sources := range map[string]string{
		"a variable of its own":                   meter("desk-plug", "TOO_READ_TOKEN", sockets) + meter("lab-plug", "TOO_READ_TOKEN", ""),
		"a name that only begins the same":        meter("desk-plug", "TOO_HA_TOKEN_2", sockets),
		"an old entry of a type that is ignored":  `  - {id: desk-plug, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: TOO_HA_TOKEN, version: "3.4"}` + "\n",
		"no power source at all":                  "",
		"a plug of another type and its password": `  - {id: shelly-1, type: shelly, url: "http://192.0.2.11", password_env: TOO_SHELLY}` + "\n",
	} {
		conf := on
		if sources != "" {
			conf += "power_sources:\n" + sources
		}
		if err := relay(conf); err != nil {
			t.Errorf("switching on, %s: %v", name, err)
		}
	}
}

// What the variable named by home_assistant.token_env holds is sent to Home Assistant: it is never one another
// kind of secret is kept in. (That it is not the variable the homeassistant entries read with either, once
// switching is on: TestSwitchingNeedsATokenVariableOfItsOwn.)
func TestSwitchTokenEnvIsNotAVariableAnotherSettingNames(t *testing.T) {
	const words = ": what that variable holds would be sent to Home Assistant as the token. The token needs a variable that nothing else names"
	block := haBlock(map[string]string{"token_env": "TES_SWITCH"})
	relay := func(conf string) error {
		cfg, err := Parse([]byte(conf), filepath.Join(t.TempDir(), "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = cfg.NewRelay()
		return err
	}
	for name, c := range map[string]struct{ conf, want string }{
		"a Shelly plug's password": {block + "power_sources:\n" +
			`  - {id: shelly-1, type: shelly, url: "http://192.0.2.11", password_env: TES_SWITCH}` + "\n", "password_env of power source shelly-1"},
		"a ups entry's, in small letters": {block + "ups:\n" +
			`  - {id: rack, host: 192.0.2.71, username: monuser, password_env: tes_switch}` + "\n", "password_env of ups rack"},
		"the BMC's": {block + "ipmi: {enabled: true, transport: ipmitool, host: 192.168.1.5, username: u, password_env: TES_SWITCH}\n", "ipmi.password_env"},
		"a BMC relay target's": {block + "bmc_relay: {enabled: true, targets: [{id: server-bmc, host: 192.168.1.7, username: u, password_env: TES_SWITCH}]}\n",
			"password_env of bmc_relay target server-bmc"},
	} {
		err := relay(c.conf)
		if want := "home_assistant: token_env names the same variable as " + c.want + words; err == nil || err.Error() != want {
			t.Errorf("%s: %v\nwant %s", name, err, want)
		}
		if err != nil && strings.Contains(strings.ToUpper(err.Error()), "TES_") {
			t.Errorf("%s: the error names the variable: %v", name, err)
		}
	}
	for name, conf := range map[string]string{
		"a variable of its own": block + "power_sources:\n" +
			`  - {id: desk-plug, type: homeassistant, url: "http://192.0.2.10:8123", token_env: TES_READ, entity: sensor.desk_plug_power}` + "\n" +
			`  - {id: shelly-1, type: shelly, url: "http://192.0.2.11", password_env: TES_SHELLY}` + "\n",
		"the variable the meters read with, while switching is off": block + "power_sources:\n" +
			`  - {id: desk-plug, type: homeassistant, url: "http://192.0.2.10:8123", token_env: TES_SWITCH, entity: sensor.desk_plug_power}` + "\n",
		"nothing else in the file": block,
	} {
		if err := relay(conf); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
