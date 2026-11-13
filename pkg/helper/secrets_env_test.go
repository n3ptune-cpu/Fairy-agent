package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// Second review of ha1: the agent hides the device secrets that config.yaml names from every program it
// starts, the Windows helper did not. The helper reads the same config.yaml and starts PowerShell for the BMC
// (IPMI through Windows); it never reads env_file, but a secret kept as a variable of the whole machine is in
// its environment as well. FromConfig is where the helper first has its config and where its transport is
// built, so the names must be hidden there, before anything else: PowerShell is started with collect.Command,
// which takes the environment at that later moment.
func TestTheHelperHidesDeviceSecretsFromThePrograms(t *testing.T) {
	secret := func(words ...string) string { return strings.Join(words, "-") } // made up, put together here
	ofTheMachine := map[string]string{
		"HLPSEC_HA_TOKEN":   secret("ha", "token", "of", "the", "machine"), // token_env of a homeassistant entry
		"HLPSEC_SHELLY_PW":  secret("shelly", "password"),                  // password_env of a plug
		"hlpsec_tasmota_pw": secret("tasmota", "password"),                 // named in capitals in config.yaml
		"HLPSEC_UPS_PW":     secret("ups", "password"),                     // password_env of a ups entry
		"HLPSEC_OLD_KEY":    secret("tuya", "local", "key"),                // only an ignored entry names it
		"HLPSEC_IPMI_PW":    secret("bmc", "password"),                     // ipmi.password_env
		"HLPSEC_RELAY_PW":   secret("relay", "target", "password"),         // a BMC relay target's password_env
	}
	for name, value := range ofTheMachine {
		t.Setenv(name, value)
	}
	t.Setenv("HLPSEC_NOT_NAMED", "stays")      // nothing in config.yaml names it
	t.Setenv("HLPSEC_HA_TOKEN_2", "stays")     // a longer name than a hidden one
	t.Setenv("HLPSEC_PLUG_NAME", "not-hidden") // the value of a `name:` member: not a member ending in "_env"
	t.Setenv("HLPSEC_IN_FILE", "set-before")   // a line of env_file, which the helper does not read
	dir := t.TempDir()
	envFile := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(envFile, []byte("HLPSEC_IN_FILE=from-the-file\nHLPSEC_ONLY_IN_FILE=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := agent.Parse([]byte(`env_file: '`+envFile+`'
power_control: {enabled: true}
ipmi: {enabled: true, transport: ipmitool, host: 192.168.1.5, username: u, password_env: HLPSEC_IPMI_PW}
bmc_relay: {enabled: true, targets: [{id: x, host: 192.168.1.6, username: u, password_env: HLPSEC_RELAY_PW}]}
power_sources:
  - {id: desk-plug, type: homeassistant, url: "http://192.0.2.10:8123", token_env: HLPSEC_HA_TOKEN, entity: sensor.desk_plug_power}
  - {id: shelly-1, type: shelly, name: HLPSEC_PLUG_NAME, url: "http://192.0.2.11", password_env: HLPSEC_SHELLY_PW}
  - {id: tasmota-1, type: tasmota, url: "http://192.0.2.12", password_env: HLPSEC_TASMOTA_PW}
  - {id: old-plug, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: HLPSEC_OLD_KEY}
ups:
  - {id: rack, host: 192.0.2.71, username: monuser, password_env: HLPSEC_UPS_PW}
`), filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	names := func(env []string) map[string]string {
		got := map[string]string{}
		for _, kv := range env {
			k, v, _ := strings.Cut(kv, "=")
			got[strings.ToUpper(k)] = v
		}
		return got
	}
	// Before the helper has its parts, nothing in this test program has hidden these names: what is found
	// hidden afterwards is FromConfig's doing.
	before := names(collect.MinimalEnv())
	for name := range ofTheMachine {
		if _, there := before[strings.ToUpper(name)]; !there {
			t.Fatalf("%s is hidden before the helper read its config: the test shows nothing", name)
		}
	}

	_, closer, err := FromConfig(cfg, "v", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()

	check := func(what string, env []string) {
		t.Helper()
		got := names(env)
		for name, value := range ofTheMachine {
			if _, there := got[strings.ToUpper(name)]; there {
				t.Errorf("%s: a program the helper starts is handed %s", what, name)
			}
			if strings.Contains(strings.Join(env, "\n"), value) {
				t.Errorf("%s: a program the helper starts is handed the value of %s", what, name)
			}
		}
		for _, name := range []string{"HLPSEC_NOT_NAMED", "HLPSEC_HA_TOKEN_2", "HLPSEC_PLUG_NAME"} {
			if got[name] == "" {
				t.Errorf("%s: %s, which is no secret of a device, is not handed on any more", what, name)
			}
		}
		if _, there := got["PATH"]; !there && os.Getenv("PATH") != "" {
			t.Errorf("%s: PATH is not handed on any more", what)
		}
	}
	check("MinimalEnv", collect.MinimalEnv())
	check("Command (PowerShell for IPMI through Windows)", collect.Command(context.Background(), "true").Env)

	// Otherwise as before: the helper's own environment still has the variables, and env_file was not read (a
	// name that is only a line of that file is the agent's to hide, in the agent).
	for name, value := range ofTheMachine {
		if os.Getenv(name) != value {
			t.Errorf("%s is no longer in the helper's own environment", name)
		}
	}
	if v := os.Getenv("HLPSEC_IN_FILE"); v != "set-before" {
		t.Errorf("the helper read env_file: HLPSEC_IN_FILE is %q", v)
	}
	if _, set := os.LookupEnv("HLPSEC_ONLY_IN_FILE"); set {
		t.Error("the helper read env_file: HLPSEC_ONLY_IN_FILE is set")
	}
}
