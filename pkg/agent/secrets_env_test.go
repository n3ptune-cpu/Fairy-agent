package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// Review of the Home Assistant source (F1): a device secret that is in the service's own environment, not in
// env_file, was handed to every program the agent starts, because only the names of env_file's lines (and the
// BMC's) were hidden. Now every variable that a power_sources or ups entry names in a member ending in "_env"
// is hidden, wherever its value came from; so is one that only an ignored (tuya) entry named. Every other
// variable is passed on as before.
func TestDeviceSecretsOfTheEnvironmentAreNotHandedToChildPrograms(t *testing.T) {
	secret := func(words ...string) string { return strings.Join(words, "-") } // made up, put together here
	fromEnvironment := map[string]string{
		"ENVSEC_HA_TOKEN":   secret("ha", "token", "of", "the", "service"), // token_env of a homeassistant entry
		"ENVSEC_SHELLY_PW":  secret("shelly", "password"),                  // password_env of a plug
		"envsec_tasmota_pw": secret("tasmota", "password"),                 // named in capitals in config.yaml
		"ENVSEC_UPS_PW":     secret("ups", "password"),                     // password_env of a ups entry
		"ENVSEC_OLD_KEY":    secret("tuya", "local", "key"),                // only an ignored entry names it
	}
	for name, value := range fromEnvironment {
		t.Setenv(name, value)
	}
	t.Setenv("ENVSEC_NOT_NAMED", "stays")      // nothing in config.yaml names it
	t.Setenv("ENVSEC_HA_TOKEN_2", "stays")     // a longer name than a hidden one
	t.Setenv("ENVSEC_IN_FILE", "set-before")   // a line of env_file: hidden as before
	t.Setenv("ENVSEC_PLUG_NAME", "not-hidden") // the value of a `name:` member: not a member ending in "_env"
	dir := t.TempDir()
	envFile := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(envFile, []byte("ENVSEC_IN_FILE=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]byte(`env_file: `+envFile+`
power_sources:
  - {id: desk-plug, type: homeassistant, url: "http://192.0.2.10:8123", token_env: ENVSEC_HA_TOKEN, entity: sensor.desk_plug_power}
  - {id: shelly-1, type: shelly, name: ENVSEC_PLUG_NAME, url: "http://192.0.2.11", password_env: ENVSEC_SHELLY_PW}
  - {id: tasmota-1, type: tasmota, url: "http://192.0.2.12", password_env: ENVSEC_TASMOTA_PW}
  - {id: old-plug, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: ENVSEC_OLD_KEY}
ups:
  - {id: rack, host: 192.0.2.71, username: monuser, password_env: ENVSEC_UPS_PW}
`), filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := loadSecrets(cfg); err != nil {
		t.Fatal(err)
	}
	for name, value := range fromEnvironment { // the agent itself still has them: it reads them for its requests
		if os.Getenv(name) != value {
			t.Errorf("%s is no longer in the agent's own environment", name)
		}
	}

	check := func(what string, env []string) {
		t.Helper()
		got := map[string]string{}
		for _, kv := range env {
			k, v, _ := strings.Cut(kv, "=")
			got[k] = v
			for name, value := range fromEnvironment {
				if strings.EqualFold(k, name) || strings.Contains(kv, value) {
					t.Errorf("%s: a program the agent starts is handed %s", what, name)
				}
			}
		}
		if _, there := got["ENVSEC_IN_FILE"]; there {
			t.Errorf("%s: a name of env_file is handed on", what)
		}
		for _, name := range []string{"ENVSEC_NOT_NAMED", "ENVSEC_HA_TOKEN_2", "ENVSEC_PLUG_NAME"} {
			if _, there := got[name]; !there {
				t.Errorf("%s: %s, which is no secret of a device, is not handed on any more", what, name)
			}
		}
		if _, there := got["PATH"]; !there && os.Getenv("PATH") != "" {
			t.Errorf("%s: PATH is not handed on any more", what)
		}
	}
	check("MinimalEnv (ipmitool, nvidia-smi)", collect.MinimalEnv())
	check("Command (systemctl, busctl, PowerShell)", collect.Command(context.Background(), "true").Env)

	// a real child process, where there is a program that prints its environment
	if envProg, err := exec.LookPath("env"); err == nil {
		out, err := collect.Command(context.Background(), envProg).Output()
		if err != nil {
			t.Fatal(err)
		}
		check("a child process", strings.Split(strings.TrimSpace(string(out)), "\n"))
	}
}
