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

// Second review of ha1: the Windows helper hides the same names with HideDeviceSecrets, which the agent's
// loadSecrets now calls too. For one config, written twice with two families of names, HideDeviceSecrets alone
// hides exactly what loadSecrets hides of the names config.yaml gives: every "_env" member of a power_sources
// or ups entry, the one of an ignored entry, ipmi.password_env and the BMC relay targets' password_env. What
// it leaves to loadSecrets is env_file: it reads no file, so no line of it is loaded and no name that is only
// a line of it is hidden.
func TestHideDeviceSecretsHidesTheNamesLoadSecretsHides(t *testing.T) {
	suffixes := []string{"HA_TOKEN", "SHELLY_PW", "TASMOTA_PW", "REDFISH_PW", "NUT_PW", "UPS_PW", "OLD_KEY", "IPMI_PW", "RELAY_PW", "RELAY2_PW",
		"NOT_NAMED", "PLUG_NAME", "IN_FILE"}
	dir := t.TempDir()
	config := func(family string) *Config {
		t.Helper()
		for _, s := range suffixes {
			t.Setenv(family+s, "x")
		}
		os.Unsetenv(family + "IN_FILE") // only a line of env_file
		envFile := filepath.Join(dir, family+"secrets.env")
		if err := os.WriteFile(envFile, []byte(family+"IN_FILE=x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Parse([]byte(strings.ReplaceAll(`env_file: '`+envFile+`'
ipmi: {enabled: true, transport: ipmitool, host: 192.168.1.5, username: u, password_env: F_IPMI_PW}
bmc_relay:
  enabled: true
  targets:
    - {id: a, host: 192.168.1.6, username: u, password_env: F_RELAY_PW}
    - {id: b, host: 192.168.1.7, username: u, password_env: F_RELAY2_PW}
power_sources:
  - {id: desk-plug, type: homeassistant, url: "http://192.0.2.10:8123", token_env: F_HA_TOKEN, entity: sensor.desk_plug_power}
  - {id: shelly-1, type: shelly, name: F_PLUG_NAME, url: "http://192.0.2.11", password_env: F_SHELLY_PW}
  - {id: tasmota-1, type: tasmota, url: "http://192.0.2.12", password_env: F_TASMOTA_PW}
  - {id: bmc-1, type: redfish, url: "https://192.0.2.13", username: u, password_env: F_REDFISH_PW}
  - {id: nut-1, type: nut, host: 192.0.2.14, ups: rack, username: u, password_env: F_NUT_PW}
  - {id: old-plug, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: F_OLD_KEY}
ups:
  - {id: rack, host: 192.0.2.71, username: monuser, password_env: F_UPS_PW}
`, "F_", family)), filepath.Join(dir, family+"config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	hidden := func(family string) string { // the suffixes of the family's names that a child program does not get
		got := map[string]bool{}
		for _, kv := range collect.MinimalEnv() {
			k, _, _ := strings.Cut(kv, "=")
			got[k] = true
		}
		var out []string
		for _, s := range suffixes {
			if !got[family+s] {
				out = append(out, s)
			}
		}
		return strings.Join(out, " ")
	}

	agentCfg, helperCfg := config("HDSA_"), config("HDSH_")
	if h := hidden("HDSA_") + hidden("HDSH_"); h != "IN_FILEIN_FILE" { // not set yet, so not in any environment
		t.Fatalf("hidden before anything was called: %s", h)
	}
	if err := loadSecrets(agentCfg); err != nil {
		t.Fatal(err)
	}
	HideDeviceSecrets(helperCfg)

	const named = "HA_TOKEN SHELLY_PW TASMOTA_PW REDFISH_PW NUT_PW UPS_PW OLD_KEY IPMI_PW RELAY_PW RELAY2_PW"
	if got := hidden("HDSA_"); got != named+" IN_FILE" {
		t.Errorf("loadSecrets hides\n\t%s, want\n\t%s IN_FILE", got, named)
	}
	if got := hidden("HDSH_"); got != named+" IN_FILE" { // IN_FILE: still not set, HideDeviceSecrets read no file
		t.Errorf("HideDeviceSecrets hides\n\t%s, want\n\t%s (and IN_FILE, which is not set)", got, named)
	}
	if os.Getenv("HDSA_IN_FILE") != "x" {
		t.Error("loadSecrets did not read env_file")
	}
	if _, set := os.LookupEnv("HDSH_IN_FILE"); set {
		t.Error("HideDeviceSecrets read env_file")
	}
	// A name that is only a line of env_file: hidden by loadSecrets, not by HideDeviceSecrets.
	t.Setenv("HDSA_IN_FILE", "x")
	t.Setenv("HDSH_IN_FILE", "x")
	if a, h := hidden("HDSA_"), hidden("HDSH_"); a != named+" IN_FILE" || h != named {
		t.Errorf("with both IN_FILE variables set, hidden are\n\t%s (loadSecrets), want %s IN_FILE\n\t%s (HideDeviceSecrets), want %s", a, named, h, named)
	}
}
