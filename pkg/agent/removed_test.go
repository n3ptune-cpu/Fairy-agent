package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

const ignoredTuya = `power source "desk-plug": tuya is no longer supported and is ignored`

// oldTuyaConfig is a config.yaml as an earlier version accepted it: a Tuya plug (the line of the old example
// file, with a data-point mapping) between a Shelly plug and a UPS power source, a UPS, an env file that still
// holds the plug's key, and settings of other sections.
func oldTuyaConfig(t *testing.T, shellyURL string, upsdPort int) string {
	t.Helper()
	env := filepath.Join(t.TempDir(), "devices.env")
	if err := os.WriteFile(env, []byte("OLD_PLUG_KEY=not-a-real-key\nOLD_SHELLY_PW=not-real\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Unsetenv("OLD_PLUG_KEY"); os.Unsetenv("OLD_SHELLY_PW") })
	return fmt.Sprintf(`control_rate_per_min: 7
processes: {enabled: false}
gpu: {nvidia_smi: "off", amdgpu: "off"}
env_file: %q
power_sources:
  - {id: shelly-1, type: shelly, url: %q, gen: "2", password_env: OLD_SHELLY_PW, system_hint: self}
  - {id: desk-plug, type: tuya, name: "Desk plug", device_id: plug1, ip: 192.0.2.60, local_key_env: OLD_PLUG_KEY, version: "3.4", system_hint: self, dps: {power: {dp: "19", scale: 0.1}}, refresh_dps: [18, 19]}
  - {id: ups-power, type: nut, host: 127.0.0.1, port: %d, ups: cp}
ups:
  - {id: rack, host: 127.0.0.1, port: %d}
`, env, shellyURL, upsdPort, upsdPort)
}

// Tuya was removed. A config.yaml that still has a Tuya entry loads: the entry is left out and named in one
// line, and everything else in the file works as before (the other devices are read, the other settings hold).
func TestOldTuyaEntryIsIgnoredAndTheRestWorks(t *testing.T) {
	shelly := fakePlug(t, `{"apower":95.5,"voltage":229.8,"current":0.41,"aenergy":{"total":12000}}`)
	port := fakeUpsd(t, map[string]string{"ups.status": "OL", "battery.charge": "100", "ups.realpower": "120", "input.voltage": "230"})
	cfg := mustParse(t, oldTuyaConfig(t, shelly, port))
	if got := cfg.Ignored(); len(got) != 1 || !strings.HasPrefix(got[0], ignoredTuya) {
		t.Fatalf("Ignored: %q", got)
	}
	if len(cfg.PowerSources) != 2 || cfg.PowerSources[0]["id"] != "shelly-1" || cfg.PowerSources[1]["id"] != "ups-power" ||
		len(cfg.UPS) != 1 || cfg.ControlRatePerMin != 7 || cfg.ProcessesEnabled() {
		t.Fatalf("the rest of the config: power_sources %v, ups %v, rate %d", cfg.PowerSources, cfg.UPS, cfg.ControlRatePerMin)
	}
	if _, err := LoadEnvFile(cfg.EnvFile); err != nil { // the plug's old key may stay in the env file
		t.Fatal(err)
	}
	relay, err := NewRelay(cfg.PowerSources, cfg.UPS)
	if err != nil {
		t.Fatal("the agent would not start:", err)
	}
	relay.PollOnce(context.Background())
	st, body := agentWithRelay(t, relay)("/metrics")
	var m map[string]any
	if st != 200 || json.Unmarshal(body, &m) != nil {
		t.Fatalf("/metrics: status %d, body %.200s", st, body)
	}
	ps, _ := m["power_sources"].([]any)
	us, _ := m["ups"].([]any)
	if len(ps) != 2 || len(us) != 1 {
		t.Fatalf("power_sources %v, ups %v", m["power_sources"], m["ups"])
	}
	sh, nut, rack := ps[0].(map[string]any), ps[1].(map[string]any), us[0].(map[string]any)
	if sh["id"] != "shelly-1" || sh["ok"] != true || sh["watts"] != 95.5 || sh["system_hint"] != "self" {
		t.Errorf("shelly row: %v", sh)
	}
	if nut["id"] != "ups-power" || nut["ok"] != true || nut["watts"] != 120.0 {
		t.Errorf("nut row: %v", nut)
	}
	if rack["name"] != "cp" || rack["ok"] != true || rack["state"] != "online" {
		t.Errorf("ups row: %v", rack)
	}
	if strings.Contains(string(body), "desk-plug") {
		t.Errorf("the ignored entry is in /metrics: %.300s", body)
	}
}

// Whatever the old entry holds, it is only ignored: a key that was never valid, a missing id, the id of
// another entry, a scale that is not a number, a key that is not in the environment. None of them stops Parse
// or NewRelay, and a file without such an entry has nothing to say.
func TestOldTuyaEntryNeverStopsTheConfig(t *testing.T) {
	for name, entry := range map[string]string{
		"as the old example":   `{id: desk-plug, type: tuya, name: "Desk plug", device_id: plug1, ip: 192.0.2.60, local_key_env: NOT_SET_ANYWHERE, version: "3.4", system_hint: self}`,
		"only the type":        `{type: tuya}`,
		"unknown keys":         `{id: desk-plug, type: tuya, color: blue, port: 6668}`,
		"bad version":          `{id: desk-plug, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: K, version: "9.9"}`,
		"scale not a number":   `{id: desk-plug, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: K, dps: {power: {dp: "19", scale: .nan}}}`,
		"interval not allowed": `{id: desk-plug, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: K, interval: 0}`,
		"id of another entry":  `{id: other, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: K}`,
		"an id that is none":   `{id: "Not An Id!", type: tuya}`,
	} {
		for _, y := range []string{
			"power_sources:\n  - " + entry + "\n",
			"power_sources:\n  - {id: other, type: tasmota, url: \"http://192.0.2.1\"}\n  - " + entry + "\n",
			"power_sources:\n  - " + entry + "\n  - " + entry + "\n  - {id: other, type: shelly, url: \"http://192.0.2.1\"}\n",
		} {
			cfg, err := Parse([]byte(y), "config.yaml")
			if err != nil {
				t.Errorf("%s: Parse: %v\n%s", name, err, y)
				continue
			}
			n := strings.Count(y, "type: tuya")
			if got := cfg.Ignored(); len(got) != n {
				t.Errorf("%s: %d old entries, lines: %q", name, n, got)
			}
			for _, line := range cfg.Ignored() {
				if !strings.Contains(line, "tuya is no longer supported and is ignored") || !strings.HasPrefix(line, "power source ") {
					t.Errorf("%s: line %q", name, line)
				}
			}
			relay, err := NewRelay(cfg.PowerSources, cfg.UPS)
			if err != nil {
				t.Errorf("%s: NewRelay: %v\n%s", name, err, y)
				continue
			}
			if want := strings.Count(y, "id: other, type: tasmota") + strings.Count(y, "id: other, type: shelly"); len(relay.sources) != want {
				t.Errorf("%s: %d sources, want %d\n%s", name, len(relay.sources), want, y)
			}
		}
	}
	for _, y := range []string{"", "power_sources: []\n", "power_sources:\n  - {id: other, type: tasmota, url: \"http://192.0.2.1\"}\n"} {
		if cfg, err := Parse([]byte(y), "config.yaml"); err != nil || len(cfg.Ignored()) != 0 {
			t.Errorf("%q: %v, lines %q", y, err, cfg.Ignored())
		}
	}
	// the loader is as strict as before about everything else: an unknown type and an unknown key still fail
	for y, want := range map[string]string{
		"power_sources: [{id: p, type: zigbee}]":                              "unknown type",
		"power_sources: [{id: p, type: shelly, url: 'http://a', bogus: 1}]":   "bogus",
		"power_sources: [{id: p, type: Tuya, device_id: d}]":                  "unknown type",
		"tuya: {enabled: true}":                                               "tuya",
		"power_sources: [{id: p, type: shelly, url: 'http://a'}]\nbogus: 1\n": "bogus",
	} {
		cfg, err := Parse([]byte(y), "config.yaml")
		if err == nil {
			_, err = NewRelay(cfg.PowerSources, cfg.UPS)
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error naming %q", y, err, want)
		}
	}
}

// The real Run with such a config starts, serves, reads the other devices, and says once in its log which
// entry it ignores.
func TestRunStartsWithOldTuyaEntryAndWarns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Run looks for the helper service on Windows")
	}
	logs := captureLog(t)
	shelly := fakePlug(t, `{"apower":95.5,"voltage":229.8,"current":0.41,"aenergy":{"total":12000}}`)
	port := fakeUpsd(t, map[string]string{"ups.status": "OL", "battery.charge": "100", "ups.realpower": "120", "input.voltage": "230"})
	t.Setenv("FAIRY_AGENT_TOKEN", readTok)
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	addr := freeAddr(t)
	cfg := mustParse(t, "listen: "+addr+"\n"+oldTuyaConfig(t, shelly, port))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, Build{Version: "test"}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("Run:", err)
			}
		case <-time.After(20 * time.Second):
			t.Error("Run did not stop")
		}
	})
	var rows []any
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		select {
		case err := <-done:
			done <- err
			t.Fatal("Run ended early:", err)
		default:
		}
		req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+readTok)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var m map[string]any
			if resp.StatusCode == 200 && json.Unmarshal(body, &m) == nil {
				if rows, _ = m["power_sources"].([]any); len(rows) == 2 {
					break
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no /metrics with both devices in time: %v\n%s", rows, logs.String())
		}
	}
	if a, b := rows[0].(map[string]any), rows[1].(map[string]any); a["id"] != "shelly-1" || a["ok"] != true || b["id"] != "ups-power" {
		t.Errorf("rows: %v", rows)
	}
	log := logs.String()
	if strings.Count(log, "tuya is no longer supported and is ignored") != 1 {
		t.Fatalf("want the line once in the log:\n%s", log)
	}
	// audit 5, r1-a2-06: the line names the variable of the plug's key, never its value, and the running agent
	// does not hold the key in its environment; the secret of the plug that is still read is there
	if !strings.Contains(log, "the line OLD_PLUG_KEY=... from the env file") || strings.Contains(log, "not-a-real-key") {
		t.Errorf("the log must name the key's variable and never its value:\n%s", log)
	}
	if v, set := os.LookupEnv("OLD_PLUG_KEY"); set {
		t.Errorf("the agent loaded the removed plug's key into its environment (%d bytes)", len(v))
	}
	if os.Getenv("OLD_SHELLY_PW") != "not-real" {
		t.Error("the secret of a device that is still read was not loaded")
	}
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "tuya is no longer supported") &&
			(!strings.Contains(line, "level=WARN") || !strings.Contains(line, `power source \"desk-plug\"`) || !strings.Contains(line, "config.yaml")) {
			t.Errorf("log line: %s", line)
		}
	}
}

// TestOldTuyaKeyIsNotLoadedIntoTheEnvironment (audit 5, r1-a2-06): the plug's local key stays in env_file after
// the upgrade, and the agent used to load it into its environment at every start, for nothing. A secret that
// only an ignored entry names is not loaded any more. Everything else is: a variable that a kept entry names
// too, the agent's own variables, and a variable that was in the environment before the agent looked.
func TestOldTuyaKeyIsNotLoadedIntoTheEnvironment(t *testing.T) {
	for _, n := range []string{"OLD_PLUG_KEY", "SHARED_PW", "OTHER_SECRET", "INHERITED_KEY", "FAIRY_AGENT_TOKEN_TEST"} {
		os.Unsetenv(n)
		t.Cleanup(func() { os.Unsetenv(n) })
	}
	env := filepath.Join(t.TempDir(), "devices.env")
	if err := os.WriteFile(env, []byte("OLD_PLUG_KEY=key-of-the-old-plug\nSHARED_PW=shared\nOTHER_SECRET=other\nINHERITED_KEY=from-the-file\n"+
		"FAIRY_AGENT_TOKEN_TEST=agents-own\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INHERITED_KEY", "from-the-service")
	cfg := mustParse(t, fmt.Sprintf(`env_file: %q
power_sources:
  - {id: desk-plug, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: OLD_PLUG_KEY}
  - {id: second-plug, type: tuya, device_id: plug2, ip: 192.0.2.61, local_key_env: SHARED_PW}
  - {id: third-plug, type: tuya, device_id: plug3, ip: 192.0.2.62, local_key_env: INHERITED_KEY}
  - {id: odd-plug, type: tuya, device_id: plug4, ip: 192.0.2.63, local_key_env: FAIRY_AGENT_TOKEN_TEST}
  - {id: shelly-1, type: shelly, url: "http://192.0.2.70", gen: "2", password_env: shared_pw}
`, env))
	if !cfg.UnusedSecret("OLD_PLUG_KEY") || !cfg.UnusedSecret("old_plug_key") || cfg.UnusedSecret("SHARED_PW") || cfg.UnusedSecret("OTHER_SECRET") ||
		cfg.UnusedSecret("FAIRY_AGENT_TOKEN_TEST") || cfg.UnusedSecret("") {
		t.Fatal("which secrets count as unused is wrong")
	}
	if err := loadSecrets(cfg); err != nil {
		t.Fatal(err)
	}
	if v, set := os.LookupEnv("OLD_PLUG_KEY"); set {
		t.Errorf("the removed plug's key is in the agent's environment (%d bytes)", len(v))
	}
	for name, want := range map[string]string{
		"SHARED_PW":              "shared",           // a kept entry names it too (in another letter case)
		"OTHER_SECRET":           "other",            // nothing to do with a removed entry
		"INHERITED_KEY":          "from-the-service", // was set before: not the file's to give, not the agent's to take
		"FAIRY_AGENT_TOKEN_TEST": "agents-own",       // the agent's own names are never left out
	} {
		if got := os.Getenv(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	// every line of the env file is still checked, and a child process sees none of its names
	for _, kv := range collect.MinimalEnv() {
		if k, _, _ := strings.Cut(kv, "="); k == "OLD_PLUG_KEY" || k == "INHERITED_KEY" || k == "SHARED_PW" {
			t.Errorf("a child process would get %s", k)
		}
	}
	if err := os.WriteFile(env, []byte("OLD_PLUG_KEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadSecrets(cfg); err == nil {
		t.Error("a broken line of an unused secret was not reported")
	}
}
