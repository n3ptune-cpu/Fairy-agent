package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// check-config's line for a Home Assistant source names the sensors of the optional values (voltage_entity,
// current_entity, energy_entity) after the power sensor, each with its word; a source without them has the
// line it always had. A member that is not a sensor's id, or that names a sensor twice, is a config problem
// in fixed words, with exit code 1.
func TestCheckConfigNamesTheExtraSensors(t *testing.T) {
	const env = "CHECK_TEST_HA_EXTRAS_TOKEN"
	if _, set := os.LookupEnv(env); set {
		t.Skip(env + " is set in this environment")
	}
	t.Cleanup(func() { os.Unsetenv(env) }) // check-config loads env_file into this process
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	tok := strings.Join([]string{"fake", "ha", "token", "for", "tests"}, "-") // made up, put together here
	dir := t.TempDir()
	p, envFile := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "secrets.env")
	conf := `env_file: ` + envFile + `
power_sources:
  - id: lab-plug
    type: homeassistant
    url: "http://192.0.2.10:8123"
    token_env: ` + env + `
    entity: sensor.lab_plug_power
    voltage_entity: sensor.lab_plug_voltage
    current_entity: sensor.lab_plug_current
    energy_entity: sensor.lab_plug_energy
  - {id: shed-plug, type: homeassistant, url: "https://ha.example.net/", token_env: ` + env + `, entity: sensor.shed_plug_power, energy_entity: sensor.shed_plug_energy}
  - {id: bare-plug, type: homeassistant, url: "http://192.0.2.10:8123", token_env: ` + env + `, entity: sensor.bare_plug_power}
`
	for path, text := range map[string]string{p: conf, envFile: env + "=" + tok + "\n", filepath.Join(dir, "token"): strings.Repeat("r", 30)} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out, errb bytes.Buffer
	code := checkConfigCmd(p, &out, &errb)
	want := "config OK: " + p + "\n" +
		`power source "lab-plug": homeassistant, host 192.0.2.10:8123 (http), sensor.lab_plug_power, voltage sensor.lab_plug_voltage, ` +
		`current sensor.lab_plug_current, energy sensor.lab_plug_energy, token: present (` + env + `)` + "\n" +
		`power source "shed-plug": homeassistant, host ha.example.net (https), sensor.shed_plug_power, energy sensor.shed_plug_energy, token: present (` + env + `)` + "\n" +
		`power source "bare-plug": homeassistant, host 192.0.2.10:8123 (http), sensor.bare_plug_power, token: present (` + env + `)` + "\n"
	if code != 0 || out.String() != want || errb.Len() != 0 {
		t.Fatalf("exit %d\nstdout: %s\nwant:   %s\nstderr: %s", code, out.String(), want, errb.String())
	}
	if strings.Contains(out.String()+errb.String(), tok) {
		t.Fatal("check-config shows the token")
	}

	for bad, word := range map[string]string{
		"voltage_entity: switch.lab_plug": "config problem: power source lab-plug: voltage_entity must be the entity id of a sensor, like sensor.desk_plug_voltage " +
			"(only sensor.* is read); leave the member out when the plug has no such sensor\n",
		"voltage_entity: \"\"": "config problem: power source lab-plug: voltage_entity must be the entity id of a sensor, like sensor.desk_plug_voltage " +
			"(only sensor.* is read); leave the member out when the plug has no such sensor\n",
		"voltage_entity: sensor.lab_plug_current":                                          "config problem: power source lab-plug: current_entity names the same sensor as voltage_entity: each value has a sensor of its own\n",
		"voltage_entity: sensor.lab_plug_power":                                            "config problem: power source lab-plug: voltage_entity names the same sensor as entity: each value has a sensor of its own\n",
		"voltage_entity: sensor.lab_plug_voltage\n    power_entity: sensor.lab_plug_power": "config problem: power source lab-plug: field power_entity not found (a homeassistant entry has no such member)\n",
	} {
		broken := strings.Replace(conf, "voltage_entity: sensor.lab_plug_voltage", bad, 1)
		if err := os.WriteFile(p, []byte(broken), 0o600); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		errb.Reset()
		if code := checkConfigCmd(p, &out, &errb); code != 1 || out.Len() != 0 || errb.String() != word {
			t.Errorf("%s: exit %d\nstdout: %s\nstderr: %s\nwant:   %s", bad, code, out.String(), errb.String(), word)
		}
	}
}
