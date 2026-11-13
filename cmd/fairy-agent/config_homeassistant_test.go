package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// check-config has one line for every Home Assistant power source: its id, the type, the host, the sensor, and
// whether the token's variable has a value (from env_file, or from the environment). The token itself is in
// no line, and a missing token is said, not an exit code. Other sources have no such line.
func TestCheckConfigHomeAssistantLines(t *testing.T) {
	const present, missing = "CHECK_TEST_HA_TOKEN", "CHECK_TEST_HA_TOKEN_2"
	for _, n := range []string{present, missing} {
		if _, set := os.LookupEnv(n); set {
			t.Skip(n + " is set in this environment")
		}
		t.Cleanup(func() { os.Unsetenv(n) }) // check-config loads env_file into this process
	}
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	tok := strings.Join([]string{"fake", "ha", "token", "for", "tests"}, "-") // made up, put together here
	dir := t.TempDir()
	p, env := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "secrets.env")
	conf := `env_file: ` + env + `
power_sources:
  - {id: shelly-1, type: shelly, url: "http://192.0.2.61", password_env: CHECK_TEST_SHELLY_PW}
  - {id: desk-plug, type: homeassistant, name: "Desk plug", url: "http://192.0.2.10:8123", token_env: ` + present + `, entity: sensor.desk_plug_power, system_hint: self}
  - {id: rack-plug, type: homeassistant, url: "https://ha.example.net/", token_env: ` + missing + `, entity: sensor.rack_plug_power, max_age_s: 900}
`
	for path, text := range map[string]string{p: conf, env: "# secrets\n" + present + "=" + tok + "\n", filepath.Join(dir, "token"): strings.Repeat("r", 30)} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out, errb bytes.Buffer
	code := checkConfigCmd(p, &out, &errb)
	want := "config OK: " + p + "\n" +
		`power source "desk-plug": homeassistant, host 192.0.2.10:8123 (http), sensor.desk_plug_power, token: present (` + present + `)` + "\n" +
		`power source "rack-plug": homeassistant, host ha.example.net (https), sensor.rack_plug_power, token: missing (` + missing +
		` is not set: fairy-agent secret set ` + missing + `, then restart the agent)` + "\n"
	if code != 0 || out.String() != want || errb.Len() != 0 {
		t.Fatalf("exit %d\nstdout: %s\nwant:   %s\nstderr: %s", code, out.String(), want, errb.String())
	}
	if strings.Contains(out.String()+errb.String(), tok) {
		t.Fatal("check-config shows the token")
	}

	// a token_env that another setting names for its own secret, or that is a variable of the system, is a
	// config problem: fixed words, the two entries by id, no variable's name and no token
	for bad, word := range map[string]string{
		"token_env: " + present: "config problem: power source desk-plug: token_env names the same variable as password_env of power source shelly-1: " +
			"what that variable holds would be sent to Home Assistant as the token. The token needs a variable that nothing else names\n",
		"token_env: " + missing: "config problem: power source rack-plug: token_env must not be a variable of the system (PATH, HOME, TEMP, TMP, SystemRoot, USERPROFILE): " +
			"the variable named there is used for nothing but the token and is hidden from the programs the agent starts\n",
	} {
		broken := strings.Replace(conf, "password_env: CHECK_TEST_SHELLY_PW", "password_env: "+strings.ToLower(present), 1)
		if strings.HasSuffix(bad, missing) {
			broken = strings.Replace(conf, bad, "token_env: Path", 1)
		}
		if err := os.WriteFile(p, []byte(broken), 0o600); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		errb.Reset()
		if code := checkConfigCmd(p, &out, &errb); code != 1 || out.Len() != 0 || errb.String() != word {
			t.Errorf("%s: exit %d\nstdout: %s\nstderr: %s\nwant:   %s", bad, code, out.String(), errb.String(), word)
		}
	}

	// an entry that is not a sensor is a config problem, named without the entry's secrets
	for bad, word := range map[string]string{
		"entity: switch.desk_plug":                      "entity must be",
		"entity: sensor.desk_plug_power, token: " + tok: "field token not found",
	} {
		broken := strings.Replace(conf, "entity: sensor.desk_plug_power", bad, 1)
		if err := os.WriteFile(p, []byte(broken), 0o600); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		errb.Reset()
		if code := checkConfigCmd(p, &out, &errb); code != 1 || out.Len() != 0 || !strings.Contains(errb.String(), "config problem:") ||
			!strings.Contains(errb.String(), word) || strings.Contains(errb.String(), tok) {
			t.Errorf("%s: exit %d\nstdout: %s\nstderr: %s", word, code, out.String(), errb.String())
		}
	}
}
