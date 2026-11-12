package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tuya was removed. check-config on a config.yaml that still has a Tuya entry says "config OK" and names the
// ignored entry in one line; it is not a problem and not an exit code. The other entries are still checked:
// the same file with a real mistake in another entry fails as before.
func TestCheckConfigNamesIgnoredTuyaEntry(t *testing.T) {
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	const old = `# written for an earlier version
fan_control:
  enabled: false
power_sources:
  - {id: shelly-1, type: shelly, url: "http://192.0.2.61"}
  - {id: desk-plug, type: tuya, name: "Desk plug", device_id: plug1, ip: 192.0.2.60, local_key_env: OLD_PLUG_KEY, version: "3.4", system_hint: self}
ups:
  - {id: local, host: 127.0.0.1}
`
	if err := os.WriteFile(p, []byte(old), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(strings.Repeat("r", 30)), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := checkConfigCmd(p, &out, &errb)
	want := "config OK: " + p + "\n" +
		`note: power source "desk-plug": tuya is no longer supported and is ignored (remove the entry from config.yaml, ` +
		`and the line OLD_PLUG_KEY=... from the env file: the plug's key is not used any more)` + "\n"
	if code != 0 || out.String() != want || errb.Len() != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out.String(), errb.String())
	}

	// `config show` reads the same file, and counts the entries the agent uses
	if code, text, errs := run(t, "show", "--config", p); code != 0 || !strings.Contains(text, "power_sources: (1 entries") || !strings.Contains(text, "fan_control.enabled: false\n") {
		t.Fatal(code, text, errs)
	}

	// without the old entry there is nothing to note
	if err := os.WriteFile(p, []byte(strings.Replace(old, "  - {id: desk-plug, type: tuya,", "  # - {id: desk-plug, type: tuya,", 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := checkConfigCmd(p, &out, &errb); code != 0 || out.String() != "config OK: "+p+"\n" || errb.Len() != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out.String(), errb.String())
	}

	// a mistake in another entry is still a problem, next to the old entry
	if err := os.WriteFile(p, []byte(strings.Replace(old, `url: "http://192.0.2.61"`, `url: "http://192.0.2.61", bogus: 1`, 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := checkConfigCmd(p, &out, &errb); code != 1 || out.Len() != 0 || !strings.Contains(errb.String(), "config problem:") || !strings.Contains(errb.String(), "bogus") {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out.String(), errb.String())
	}
}
