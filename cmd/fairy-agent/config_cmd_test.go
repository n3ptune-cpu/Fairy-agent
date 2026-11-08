package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := configCmd(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestConfigCommand(t *testing.T) {
	if !isAdmin() {
		t.Skip("config set needs root / Administrator")
	}
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	orig := "# my settings\nipmi:\n  enabled: true          # BMC\n\nfan_control:\n  enabled: false\n"
	if err := os.WriteFile(p, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(strings.Repeat("r", 30)), 0o600); err != nil {
		t.Fatal(err)
	}
	read := func() string { b, _ := os.ReadFile(p); return string(b) }

	code, out, errs := run(t, "set", "fan_control.auto_mode", "standard", "--config", p)
	if code != 0 || !strings.Contains(out, "fan_control.auto_mode: not set, default optimal -> standard") || !strings.Contains(out, "restart") {
		t.Fatal(code, out, errs)
	}
	if read() != orig+"  auto_mode: standard\n" {
		t.Fatalf("%q", read())
	}
	if code, out, _ := run(t, "--config="+p, "get", "fan_control.auto_mode"); code != 0 || out != "standard\n" {
		t.Fatal(code, out)
	}
	if code, out, _ := run(t, "set", "fan_control.auto_mode", "standard", "--config", p); code != 0 || !strings.Contains(out, "nothing changed") {
		t.Fatal(code, out)
	}
	// invalid results are refused and nothing is written
	before := read()
	for _, c := range [][2]string{{"fan_control.min_duty", "20"}, {"fan_control.auto_mode", "turbo"}, {"listen", "0.0.0.0:9101"},
		{"power_control.enabled", "true"}, // needs a control-token file: check-config would fail
		{"fan_control.nope", "1"}, {"ipmi.enabled", "maybe"}} {
		code, _, errs := run(t, "set", c[0], c[1], "--config", p)
		if code != 1 || errs == "" || read() != before {
			t.Fatal(c, code, errs)
		}
	}
	if code, out, _ := run(t, "show", "--config", p); code != 0 || !strings.Contains(out, "ipmi.enabled: true\n") ||
		!strings.Contains(out, "processes.enabled: true\n") || !strings.Contains(out, "power_sources: (0 entries") {
		t.Fatal(code, out)
	}
	if code, _, _ := run(t, "frobnicate"); code != 2 {
		t.Fatal(code)
	}
	if code, _, _ := run(t, "set", "a"); code != 2 {
		t.Fatal(code)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Fatal(st.Mode())
	}
	// a config that is already broken in another way can still be fixed (with a note)
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs = run(t, "set", "fan_control.auto_mode", "heavyio", "--config", p)
	if code != 0 || !strings.Contains(out, "already had this problem") || !strings.Contains(read(), "auto_mode: heavyio") {
		t.Fatal(code, out, errs)
	}
}
