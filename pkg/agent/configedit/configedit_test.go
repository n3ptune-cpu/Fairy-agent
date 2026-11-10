package configedit

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

func set(t *testing.T, in, key, value string) string {
	t.Helper()
	s, err := Lookup(key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseValue(s, value)
	if err != nil {
		t.Fatal(err)
	}
	out, _, _, err := Edit([]byte(in), s, v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestEdit(t *testing.T) {
	for _, tc := range []struct{ name, in, key, value, want string }{
		{"scalar, comment stays in its column",
			"fan_control:\n  enabled: false\n  auto_mode: optimal           # the BMC mode\n\n# next\nwol: {}\n",
			"fan_control.auto_mode", "standard",
			"fan_control:\n  enabled: false\n  auto_mode: standard          # the BMC mode\n\n# next\nwol: {}\n"},
		{"longer value keeps one space before the comment",
			"ipmi:\n  enabled: true  # BMC\n", "ipmi.enabled", "false", "ipmi:\n  enabled: false # BMC\n"},
		{"top level", "control_rate_per_min: 12       # all\n", "control_rate_per_min", "30", "control_rate_per_min: 30       # all\n"},
		{"flow mapping: replace", "fan_control: {enabled: true, auto_mode: optimal}\n", "fan_control.auto_mode", "standard",
			"fan_control: {enabled: true, auto_mode: standard}\n"},
		{"flow mapping: add", "ipmi: {enabled: true}\nfan_control: {enabled: true }\n", "fan_control.auto_mode", "standard",
			"ipmi: {enabled: true}\nfan_control: {enabled: true, auto_mode: standard }\n"},
		{"empty flow mapping", "wol: {}\n", "wol.enabled", "true", "wol: {enabled: true}\n"},
		{"missing key: after the section's last line",
			"fan_control:\n  enabled: true\n  min_duty: 40   # c\n\n# Shutdown\npower_control:\n  enabled: false\n",
			"fan_control.auto_mode", "standard",
			"fan_control:\n  enabled: true\n  min_duty: 40   # c\n  auto_mode: standard\n\n# Shutdown\npower_control:\n  enabled: false\n"},
		{"missing section: appended", "# hello\nlisten: 100.64.0.10:9101\n", "sensors.coretemp", "true",
			"# hello\nlisten: 100.64.0.10:9101\nsensors:\n  coretemp: true\n"},
		{"missing section, no final newline", "listen: 100.64.0.10:9101", "fan_control.min_duty", "35",
			"listen: 100.64.0.10:9101\nfan_control:\n  min_duty: 35\n"},
		{"empty section with commented examples", "sensors:\n#   acpi_thermal: true\n#   coretemp: false\nipmi:\n  enabled: true\n",
			"sensors.coretemp", "true", "sensors:\n  coretemp: true\n#   acpi_thermal: true\n#   coretemp: false\nipmi:\n  enabled: true\n"},
		{"explicit null section", "sensors: ~\n", "sensors.coretemp", "true", "sensors: {coretemp: true}\n"},
		{"empty value", "self_update:\n  repo:\n  enabled: false\n", "self_update.repo", "me/fork", "self_update:\n  repo: me/fork\n  enabled: false\n"},
		{"empty file", "", "fan_control.auto_mode", "standard", "fan_control:\n  auto_mode: standard\n"},
		{"comments only", "# nothing yet\n", "wol.enabled", "true", "# nothing yet\nwol:\n  enabled: true\n"},
		{"4-space indentation", "fan_control:\n    enabled: true\n", "fan_control.min_duty", "50", "fan_control:\n    enabled: true\n    min_duty: 50\n"},
		{"CRLF line endings stay", "# c\r\nfan_control:\r\n  enabled: true\r\n\r\nwol: {}\r\n", "fan_control.auto_mode", "standard",
			"# c\r\nfan_control:\r\n  enabled: true\r\n  auto_mode: standard\r\n\r\nwol: {}\r\n"},
		{"CRLF replace", "ipmi:\r\n  enabled: false\r\n", "ipmi.enabled", "true", "ipmi:\r\n  enabled: true\r\n"},
		{"byte order mark", "\ufefffan_control: {enabled: true}\n", "fan_control.auto_mode", "standard",
			"\ufefffan_control: {enabled: true, auto_mode: standard}\n"},
		{"quoted value", "self_update:\n  repo: \"a/b\"  # fork\n", "self_update.repo", "c/d", "self_update:\n  repo: c/d    # fork\n"},
		{"string that needs quotes", "log_file: x\n", "log_file", `C:\ProgramData\fairy-agent\logs\agent.log`,
			"log_file: \"C:\\\\ProgramData\\\\fairy-agent\\\\logs\\\\agent.log\"\n"},
		{"plain string", "gpu:\n  nvidia_smi: auto\n", "gpu.nvidia_smi", "off", "gpu:\n  nvidia_smi: off\n"},
		{"string that looks like a number", "self_update: {}\n", "self_update.repo", "123", "self_update: {repo: \"123\"}\n"},
		{"float", "fan_control:\n  max_temp_c: 80\n", "fan_control.max_temp_c", "77.5", "fan_control:\n  max_temp_c: 77.5\n"},
		{"flow list", "wol:\n  allowed_macs: []   # any\n", "wol.allowed_macs", "aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66",
			"wol:\n  allowed_macs: [\"aa:bb:cc:dd:ee:ff\", \"11:22:33:44:55:66\"]   # any\n"},
		{"block list becomes a flow list", "processes:\n  never_open:   # games\n    - a.exe\n    # b\n    - b.exe\n  cmdline: false\n",
			"processes.never_open", "[x.exe]", "processes:\n  never_open: [x.exe] # games\n  cmdline: false\n"},
		{"block list at the end", "processes:\n  never_open:\n    - a.exe\n", "processes.never_open", "", "processes:\n  never_open: []\n"},
		{"pointer bool", "processes:\n  cmdline: true\n", "processes.cmdline", "FALSE", "processes:\n  cmdline: false\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := set(t, tc.in, tc.key, tc.value); got != tc.want {
				t.Fatalf("got\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

// The shipped example config: one line changes, every comment and blank line stays.
func TestEditExampleConfig(t *testing.T) {
	in, err := os.ReadFile("../../../deploy/fairy-agent.config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out := set(t, string(in), "fan_control.auto_mode", "standard")
	a, b := strings.Split(string(in), "\n"), strings.Split(out, "\n")
	if len(a) != len(b) {
		t.Fatal("line count changed")
	}
	changed := 0
	for i := range a {
		if a[i] != b[i] {
			changed++
			if !strings.HasPrefix(b[i], "  auto_mode: standard ") || !strings.Contains(b[i], "# the BMC mode") {
				t.Fatalf("%q", b[i])
			}
		}
	}
	if changed != 1 {
		t.Fatal(changed)
	}
	out = set(t, out, "sensors.coretemp", "false") // a commented-out section gets the key under it
	if _, err := agent.Parse([]byte(out), "config.yaml"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "# sensors:\n#   acpi_thermal") || strings.Count(out, "#") != strings.Count(string(in), "#") {
		t.Fatal("comments changed")
	}
}

func TestEditErrors(t *testing.T) {
	for key, want := range map[string]string{"fan": "unknown setting", "fan_control": "is a section", "power_sources": "edit config.yaml",
		"ups": "edit config.yaml"} {
		if _, err := Lookup(key); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatal(key, err)
		}
	}
	for key, value := range map[string]string{"ipmi.enabled": "yes", "fan_control.min_duty": "30.5", "fan_control.max_temp_c": "hot",
		"listen": "a\nb", "wol.allowed_macs": "[a, b"} {
		s, err := Lookup(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseValue(s, value); err == nil {
			t.Fatal(key, value)
		}
	}
	s, _ := Lookup("fan_control.auto_mode")
	for in, want := range map[string]string{"fan_control: [1, 2]\n": "not a section", "a: b: c\n": "not valid YAML",
		"fan_control:\n  auto_mode: |\n    optimal\n": "multi-line", "- 1\n": "not a list of settings"} {
		if _, _, _, err := Edit([]byte(in), s, "standard"); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatal(in, err)
		}
	}
}

func TestEditReportsOld(t *testing.T) {
	s, _ := Lookup("fan_control.auto_mode")
	_, old, ok, err := Edit([]byte("fan_control: {auto_mode: optimal}\n"), s, "standard")
	if err != nil || !ok || old != "optimal" {
		t.Fatal(old, ok, err)
	}
	_, _, ok, _ = Edit([]byte("wol: {}\n"), s, "standard")
	if ok {
		t.Fatal("not set before")
	}
	l, _ := Lookup("wol.allowed_macs")
	if _, old, _, _ := Edit([]byte("wol:\n  allowed_macs:\n    - aa:bb:cc:dd:ee:ff\n"), l, []string{}); old != `["aa:bb:cc:dd:ee:ff"]` {
		t.Fatal(old)
	}
}

func TestSettingsAndEffective(t *testing.T) {
	cfg, err := agent.Parse([]byte("processes: {cmdline: false}\nwol: {allowed_macs: [aa:bb:cc:dd:ee:ff]}\n"), "/etc/fairy-agent/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range Settings() {
		got[s.Key] = Effective(cfg, s)
		if s.Type == ptrBoolT {
			if _, ok := ptrDefaults[s.Key]; !ok {
				t.Fatal("no default for", s.Key)
			}
		}
	}
	want := map[string]string{"processes.enabled": "true", "processes.cmdline": "false", "fan_control.auto_mode": "optimal",
		"fan_control.max_temp_c": "80", "wol.allowed_macs": `["aa:bb:cc:dd:ee:ff"]`, "power_sources": "(0 entries; edit config.yaml itself)",
		"listen": `""`, "self_update.repo": "n3ptune-cpu/Fairy-agent", "sensors.acpi_thermal": "true"}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(Settings()) || len(got) < 30 {
		t.Fatal(len(got))
	}
}

func TestParseValueList(t *testing.T) {
	s, _ := Lookup("processes.never_open")
	for in, want := range map[string][]string{"a.exe, b.exe": {"a.exe", "b.exe"}, "[a.exe, 'b c.exe']": {"a.exe", "b c.exe"},
		"[]": {}, "": {}, " x.exe ,": {"x.exe"}} {
		v, err := ParseValue(s, in)
		if err != nil || !reflect.DeepEqual(v, want) {
			t.Fatal(in, v, err)
		}
	}
}

func TestWriteFileKeepsPermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("a: 1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("a: 2\n")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	st, _ := os.Stat(p)
	if string(b) != "a: 2\n" || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o640) {
		t.Fatal(string(b), st.Mode())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatal("temporary file left behind", entries)
	}
	if err := WriteFile(filepath.Join(dir, "missing.yaml"), nil); err == nil {
		t.Fatal("only existing files are replaced")
	}
}

// H1: the old file is never written to; it is replaced by a new one. A second name of the old file (which
// stands for "the file someone else prepared and still owns") keeps the old content, and the config's name
// now belongs to a different file.
func TestWriteFileNeverWritesInPlace(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("planted: 1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(t.TempDir(), "the-old-file")
	if err := os.Link(p, old); err != nil {
		t.Skip("no hard links here:", err)
	}
	before, _ := os.Stat(p)
	if err := WriteFile(p, []byte("a: 2\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(old); string(b) != "planted: 1\n" {
		t.Fatalf("the old file was written in place: %q", b)
	}
	if b, _ := os.ReadFile(p); string(b) != "a: 2\n" {
		t.Fatalf("%q", b)
	}
	after, _ := os.Stat(p)
	if os.SameFile(before, after) {
		t.Fatal("config.yaml is still the old file")
	}
}
