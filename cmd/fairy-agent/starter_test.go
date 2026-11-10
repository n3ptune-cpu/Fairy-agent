package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

// L19: command lines are off for NEW Linux installs only. The starter config and the example file say
// `cmdline: false`; a config.yaml that does not have the key keeps the meaning it always had (on), so an
// existing install behaves exactly as before.
func TestCmdlineOffForNewInstallsOnly(t *testing.T) {
	parse := func(name, y string) *agent.Config {
		t.Helper()
		c, err := agent.Parse([]byte(y), name)
		if err != nil {
			t.Fatal(name, err)
		}
		return c
	}
	// the config `join` writes when there is none: Linux off; Windows on (program paths only, never arguments)
	starter := parse("starter", starterConfig())
	if want := runtime.GOOS == "windows"; !starter.ProcessesEnabled() || starter.CmdlineEnabled() != want {
		t.Fatalf("starter config: processes %v, cmdline %v (want %v)", starter.ProcessesEnabled(), starter.CmdlineEnabled(), want)
	}
	example, err := os.ReadFile("../../deploy/fairy-agent.config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c := parse("example", string(example)); !c.ProcessesEnabled() || c.CmdlineEnabled() {
		t.Fatal("the example config must have the process list on and command lines off")
	}
	// existing configs: the code default did not flip
	for y, want := range map[string]bool{
		"":                                true,
		"processes: {}\n":                 true,
		"processes: {enabled: true}\n":    true,
		"listen: 127.0.0.1:9101\n":        true,
		"processes: {cmdline: true}\n":    true,
		"processes: {cmdline: false}\n":   false,
		"processes:\n  cmdline: false\n":  false,
		"processes:\n  enabled: false\n":  true,
		"processes:\n  cmdline: true  \n": true,
	} {
		if got := parse("existing", y).CmdlineEnabled(); got != want {
			t.Errorf("%q: cmdline %v, want %v", y, got, want)
		}
	}
}

// Review N5: command lines are still on when config.yaml has no `cmdline` key. That is the owner's decision
// (off for new installs only; an existing install keeps what it does). What it rests on is checked here with
// the real join command, which is what install.sh and install.ps1 run: a new install gets a config.yaml that
// says `cmdline: false` on Linux, and joining again (Re-pair) never adds, removes or flips the key of a config
// that is already there.
func TestJoinWritesCmdlineOffForANewInstallAndLeavesAnOldOneAlone(t *testing.T) {
	if !isAdmin() {
		t.Skip("join needs root / Administrator")
	}
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	const code = "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"
	join := func(cfgPath, state string) {
		t.Helper()
		var out, errb bytes.Buffer
		if rc := joinCmd([]string{"--code", code, "--panel", "100.64.0.10", "--config", cfgPath, "--state-dir", state, "--power-control"}, &out, &errb); rc != 0 {
			t.Fatal(rc, out.String(), errb.String())
		}
	}
	// a new install: no config.yaml yet
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	join(cfgPath, t.TempDir())
	cfg, err := agent.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(cfgPath)
	if runtime.GOOS != "windows" {
		if cfg.CmdlineEnabled() || !strings.Contains(string(b), "cmdline: false") {
			t.Fatalf("a new install sends command lines:\n%s", b)
		}
	}
	if !cfg.ProcessesEnabled() || !cfg.PowerControl.Enabled {
		t.Fatalf("the new config: processes %v, power %v", cfg.ProcessesEnabled(), cfg.PowerControl.Enabled)
	}
	// existing installs, joined again: the key stays as it is, present or not
	for name, c := range map[string]struct {
		yaml string
		want bool
	}{
		"no key (older than the key, or written by hand)": {"listen: 127.0.0.1:9101\n", true},
		"the old starter's cmdline: true":                 {"processes:\n  enabled: true\n  cmdline: true\n", true},
		"switched off by the owner":                       {"processes:\n  enabled: true\n  cmdline: false\n", false},
	} {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte(c.yaml), 0o640); err != nil {
			t.Fatal(err)
		}
		join(cfgPath, t.TempDir())
		cfg, err := agent.Load(cfgPath)
		if err != nil {
			t.Fatal(name, err)
		}
		after, _ := os.ReadFile(cfgPath)
		if cfg.CmdlineEnabled() != c.want || strings.Count(string(after), "cmdline") != strings.Count(c.yaml, "cmdline") {
			t.Errorf("%s: after joining again cmdline is %v, want %v:\n%s", name, cfg.CmdlineEnabled(), c.want, after)
		}
	}
}
