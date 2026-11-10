package main

import (
	"os"
	"runtime"
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
