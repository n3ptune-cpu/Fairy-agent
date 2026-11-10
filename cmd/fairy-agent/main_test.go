package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

// fans-auto does one fixed thing: whatever is written after it on the command line, nothing is read, run or
// sent to the BMC.
func TestFansAutoTakesNoArguments(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("ipmi: {enabled: true, ipmitool: /nonexistent/ipmitool}\nfan_control: {enabled: true}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--config", cfg}, {"--config=" + cfg}, {cfg}, {"full"}, {"--mode", "full"}, {"30"},
		{"--ipmitool", "/bin/sh"}, {"--", "sh", "-c", "id"}, {"-h"}, {""}} {
		var out, errb bytes.Buffer
		if code := fansAutoCmd(args, &out, &errb); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
		if out.Len() != 0 || !strings.Contains(errb.String(), "takes no arguments") {
			t.Errorf("%q: stdout %q stderr %q", args, out.String(), errb.String())
		}
	}
}

func TestFansAutoCommand(t *testing.T) {
	dir := t.TempDir()
	write := func(y string) string {
		p := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(p, []byte(y), 0o640); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// fan control off (every agent without it runs this after each stop): quiet success, nothing done
	for _, y := range []string{"", "ipmi: {enabled: true}\n"} {
		var out, errb bytes.Buffer
		if code := fansAuto(write(y), &out, &errb); code != 0 || !strings.Contains(out.String(), "nothing to do") || errb.Len() != 0 {
			t.Fatalf("%q: %d %q %q", y, code, out.String(), errb.String())
		}
	}
	// no config, a broken config, or no way to reach the BMC: exit 1 with the reason (never a false "done")
	var out, errb bytes.Buffer
	if code := fansAuto(filepath.Join(dir, "missing.yaml"), &out, &errb); code != 1 || errb.Len() == 0 {
		t.Fatal(code, errb.String())
	}
	errb.Reset()
	if code := fansAuto(write("fan_control: {enabled: true, min_duty: 5}\n"), &out, &errb); code != 1 || !strings.Contains(errb.String(), "min_duty") {
		t.Fatal(code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatal("stdout on failure:", out.String())
	}
}

// Fan control is on and the BMC cannot be reached: exit 1 with the reason, never a false "done".
//
// Not on Windows. There the agent reaches the BMC through Windows' own IPMI driver, asked by a powershell.exe
// that it starts from System32 (config.yaml's ipmitool path is not used), so this test would start a program
// outside its temporary folder and ask the hardware of the PC it runs on. The same end ("could not hand the
// fans back", with a BMC that does not answer) is tested on every system with a fake BMC in pkg/agent
// (TestFansAuto*).
func TestFansAutoCommandWithoutABMC(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("would start powershell.exe to ask this PC's IPMI driver; covered with a fake BMC in pkg/agent")
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("ipmi: {enabled: true, ipmitool: /nonexistent/ipmitool}\nfan_control: {enabled: true}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := fansAuto(p, &out, &errb); code != 1 || !strings.Contains(errb.String(), "could not hand the fans back") {
		t.Fatal(code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatal("stdout on failure:", out.String())
	}
}

// The unit file runs fans-auto after the agent has ended, from the same program as ExecStart, without
// arguments, and the config the service runs with is the one fans-auto reads.
func TestUnitRunsFansAutoAfterStop(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "fairy-agent.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(b)
	start := regexp.MustCompile(`(?m)^ExecStart=(\S+) run --config (\S+)$`).FindStringSubmatch(unit)
	if start == nil {
		t.Fatal("ExecStart line not found")
	}
	post := regexp.MustCompile(`(?m)^ExecStopPost=(.*)$`).FindAllStringSubmatch(unit, -1)
	if len(post) != 1 || post[0][1] != "-"+start[1]+" fans-auto" {
		t.Fatalf("ExecStopPost must be exactly %q, got %q", "-"+start[1]+" fans-auto", post)
	}
	if want := "/etc/fairy-agent/config.yaml"; start[2] != want || (runtime.GOOS == "linux" && agent.DefaultConfigPath() != want) {
		t.Fatalf("the unit runs with %s but fans-auto reads %s", start[2], agent.DefaultConfigPath())
	}
	if strings.Contains(usage, "fans-auto [") || !strings.Contains(usage, "fairy-agent fans-auto") {
		t.Fatal("usage: fans-auto is listed without options")
	}
}
