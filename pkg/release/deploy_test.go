package release_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The install scripts are published with every release and run from the one line the panel's Add host dialog
// prints. That line and the scripts must fit together, and the panel finds out what a pinned script can do by
// looking for these very lines in it. This test pins what the panel's line relies on; nothing here runs a
// script (install.sh is exercised end to end outside the repository, the PowerShell scripts on a real PC).
func TestInstallScriptsKeepTheirContractWithThePanelsCommand(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "deploy", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sh, ps1, inner := read("install.sh"), read("install.ps1"), read("install-fairy-agent.ps1")

	// Plain ASCII, no byte order mark: the panel's Windows line turns the downloaded bytes into a script
	// block, and Windows PowerShell 5.1 reads a file without a mark in the PC's own code page.
	for name, b := range map[string][]byte{"install.sh": sh, "install.ps1": ps1, "install-fairy-agent.ps1": inner} {
		for i, c := range b {
			if c >= 0x80 || (c < 0x20 && c != '\n' && c != '\r') {
				t.Fatalf("%s: byte %#x at offset %d (ASCII without tabs only)", name, c, i)
			}
		}
	}
	if bytes.Contains(sh, []byte("\r")) {
		t.Fatal("install.sh has carriage returns")
	}

	// what the panel looks for to know which options a pinned script takes (regular expressions as in the
	// panel's internal/enrollment), old and new
	for name, c := range map[string]struct {
		in []byte
		re string
	}{
		"install.sh takes --sums-sha256":             {sh, `(?m)^\s*--sums-sha256\)`},
		"install.sh takes --join (old panels)":       {sh, `(?m)^\s*--join\)`},
		"install.sh takes --join-stdin":              {sh, `(?m)^\s*--join-stdin\)`},
		"install.sh takes --pair-v2":                 {sh, `(?m)^\s*--pair-v2\)`},
		"install.sh takes --unverified":              {sh, `(?m)^\s*--unverified\)`},
		"install.ps1 takes -SumsSha256":              {ps1, `(?im)^\s*\[string\]\$SumsSha256\b`},
		"install.ps1 takes -Join (old panels)":       {ps1, `(?im)^\s*\[string\]\$Join\b`},
		"install.ps1 takes -PairV2":                  {ps1, `(?im)^\s*\[switch\]\$PairV2\b`},
		"install.ps1 takes -Unverified":              {ps1, `(?im)^\s*\[switch\]\$Unverified\b`},
		"install.ps1 reads FAIRY_JOIN_CODE":          {ps1, `(?m)\$env:FAIRY_JOIN_CODE\b`},
		"install.sh reads FAIRY_JOIN_CODE":           {sh, `(?m)\$\{FAIRY_JOIN_CODE:-\}`},
		"install.sh hands the code to join on stdin": {sh, `(?m)^"\$BIN" join "\$@" <<EOF$`},
	} {
		if !regexp.MustCompile(c.re).Match(c.in) {
			t.Errorf("%s: no line matches %s", name, c.re)
		}
	}
	// -Join is no longer mandatory (the code comes from the environment)
	if regexp.MustCompile(`(?i)Mandatory[^\n]*\$Join\b`).Match(ps1) {
		t.Error("install.ps1: -Join is mandatory again")
	}

	// install.ps1 must run from memory as a script block: nothing that needs a file
	if regexp.MustCompile(`(?im)^\s*#Requires\b`).Match(ps1) {
		t.Error("install.ps1 has a #Requires line, which is not checked in a script block run from memory")
	}
	for _, bad := range []string{"$PSScriptRoot", "$PSCommandPath", "$MyInvocation"} {
		if strings.Contains(strings.ToLower(string(ps1)), strings.ToLower(bad)) {
			t.Errorf("install.ps1 uses %s, which is empty in a script block run from memory", bad)
		}
	}
	// no script evaluates text, and none shows or carries the code where a process list can see it
	for name, b := range map[string][]byte{"install.ps1": ps1, "install-fairy-agent.ps1": inner} {
		if regexp.MustCompile(`(?i)\b(Invoke-Expression|iex)\b`).Match(b) {
			t.Errorf("%s uses Invoke-Expression", name)
		}
	}
	if regexp.MustCompile(`(?m)^[^#\n]*--code[ "']`).Match(sh) || regexp.MustCompile(`(?m)^[^#\n]*'--code'`).Match(ps1) {
		t.Error("a script passes the join code to fairy-agent on its command line (--code)")
	}
	if regexp.MustCompile(`(?m)^[^#\n]*\b(eval|set -x)\b`).Match(sh) {
		t.Error("install.sh uses eval or set -x")
	}
	// L27: no line that pipes a download into a shell, or runs "latest" from a fixed temp file
	for name, b := range map[string][]byte{"install.sh": sh, "install.ps1": ps1} {
		if regexp.MustCompile(`(?i)\|\s*(sudo\s+)?(ba)?sh\b`).Match(b) && !bytes.Contains(b, []byte("printf '%s' CODE | sudo ... sh install.sh")) {
			t.Errorf("%s shows a download piped into a shell", name)
		}
		if bytes.Contains(b, []byte("fairy-install.ps1")) {
			t.Errorf("%s shows the fixed temp file name", name)
		}
	}
	// L25: one rule file per feature, the combined one is neither shipped nor installed (only removed)
	for _, f := range []string{"fairy-agent-power.polkit.rules", "fairy-agent-update.polkit.rules"} {
		if !bytes.Contains(sh, []byte(f)) {
			t.Errorf("install.sh does not install %s", f)
		}
		_ = read(f)
	}
	if _, err := os.Stat(filepath.Join("..", "..", "deploy", "fairy-agent.polkit.rules")); err == nil {
		t.Error("the combined polkit file is back in deploy/")
	}
	power, update := read("fairy-agent-power.polkit.rules"), read("fairy-agent-update.polkit.rules")
	if bytes.Contains(power, []byte("systemd1")) || bytes.Contains(update, []byte("login1")) {
		t.Error("a polkit rule file grants the other feature's right")
	}
	wf, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"fairy-agent-power.polkit.rules", "fairy-agent-update.polkit.rules", "install.sh", "install.ps1", "install-fairy-agent.ps1"} {
		if !regexp.MustCompile(`(?m)^\s*deploy="[^"\n]*\b` + regexp.QuoteMeta(f) + `\b`).Match(wf) {
			t.Errorf("release.yml does not publish %s", f)
		}
	}
	if regexp.MustCompile(`(?m)^\s*deploy="[^"\n]*fairy-agent\.polkit\.rules`).Match(wf) {
		t.Error("release.yml still publishes the combined polkit file")
	}
}
