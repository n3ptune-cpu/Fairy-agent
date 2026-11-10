//go:build !windows

package release_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Review O2: install.sh still takes the join code on its command line (--join CODE), because the command of a
// panel up to 0.5.x ends in it and a machine must never be stuck with such a panel. It is deprecated: the
// script says so in ONE line on standard error and never shows the code, on any path.
//
// The script is run for real here, with every shell that is installed, but only as far as its first refusal:
// without a release fingerprint (and without --unverified) it stops before it looks at the machine, downloads
// or changes anything.
func TestInstallScriptWarnsAboutTheCodeOnTheCommandLine(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "deploy", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	const code = "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567"
	bare := strings.ReplaceAll(code, "-", "")
	shows := func(text string) bool {
		for _, s := range []string{code, bare, strings.ToLower(code), strings.ToLower(bare), code[:14], bare[:12]} {
			if strings.Contains(text, s) {
				return true
			}
		}
		return false
	}
	shells := [][]string{{"sh"}, {"dash"}, {"bash", "--posix"}, {"busybox", "sh"}}
	ran := 0
	for _, shell := range shells {
		if _, err := exec.LookPath(shell[0]); err != nil {
			continue
		}
		ran++
		run := func(stdin string, env []string, args ...string) (stdout, stderr string, rc int) {
			t.Helper()
			cmd := exec.Command(shell[0], append(append(shell[1:], script), args...)...)
			cmd.Stdin = strings.NewReader(stdin)
			cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}, env...)
			var o, e bytes.Buffer
			cmd.Stdout, cmd.Stderr = &o, &e
			err := cmd.Run()
			if ee, ok := err.(*exec.ExitError); ok {
				rc = ee.ExitCode()
			} else if err != nil {
				t.Fatal(shell, err)
			}
			return o.String(), e.String(), rc
		}
		warnings := func(stderr string) (n int) {
			for _, line := range strings.Split(stderr, "\n") {
				if strings.Contains(line, "deprecated") {
					n++
				}
			}
			return n
		}
		// the old form: accepted (the script goes on to its next check), one line of warning, no code
		stdout, stderr, rc := run("", nil, "--join", code, "--panel", "100.64.0.10", "--power-control")
		if rc == 0 || !strings.Contains(stderr, "no release fingerprint") {
			t.Fatalf("%v: the script did not stop at the fingerprint: rc %d\n%s", shell, rc, stderr)
		}
		if warnings(stderr) != 1 || !strings.Contains(stderr, "fairy: warning: --join CODE on the command line is deprecated") ||
			!strings.Contains(stderr, "--join-stdin") || strings.Contains(stdout, "deprecated") {
			t.Errorf("%v: not exactly one line of warning on standard error:\nstdout: %s\nstderr: %s", shell, stdout, stderr)
		}
		if shows(stdout + stderr) {
			t.Errorf("%v: the output shows the code:\n%s%s", shell, stdout, stderr)
		}
		// the current forms: standard input and the environment, no warning
		for name, c := range map[string]struct {
			stdin string
			env   []string
			args  []string
		}{
			"--join-stdin":    {code + "\n", nil, []string{"--join-stdin", "--panel", "100.64.0.10"}},
			"FAIRY_JOIN_CODE": {"", []string{"FAIRY_JOIN_CODE=" + code}, []string{"--panel", "100.64.0.10"}},
		} {
			stdout, stderr, rc := run(c.stdin, c.env, c.args...)
			if rc == 0 || !strings.Contains(stderr, "no release fingerprint") || warnings(stdout+stderr) != 0 || shows(stdout+stderr) {
				t.Errorf("%v, %s: rc %d\nstdout: %s\nstderr: %s", shell, name, rc, stdout, stderr)
			}
		}
		// mistakes around the code: whatever the script says, it does not repeat the code
		for _, args := range [][]string{
			{"--join", code}, // no panel
			{"--join", code, "--panel", "not an address"},                        // a bad panel address
			{"--join", code + "!", "--panel", "100.64.0.10"},                     // not a code
			{"--join", code, "--join-stdin", "--panel", "100.64.0.10"},           // both
			{code, "--panel", "100.64.0.10"},                                     // the code without its option
			{"--join", code, "--panel", "100.64.0.10", "--no-such-option"},       // an unknown option after it
			{"--join", code, "--panel", "100.64.0.10", "--sums-sha256", "xyz"},   // a bad fingerprint
			{"--join", code, "--panel", "100.64.0.10", "--ups-name", "bad name"}, // a bad UPS name
		} {
			stdout, stderr, rc := run("", nil, args...)
			if rc == 0 {
				t.Errorf("%v %q: accepted", shell, args)
			}
			if shows(stdout + stderr) {
				t.Errorf("%v %q: the output shows the code:\n%s%s", shell, args, stdout, stderr)
			}
		}
	}
	if ran == 0 {
		t.Skip("no shell to run install.sh with")
	}
	// and the script itself never traces, and has no line that prints the code variable
	sh, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(sh), "\n") {
		code := strings.TrimSpace(strings.SplitN(line, " #", 2)[0])
		if strings.HasPrefix(code, "#") {
			continue
		}
		if strings.Contains(code, "$CODE") && (strings.HasPrefix(code, "say ") || strings.HasPrefix(code, "die ") ||
			strings.HasPrefix(code, "echo ") || strings.Contains(code, ">>") || strings.Contains(code, "logger")) {
			t.Errorf("install.sh line %d prints or stores the join code: %s", i+1, line)
		}
	}
}
