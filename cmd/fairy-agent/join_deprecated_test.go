package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

// spellings are the ways a join code can appear in text.
func spellings(code string) []string {
	bare := strings.ReplaceAll(code, "-", "")
	return []string{code, bare, strings.ToLower(code), strings.ToLower(bare), bare[:16], code[:19]}
}

func showsCode(text, code string) bool {
	for _, s := range spellings(code) {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

// Review O2: the join code is still accepted on the command line (--code), because the install scripts of older
// releases pass it there. It is deprecated: join says so in one line on standard error, which does not show
// the code, and goes on. The other two ways print no warning. Removal waits for a later release.
func TestJoinCodeOnTheCommandLineIsDeprecatedNotRefused(t *testing.T) {
	code, _ := enroll.NewCode()
	bare := strings.ReplaceAll(code, "-", "")
	common := []string{"--panel", "100.64.0.10", "--config", filepath.Join(t.TempDir(), "config.yaml"), "--state-dir", t.TempDir()}
	parse := func(args ...string) (joinOpts, string, error) {
		var errb bytes.Buffer
		o, err := parseJoin(append(args, common...), &errb)
		return o, errb.String(), err
	}
	t.Setenv(joinCodeEnv, "")
	for _, c := range []string{code, bare, strings.ToLower(code)} {
		o, stderr, err := parse("--code", c)
		if n, nerr := enroll.Normalize(o.code); err != nil || nerr != nil || n != bare {
			t.Fatalf("--code %q is not accepted any more: %v", c, err)
		}
		if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, "fairy-agent join: warning: ") ||
			!strings.Contains(stderr, "deprecated") || !strings.Contains(stderr, "--code-stdin") {
			t.Fatalf("not one line of warning on standard error: %q", stderr)
		}
		if showsCode(stderr, code) {
			t.Fatalf("the warning shows the code: %q", stderr)
		}
	}
	// standard input and the environment: no warning
	old := joinStdin
	joinStdin = strings.NewReader(code + "\n")
	t.Cleanup(func() { joinStdin = old })
	if _, stderr, err := parse("--code-stdin"); err != nil || stderr != "" {
		t.Fatalf("--code-stdin: %v %q", err, stderr)
	}
	t.Setenv(joinCodeEnv, code)
	if _, stderr, err := parse(); err != nil || stderr != "" {
		t.Fatalf("environment: %v %q", err, stderr)
	}
	// the help text says it too
	var help bytes.Buffer
	_, _ = parseJoin([]string{"--help"}, &help)
	if !strings.Contains(help.String(), "deprecated") || showsCode(help.String(), code) {
		t.Fatalf("help: %s", help.String())
	}
}

// However the command is mistyped, nothing join prints repeats the code: not as an argument out of place, not
// inside an option that does not exist, not as a value an option cannot take.
func TestJoinNeverEchoesTheCode(t *testing.T) {
	code, _ := enroll.NewCode()
	bare := strings.ReplaceAll(code, "-", "")
	t.Setenv(joinCodeEnv, "")
	for _, args := range [][]string{
		{code, "--panel", "100.64.0.10"},                                  // the code without its option
		{"--panel", "100.64.0.10", code},                                  // the code after the options
		{"--join", code, "--panel", "100.64.0.10"},                        // install.sh's option name
		{"--code" + bare, "--panel", "100.64.0.10"},                       // no space
		{"--" + bare, "--panel", "100.64.0.10"},                           // the code as an option
		{"--code-stdin=" + code, "--panel", "100.64.0.10"},                // a value for a switch
		{"--pair-v2=" + strings.ToLower(code), "--panel", "100.64.0.10"},  // the same, lower case
		{"--code", code, "--panel", "not-an-address"},                     // another mistake next to a good code
		{"--code", code, "--panel", "100.64.0.10", "--ups-name", "a b c"}, // and another
		{"--code", code + "A", "--panel", "100.64.0.10"},                  // a code that is too long
		{"--code", code[:len(code)-1] + "1", "--panel", "100.64.0.10"},    // a code with a wrong character
		{"--code", code, "--code-stdin", "--panel", "100.64.0.10"},        // both
		{"--code", code}, // no panel
	} {
		var out, errb bytes.Buffer
		rc := joinCmd(args, &out, &errb)
		if rc == 0 {
			t.Fatalf("%q: accepted", args)
		}
		if text := out.String() + errb.String(); showsCode(text, code) {
			t.Errorf("%q: the output shows the code:\n%s", args, text)
		}
	}
	if got := hideCode("unexpected \"" + code + "\" and " + bare + " and " + strings.ToLower(code)); showsCode(got, code) {
		t.Fatal(got)
	}
	if got := hideCode("--panel must be the panel's Tailscale IPv4 address, e.g. 100.88.109.47"); !strings.Contains(got, "Tailscale IPv4 address") {
		t.Fatal("an ordinary message was changed:", got)
	}
}
