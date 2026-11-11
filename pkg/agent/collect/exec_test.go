package collect

// Review of the audit 4 fixes (T-60, R9): the agent hides its secrets from the programs it starts, but four of
// them were started with the whole environment (systemctl for power-off and for the update unit, busctl, and
// PowerShell for IPMI on Windows). Command is the one way to start a program now.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// childEnvMark tells the test program that it is the child of TestCommandChildSeesNoSecrets.
const childEnvMark = "COLLECT_TEST_PRINT_ENV"

func TestMain(m *testing.M) {
	if os.Getenv(childEnvMark) == "1" { // the child: print the names of its environment and stop
		var names []string
		for _, kv := range os.Environ() {
			k, _, _ := strings.Cut(kv, "=")
			names = append(names, strings.ToUpper(k))
		}
		sort.Strings(names)
		fmt.Println("ENV " + strings.Join(names, " "))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// A real child process (this test program itself) started with Command: it sees no variable that was hidden
// and none that starts with FAIRY_, and it still sees the others.
func TestCommandChildSeesNoSecrets(t *testing.T) {
	t.Setenv("R9_PLUG_PASSWORD", "dummy-secret-1")
	t.Setenv("r9_tuya_key", "dummy-secret-2") // names are compared without regard to case
	t.Setenv("FAIRY_R9_TOKEN", "dummy-secret-3")
	t.Setenv("R9_NOT_A_SECRET", "stays")
	t.Setenv(childEnvMark, "1")
	HideEnv("R9_PLUG_PASSWORD", "R9_TUYA_KEY")
	exe, err := os.Executable()
	if err != nil {
		t.Skip("this test program's own path is not known:", err)
	}
	out, err := Command(context.Background(), exe).Output()
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if !strings.HasPrefix(line, "ENV ") {
		t.Fatalf("the child did not print its environment: %q", out)
	}
	seen := map[string]bool{}
	for _, n := range strings.Fields(line)[1:] {
		seen[n] = true
	}
	for _, n := range []string{"R9_PLUG_PASSWORD", "R9_TUYA_KEY", "FAIRY_R9_TOKEN"} {
		if seen[n] {
			t.Errorf("the child sees %s", n)
		}
	}
	for _, n := range []string{"R9_NOT_A_SECRET", childEnvMark} {
		if !seen[n] {
			t.Errorf("the child does not see %s: more was removed than the secrets", n)
		}
	}
	for _, kv := range os.Environ() { // nothing else is missing either (PATH, SystemRoot and so on)
		k, _, _ := strings.Cut(kv, "=")
		ku := strings.ToUpper(k)
		if ku == "" || strings.HasPrefix(ku, "FAIRY_") || ku == "R9_PLUG_PASSWORD" || ku == "R9_TUYA_KEY" {
			continue
		}
		if !seen[ku] {
			t.Errorf("the child does not see %s", ku)
		}
	}
}
