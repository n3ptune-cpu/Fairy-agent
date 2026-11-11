package collect

// Review of the audit 4 fixes (T-60, R9): the agent hides its secrets from the programs it starts, but four of
// them were started with the whole environment (systemctl for power-off and for the update unit, busctl, and
// PowerShell for IPMI on Windows). Command is the one way to start a program now.

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// childEnvMark tells the test program that it is the child of TestCommandChildSeesNoSecrets (as a variable of
// its environment) or of TestCommandChildOfAnEnvironmentWithOnlySecrets (as its first argument).
const childEnvMark = "COLLECT_TEST_PRINT_ENV"

func TestMain(m *testing.M) {
	if os.Getenv(childEnvMark) == "1" || (len(os.Args) == 2 && os.Args[1] == childEnvMark) { // the child: print the names of its environment and stop
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

// Last review (N1): when nothing of the environment is left (every variable is a secret or a FAIRY_ variable)
// the list was nil, and for a nil list the system gives the child the WHOLE environment of the agent, secrets
// included. The list is empty then, never nil.
func TestCommandChildOfAnEnvironmentWithOnlySecrets(t *testing.T) {
	saved := os.Environ()
	t.Cleanup(func() {
		os.Clearenv()
		for _, kv := range saved {
			if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
				_ = os.Setenv(k, v)
			}
		}
	})
	os.Clearenv()
	if env := minimalEnv(); env == nil || len(env) != 0 {
		t.Fatalf("an empty environment: the list for the child is %#v, want an empty list that is not nil", env)
	}
	_ = os.Setenv("FAIRY_AGENT_TOKEN", "dummy-secret-1")
	_ = os.Setenv("N1_PLUG_PASSWORD", "dummy-secret-2")
	HideEnv("N1_PLUG_PASSWORD")
	if env := minimalEnv(); env == nil || len(env) != 0 {
		t.Fatalf("an environment of secrets only: the list for the child is %#v, want an empty list that is not nil", env)
	}
	if cmd := Command(context.Background(), "x"); cmd.Env == nil {
		t.Fatal("Command leaves the child's environment unset: the child would get everything")
	}
	if runtime.GOOS == "windows" {
		return // a program without any variable (no SystemRoot) is not a fair test there; the list was checked above
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip("this test program's own path is not known:", err)
	}
	out, err := Command(context.Background(), exe, childEnvMark).Output()
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if !strings.HasPrefix(line, "ENV") {
		t.Fatalf("the child did not print its environment: %q", out)
	}
	for _, n := range strings.Fields(line)[1:] {
		if n == "FAIRY_AGENT_TOKEN" || n == "N1_PLUG_PASSWORD" {
			t.Errorf("the child of an environment with only secrets sees %s", n)
		}
	}
}
