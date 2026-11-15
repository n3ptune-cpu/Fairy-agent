package agent

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// What the agent says once in its log when it starts with sockets (PLUGS-DESIGN.md 3.3, 3.10): how many
// sockets, how many can be switched, which switches are never switched, and a warning for each note.
func TestStartLogOfTheSockets(t *testing.T) {
	const readEnv, switchEnv = "PCHK_READ_TOKEN", "PCHK_SWITCH_TOKEN"
	secret := strings.Join([]string{"made", "up", "switch", "token"}, "-")
	t.Setenv(switchEnv, secret)
	said := func(t *testing.T, o agenttest.PlugOptions, state string) string {
		t.Helper()
		o.ReadEnv = readEnv
		if o.SwitchEnv == "" {
			o.SwitchEnv = switchEnv
		}
		cfg := mustParse(t, agenttest.PlugConfig("http://192.0.2.10:8123", o))
		relay, err := cfg.NewRelay()
		if err != nil {
			t.Fatal(err)
		}
		p, err := cfg.NewPlugs(relay)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		old := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
		defer slog.SetDefault(old)
		logPlugs(cfg, p, state)
		if strings.Contains(buf.String(), secret) {
			t.Errorf("the start log holds the token:\n%s", buf.String())
		}
		return buf.String()
	}
	on := said(t, agenttest.PlugOptions{Switching: true}, api.ApprovalRequired)
	if !strings.Contains(on, `level=INFO msg="plug sockets (home assistant)" host=192.0.2.10:8123 sockets=5 can_be_switched=2 never_switched=switch.server_corner_socket switching=true min_gap_s=5 token_env=`+switchEnv+` token_set=true`) {
		t.Errorf("switching on:\n%s", on)
	}
	if strings.Count(on, "level=WARN") != 1 || !strings.Contains(on, `level=WARN msg="plug sockets: switching goes over http:`) {
		t.Errorf("switching on, the warnings:\n%s", on)
	}
	noCheck := said(t, agenttest.PlugOptions{Switching: true}, api.ApprovalOff)
	if !strings.Contains(noCheck, `level=WARN msg="plug sockets: this machine has no passkey check: every switch request is refused (approval_off) until the check is turned on."`) {
		t.Errorf("no passkey check:\n%s", noCheck)
	}
	broken := said(t, agenttest.PlugOptions{Switching: true}, api.ApprovalBroken)
	if !strings.Contains(broken, "the passkey check of this machine cannot be used") {
		t.Errorf("a passkey check that cannot be used:\n%s", broken)
	}
	off := said(t, agenttest.PlugOptions{}, api.ApprovalOff)
	if !strings.Contains(off, "sockets=5 can_be_switched=0 never_switched=switch.server_corner_socket switching=false") || strings.Contains(off, "level=WARN") {
		t.Errorf("switching off:\n%s", off)
	}
	t.Setenv(switchEnv, "")
	noToken := said(t, agenttest.PlugOptions{Switching: true}, api.ApprovalRequired)
	if !strings.Contains(noToken, "token_set=false") || !strings.Contains(noToken, `level=WARN msg="plug sockets: the variable `+switchEnv+` holds no token: no socket's state is read and nothing is switched until it does.`) {
		t.Errorf("no token:\n%s", noToken)
	}
	// one variable for both tokens: said once, in a line that is no warning
	t.Setenv(readEnv, secret)
	one := said(t, agenttest.PlugOptions{Switching: true, SwitchEnv: readEnv}, api.ApprovalRequired)
	if strings.Count(one, "level=WARN") != 1 || strings.Count(one, "the same token") != 1 ||
		!strings.Contains(one, `level=INFO msg="plug sockets: switching and reading use the same token (`+readEnv+`): Home Assistant gives every token of an account the same rights, so a second token only lets you revoke one without the other."`) {
		t.Errorf("one variable for both tokens:\n%s", one)
	}
	t.Setenv(switchEnv, "made up, with a space")
	unusable := said(t, agenttest.PlugOptions{Switching: true}, api.ApprovalRequired)
	if !strings.Contains(unusable, "token_set=false") || strings.Contains(unusable, "made up") ||
		!strings.Contains(unusable, `level=WARN msg="plug sockets: the variable `+switchEnv+` holds a value that cannot be a token (a space, a line break or a character that is not plain ASCII is in it): no socket's state is read and nothing is switched until it holds one.`) {
		t.Errorf("a value that cannot be a token:\n%s", unusable)
	}
	if none := said(t, agenttest.PlugOptions{NoBlock: true}, api.ApprovalOff); none != "" {
		t.Errorf("an agent without the block says:\n%s", none)
	}
}

// What a program that is not the agent sees of the passkey check: no folder or no file is "off", a trust file
// is "required", a damaged one "broken"; nothing is written and nothing is logged.
func TestApprovalStateOnDisk(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)
	dir := t.TempDir()
	files := approval.Files{Path: filepath.Join(dir, "state", approval.TrustFileName)}
	if got := ApprovalStateOnDisk(files); got != api.ApprovalOff {
		t.Errorf("no folder: %s", got)
	}
	if err := os.MkdirAll(filepath.Dir(files.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := ApprovalStateOnDisk(files); got != api.ApprovalOff {
		t.Errorf("no file: %s", got)
	}
	tr, err := approval.FromInit(approvaltest.New().Init(), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.Replace(tr); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(files.Path)
	if got := ApprovalStateOnDisk(files); got != api.ApprovalRequired {
		t.Errorf("a trust file: %s", got)
	}
	if now, _ := os.ReadFile(files.Path); !bytes.Equal(now, before) {
		t.Error("the look changed the trust file")
	}
	if err := os.WriteFile(files.Path, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ApprovalStateOnDisk(files); got != api.ApprovalBroken {
		t.Errorf("a damaged trust file: %s", got)
	}
	blind := files
	blind.CheckDir = func(string) error { return os.ErrPermission }
	if got := ApprovalStateOnDisk(blind); got != api.ApprovalBroken {
		t.Errorf("a folder this user may not look into: %s", got)
	}
	if ents, _ := os.ReadDir(filepath.Dir(files.Path)); len(ents) != 1 || buf.Len() != 0 {
		t.Errorf("the look left %d files and wrote to the log: %s", len(ents), buf.String())
	}
}

// The line "switching and reading use the same token" is said when the block and an entry name one variable,
// and one variable is what this system takes as one: two names that differ in letter case only are one
// variable on Windows and two anywhere else. On Linux a block that reads pchk_one_token while the entries
// read PCHK_ONE_TOKEN has no token when only the second is set: the report says "missing", and must not say
// in the next line that the two use the same token.
func TestTheSameTokenLineTakesVariableNamesAsTheSystemDoes(t *testing.T) {
	const upper, lower = "PCHK_ONE_TOKEN", "pchk_one_token"
	t.Setenv(upper, strings.Join([]string{"made", "up", "one", "token"}, "-"))
	report := func(t *testing.T, readEnv, switchEnv string) PlugReport {
		t.Helper()
		cfg := mustParse(t, agenttest.PlugConfig("http://192.0.2.10:8123", agenttest.PlugOptions{Switching: true, ReadEnv: readEnv, SwitchEnv: switchEnv}))
		relay, err := cfg.NewRelay()
		if err != nil {
			t.Fatal(err)
		}
		p, err := cfg.NewPlugs(relay)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.PlugReport(p, api.ApprovalRequired)
	}
	same := func(rep PlugReport) int { return strings.Count(strings.Join(rep.Remarks, "\n"), "the same token") }
	old := envNamesFold
	t.Cleanup(func() { envNamesFold = old })
	for _, fold := range []bool{false, true} {
		envNamesFold = fold
		if rep := report(t, upper, upper); same(rep) != 1 || !strings.Contains(rep.Remarks[0], "("+upper+")") {
			t.Errorf("fold %v, one name in both places: remarks %v", fold, rep.Remarks)
		}
		rep := report(t, upper, lower)
		want := 0
		if fold {
			want = 1 // on Windows the two names are one variable
		}
		if same(rep) != want {
			t.Errorf("fold %v, two names that differ in letter case: remarks %v, want the line %d times", fold, rep.Remarks, want)
		}
		if rep := report(t, upper, "PCHK_OTHER_TOKEN"); same(rep) != 0 {
			t.Errorf("fold %v, two variables: remarks %v", fold, rep.Remarks)
		}
	}
	if envNamesFold = old; envNamesFold != (runtime.GOOS == "windows") {
		t.Errorf("names of variables fold their letter case: %v on %s", envNamesFold, runtime.GOOS)
	}
	// where the two names are two variables, the block's own is the one that counts: it is not set here
	if runtime.GOOS != "windows" {
		rep := report(t, upper, lower)
		if lines := strings.Join(rep.Lines, "\n"); !strings.Contains(lines, "token: missing ("+lower+" is not set") || same(rep) != 0 {
			t.Errorf("the block's variable in another letter case than the entries':\n%s\nremarks %v", lines, rep.Remarks)
		}
	}
}
