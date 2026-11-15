package agent

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
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
		o.ReadEnv, o.SwitchEnv = readEnv, switchEnv
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
