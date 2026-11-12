//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/n3ptune-cpu/Fairy-agent/internal/roottest"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// The test program plays three small parts when it is started with FAIRY_TEST_TRUST set, so that the tests
// below can run them as other users, each in a process of its own (a process that gave up root cannot go on
// as the test):
//
//	cmd     `fairy-agent helper-trust <arguments>` on the trust file FAIRY_TEST_TRUST_FILE, with the real checks
//	agent   what the running agent does: create (the first-time set's write), state (what its gate sees)
//	meddle  what a local user who is neither root nor the agent tries: read, overwrite, remove the trust file
func TestMain(m *testing.M) {
	part := os.Getenv("FAIRY_TEST_TRUST")
	if part == "" {
		os.Exit(m.Run())
	}
	path := os.Getenv("FAIRY_TEST_TRUST_FILE")
	files := approval.UnixFiles(path)
	switch part {
	case "cmd":
		trustFiles = func(*agent.Config) approval.Files {
			f := files
			f.Prepare = approval.UnixAdminPrepare(filepath.Dir(path)) // = agent.ApprovalAdminFiles
			return f
		}
		os.Exit(helperTrustCmd(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	case "agent":
		switch os.Args[1] {
		case "create":
			tr, err := approval.FromInit(approvaltest.New().Init(), time.Now(), nil)
			if err == nil {
				err = files.Create(tr)
			}
			if err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
			}
		case "state":
			st := approval.NewGate(approval.Options{Files: files, EnforcedBy: api.EnforcedByAgent,
				Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Status()
			b, _ := json.Marshal(st)
			fmt.Println(string(b))
		}
		os.Exit(0)
	case "meddle":
		_, rerr := os.ReadFile(path)
		werr := os.WriteFile(path, []byte("{}"), 0o600)
		derr := os.Remove(path)
		_, lerr := os.ReadDir(filepath.Dir(path))
		if rerr == nil || werr == nil || derr == nil || lerr == nil {
			fmt.Printf("read %v, write %v, remove %v, list %v\n", rerr, werr, derr, lerr)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(2)
}

func TestTrustActAs(t *testing.T) {
	for name, c := range map[string]struct {
		euid          int
		found, isDir  bool
		owner         uint32
		drop, refused bool
	}{
		"root, the agent's folder (a standard install)": {0, true, true, 997, true, false},
		"root, root's folder (the agent runs as root)":  {0, true, true, 0, false, false},
		"root, no folder": {0, false, false, 0, false, false},
		"root, a link or file where the folder belongs": {0, true, false, 997, false, false},
		"the agent's user, its own folder":              {997, true, true, 997, false, false},
		"another user, the agent's folder":              {1000, true, true, 997, false, true},
		"another user, root's folder":                   {1000, true, true, 0, false, true},
		"another user, no folder":                       {1000, false, false, 0, false, false},
	} {
		drop, err := trustActAs(c.euid, c.found, c.isDir, c.owner)
		if drop != c.drop || (err != nil) != c.refused {
			t.Errorf("%s: drop %v, error %v; want drop %v, refused %v", name, drop, err, c.drop, c.refused)
		}
		if err != nil && !strings.Contains(err.Error(), "as root") {
			t.Errorf("%s: the refusal does not say what to do: %v", name, err)
		}
	}
}

// reachableDir makes a folder every user can pass through (the usual temporary folder of a root test run is
// often inside one that only root can enter).
func reachableDir(t *testing.T) string {
	t.Helper()
	for _, base := range []string{os.TempDir(), "/dev/shm", "/var/tmp", "/tmp"} {
		dir, err := os.MkdirTemp(base, "fairy-trust-test-")
		if err != nil {
			continue
		}
		ok := os.Chmod(dir, 0o755) == nil
		for p := dir; ok && p != "/"; p = filepath.Dir(p) {
			st, err := os.Stat(p)
			ok = err == nil && st.Mode().Perm()&0o001 != 0
		}
		if ok {
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			return dir
		}
		_ = os.RemoveAll(dir)
	}
	t.Skip("no folder that another user can reach")
	return ""
}

// installRig is a state folder laid out as deploy/install.sh and the unit do it: <base>/fairy-agent, mode 0700,
// owned by the agent's service user (here uid and gid 4242, a user that does not have to exist).
type installRig struct {
	t                 *testing.T
	base, dir, path   string
	cfg, prog         string
	agentUID, someUID uint32
}

func newInstallRig(t *testing.T, dirOwner uint32) *installRig {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: it makes a folder that belongs to another user and runs the command as root and as two other users")
	}
	roottest.NeedOtherUsers(t)
	r := &installRig{t: t, base: reachableDir(t), agentUID: 4242, someUID: 4343}
	r.dir = filepath.Join(r.base, "fairy-agent")
	r.path = filepath.Join(r.dir, approval.TrustFileName)
	r.cfg = filepath.Join(r.base, "config.yaml")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(r.cfg, []byte("# test\n"), 0o644))
	// this test program, where the other users can start it
	self, err := os.ReadFile(os.Args[0])
	must(err)
	r.prog = filepath.Join(r.base, "prog")
	must(os.WriteFile(r.prog, self, 0o755))
	must(os.Mkdir(r.dir, 0o700))
	must(os.Chown(r.dir, int(dirOwner), int(dirOwner)))
	return r
}

// as runs one of the test program's parts as uid (0: root) and returns its exit code and output.
func (r *installRig) as(uid uint32, part string, args ...string) (int, string) {
	r.t.Helper()
	cmd := exec.Command(r.prog, args...)
	cmd.Env = append(os.Environ(), "FAIRY_TEST_TRUST="+part, "FAIRY_TEST_TRUST_FILE="+r.path)
	if uid != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		r.t.Fatalf("%s %v as uid %d: %v", part, args, uid, err)
	}
	return code, out.String()
}

func (r *installRig) trust(args ...string) (int, string) {
	return r.as(0, "cmd", append(args, "--config", r.cfg)...)
}

// agentSees is the approval state the running agent (the service user) reads from the trust file.
func (r *installRig) agentSees() api.ApprovalStatus {
	r.t.Helper()
	code, out := r.as(r.agentUID, "agent", "state")
	var st api.ApprovalStatus
	if code != 0 || json.Unmarshal([]byte(out), &st) != nil {
		r.t.Fatalf("the agent's view: %d %s", code, out)
	}
	return st
}

func (r *installRig) owner(path string) (uid uint32, mode os.FileMode, links uint64) {
	r.t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		r.t.Fatal(err)
	}
	sys := st.Sys().(*syscall.Stat_t)
	return sys.Uid, st.Mode(), uint64(sys.Nlink)
}

// TestHelperTrustAsRootOnAStandardInstall (review H1): the state folder belongs to the agent's service user,
// the agent wrote the trust file at the panel's first-time set, and root administers it: show reports what the
// agent sees, set and clear work. Before the fix show said BROKEN and set and clear failed.
func TestHelperTrustAsRootOnAStandardInstall(t *testing.T) {
	r := newInstallRig(t, 4242)
	// the panel's first-time set, as the agent's own user writes it
	if code, out := r.as(r.agentUID, "agent", "create"); code != 0 {
		t.Fatalf("the agent's own write: %d %s", code, out)
	}
	if uid, mode, _ := r.owner(r.path); uid != r.agentUID || mode.Perm() != 0o600 {
		t.Fatalf("the file the agent wrote: uid %d mode %v", uid, mode)
	}
	if st := r.agentSees(); st.State != api.ApprovalRequired {
		t.Fatalf("the agent's view: %+v", st)
	}
	// show, as root: what the agent sees, and it says as whom it looked
	code, out := r.trust("show")
	if code != 0 || !strings.Contains(out, "approval:        required") || !strings.Contains(out, "checked as:      uid 4242") ||
		!strings.Contains(out, "set by:          panel") || strings.Contains(out, "BROKEN") {
		t.Fatalf("show as root: %d\n%s", code, out)
	}
	// set, as root: changes one setting, keeps the rest; the file stays the agent's, one name, 0600
	code, out = r.trust("set", "--yes", "--fan-window", "10")
	if code != 0 || !strings.Contains(out, "written.") || !strings.Contains(out, "NOT PROVEN") {
		t.Fatalf("set as root: %d\n%s", code, out)
	}
	if uid, mode, links := r.owner(r.path); uid != r.agentUID || mode.Perm() != 0o600 || !mode.IsRegular() || links != 1 {
		t.Errorf("after set as root: uid %d mode %v links %d", uid, mode, links)
	}
	if st := r.agentSees(); st.State != api.ApprovalRequired || st.FanWindowS == nil || *st.FanWindowS != 10 || st.Issuer != approvaltest.IssuerURL {
		t.Fatalf("the agent's view after set: %+v", st)
	}
	// set with files only root can read (--from, --jwks in a folder that is root's alone): read before root is given up
	secret := filepath.Join(r.base, "root-only")
	if err := os.Mkdir(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	k := approval.KeyFromRSA("rotated", &approvaltest.Key(1).PublicKey)
	jw, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": k.Kid, "n": k.N, "e": k.E}}})
	if err := os.WriteFile(filepath.Join(secret, "jwks.json"), jw, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := r.trust("set", "--yes", "--jwks", filepath.Join(secret, "jwks.json"), "--keep-old-keys"); code != 0 {
		t.Fatalf("set --jwks as root: %d\n%s", code, out)
	}
	if st := r.agentSees(); len(st.Keys) != 2 || st.Keys[0].Kid != "rotated" {
		t.Fatalf("the agent's view after the rotation: %+v", st)
	}
	// nothing was left behind in the folder, and nothing in it is root's
	ents, _ := os.ReadDir(r.dir)
	for _, e := range ents {
		if uid, _, _ := r.owner(filepath.Join(r.dir, e.Name())); e.Name() != approval.TrustFileName || uid != r.agentUID {
			t.Errorf("in the state folder after the sets: %s, uid %d", e.Name(), uid)
		}
	}
	// a local user who is neither root nor the agent: no show, no set, no clear, no way to the file
	for _, sub := range []string{"show", "set", "clear"} {
		code, out := r.as(r.someUID, "cmd", sub, "--yes", "--config", r.cfg)
		if code != 1 || !strings.Contains(out, "root") {
			t.Errorf("%s as another local user: %d %s", sub, code, out)
		}
	}
	if code, out := r.as(r.someUID, "meddle"); code != 0 {
		t.Errorf("another local user got at the trust file: %s", out)
	}
	if st := r.agentSees(); st.State != api.ApprovalRequired || len(st.Keys) != 2 {
		t.Fatalf("the agent's view after another user tried: %+v", st)
	}
	// clear, as root
	code, out = r.trust("clear", "--yes")
	if code != 0 || !strings.Contains(out, "removed. Approval is off") {
		t.Fatalf("clear as root: %d\n%s", code, out)
	}
	if st := r.agentSees(); st.State != api.ApprovalOff {
		t.Fatalf("the agent's view after clear: %+v", st)
	}
	if code, out := r.trust("show"); code != 0 || !strings.Contains(out, "approval:        off") {
		t.Fatalf("show after clear: %d\n%s", code, out)
	}
	// and a first set typed on the machine, with nothing there yet
	fresh := filepath.Join(secret, "trust.json")
	tr, _ := approval.FromInit(approvaltest.New().Init(), time.Now(), nil)
	if err := os.WriteFile(fresh, tr.Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := r.trust("set", "--yes", "--from", fresh); code != 0 {
		t.Fatalf("set --from as root: %d\n%s", code, out)
	}
	if st := r.agentSees(); st.State != api.ApprovalRequired {
		t.Fatalf("the agent's view after set --from: %+v", st)
	}
}

// TestHelperTrustAsRootWithARootOwnedFile: the other owner the agent accepts. A trust file that root put into
// the agent's folder (readable by the agent's group, or not readable by it at all), and a state folder that is
// root's (an agent that runs as root).
func TestHelperTrustAsRootWithARootOwnedFile(t *testing.T) {
	r := newInstallRig(t, 4242)
	tr, _ := approval.FromInit(approvaltest.New().Init(), time.Now(), nil)
	put := func(mode os.FileMode) {
		t.Helper()
		_ = os.Remove(r.path)
		if err := os.WriteFile(r.path, tr.Marshal(), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(r.path, 0, int(r.agentUID)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(r.path, mode); err != nil {
			t.Fatal(err)
		}
	}
	// root's file, readable by the agent's group: required for the agent, and for show
	put(0o640)
	if st := r.agentSees(); st.State != api.ApprovalRequired {
		t.Fatalf("root's file, 0640: the agent sees %+v", st)
	}
	if code, out := r.trust("show"); code != 0 || !strings.Contains(out, "approval:        required") {
		t.Fatalf("show: %d\n%s", code, out)
	}
	if code, out := r.trust("set", "--yes", "--boot-shutdown", "300"); code != 0 {
		t.Fatalf("set over root's file: %d\n%s", code, out)
	}
	if uid, mode, _ := r.owner(r.path); uid != r.agentUID || mode.Perm() != 0o600 {
		t.Errorf("after set: uid %d mode %v", uid, mode)
	}
	if st := r.agentSees(); st.State != api.ApprovalRequired || *st.BootShutdownS != 300 {
		t.Fatalf("after set: the agent sees %+v", st)
	}
	// root's file that the agent cannot read: broken for the agent, and show says the same, not "required"
	put(0o600)
	if st := r.agentSees(); st.State != api.ApprovalBroken {
		t.Fatalf("root's file, 0600: the agent sees %+v", st)
	}
	if code, out := r.trust("show"); code != 0 || !strings.Contains(out, "BROKEN") {
		t.Fatalf("show of a file the agent cannot read: %d\n%s", code, out)
	}
	if code, out := r.trust("clear", "--yes"); code != 0 {
		t.Fatalf("clear of root's file: %d\n%s", code, out)
	}
	if st := r.agentSees(); st.State != api.ApprovalOff {
		t.Fatalf("after clear: the agent sees %+v", st)
	}

	// a link planted where the trust file belongs, pointing at a file of root's: the command, which works as
	// the folder's owner, replaces the link and does not touch the file behind it
	victim := filepath.Join(r.base, "victim")
	if err := os.WriteFile(victim, []byte("root's own file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, r.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(r.path, int(r.agentUID), int(r.agentUID)); err != nil {
		t.Fatal(err)
	}
	if code, out := r.trust("show"); code != 0 || !strings.Contains(out, "BROKEN") {
		t.Fatalf("show with a link: %d\n%s", code, out)
	}
	src := filepath.Join(r.base, "trust.json")
	if err := os.WriteFile(src, tr.Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := r.trust("set", "--yes", "--from", src); code != 0 || !strings.Contains(out, "will be replaced") {
		t.Fatalf("set over a link: %d\n%s", code, out)
	}
	if b, _ := os.ReadFile(victim); string(b) != "root's own file\n" {
		t.Errorf("the file behind the link was changed: %q", b)
	}
	if uid, mode, _ := r.owner(victim); uid != 0 || mode.Perm() != 0o644 {
		t.Errorf("the file behind the link: uid %d mode %v", uid, mode)
	}
	if uid, mode, _ := r.owner(r.path); uid != r.agentUID || !mode.IsRegular() {
		t.Errorf("the trust file after set over a link: uid %d mode %v", uid, mode)
	}

	// a state folder that is root's (the agent runs as root): root works as root, the file is root's
	rr := newInstallRig(t, 0)
	if code, out := rr.trust("set", "--yes", "--from", src); code != 0 {
		t.Fatalf("set in root's folder: %d\n%s", code, out)
	}
	if uid, mode, _ := rr.owner(rr.path); uid != 0 || mode.Perm() != 0o640 {
		t.Errorf("in root's folder: uid %d mode %v", uid, mode)
	}
	if code, out := rr.trust("show"); code != 0 || !strings.Contains(out, "approval:        required") || strings.Contains(out, "checked as") {
		t.Fatalf("show in root's folder: %d\n%s", code, out)
	}
	if code, out := rr.as(rr.someUID, "cmd", "show", "--config", rr.cfg); code != 1 || !strings.Contains(out, "as root") {
		t.Errorf("show as another local user in root's folder: %d %s", code, out)
	}
	if code, out := rr.trust("clear", "--yes"); code != 0 {
		t.Fatalf("clear in root's folder: %d\n%s", code, out)
	}
}

// TestTrustFileFromBeforeMachineIDsOnAnInstall (audit 5, r1-x1-01): what happens to a trust file of the test
// build of 2026-11-11, which has no machine id, on a machine laid out as the installer does it. The agent adds
// the id when it starts, and the file is afterwards whose it was, with the mode it had. Where the agent cannot
// do that (the file is root's and the agent is not root), nothing changes and the state is broken, with the
// reason, until root runs helper-trust set.
func TestTrustFileFromBeforeMachineIDsOnAnInstall(t *testing.T) {
	old, err := approval.FromInit(approvaltest.New().Init(), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	old.MachineID = ""
	raw := old.Marshal()
	put := func(r *installRig, uid, gid int, mode os.FileMode) {
		t.Helper()
		_ = os.Remove(r.path)
		for _, err := range []error{os.WriteFile(r.path, raw, mode), os.Chown(r.path, uid, gid), os.Chmod(r.path, mode)} {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	group := func(path string) uint32 {
		t.Helper()
		st, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		return st.Sys().(*syscall.Stat_t).Gid
	}
	only := func(r *installRig) {
		t.Helper()
		ents, _ := os.ReadDir(r.dir)
		if len(ents) != 1 || ents[0].Name() != approval.TrustFileName {
			t.Errorf("in the state folder: %v", ents)
		}
	}

	t.Run("the agent's own file, as the first-time set wrote it", func(t *testing.T) {
		r := newInstallRig(t, 4242)
		put(r, 4242, 4242, 0o600)
		// show, as root, only looks: it says what is wrong and writes nothing
		code, out := r.trust("show")
		if code != 0 || !strings.Contains(out, "BROKEN") || !strings.Contains(out, "has no machine_id") {
			t.Fatalf("show: %d\n%s", code, out)
		}
		if now, _ := os.ReadFile(r.path); !bytes.Equal(now, raw) {
			t.Fatal("show wrote the file")
		}
		st := r.agentSees() // the agent starts
		if st.State != api.ApprovalRequired || api.CheckMachineID(st.MachineID) != nil {
			t.Fatalf("the agent after its start: %+v", st)
		}
		if uid, mode, links := r.owner(r.path); uid != r.agentUID || group(r.path) != 4242 || mode.Perm() != 0o600 || !mode.IsRegular() || links != 1 {
			t.Errorf("the file after the id was added: uid %d gid %d mode %v links %d", uid, group(r.path), mode, links)
		}
		only(r)
		now, _ := os.ReadFile(r.path)
		if want := "{\n  \"machine_id\": \"" + st.MachineID + "\"," + string(raw[1:]); string(now) != want {
			t.Errorf("the file:\n%s\nwant\n%s", now, want)
		}
		if again := r.agentSees(); again.MachineID != st.MachineID { // the next start
			t.Errorf("the id at the next start: %q, was %q", again.MachineID, st.MachineID)
		}
		if later, _ := os.ReadFile(r.path); !bytes.Equal(later, now) {
			t.Error("the file was written again at the next start")
		}
		if code, out := r.trust("show"); code != 0 || !strings.Contains(out, "machine id:      "+st.MachineID) {
			t.Errorf("show afterwards: %d\n%s", code, out)
		}
	})

	t.Run("root's file in the agent's folder, readable by the agent's group", func(t *testing.T) {
		r := newInstallRig(t, 4242)
		put(r, 0, 4242, 0o640)
		st := r.agentSees() // the agent is not root: it cannot make the new file root's, and does not try
		if st.State != api.ApprovalBroken || st.MachineID != "" || !strings.Contains(st.Error, "has no machine_id, and adding one failed") ||
			!strings.Contains(st.Error, "the trust file belongs to user 0, group 4242, but this service is user 4242, group 4242") || // cut here: the test folder has a long name
			!strings.HasSuffix(st.Error, "repair on the machine: fairy-agent helper-trust set)") {
			t.Fatalf("the agent: %+v", st)
		}
		if uid, mode, _ := r.owner(r.path); uid != 0 || group(r.path) != 4242 || mode.Perm() != 0o640 {
			t.Errorf("the file: uid %d mode %v", uid, mode)
		}
		if now, _ := os.ReadFile(r.path); !bytes.Equal(now, raw) {
			t.Error("the file changed")
		}
		only(r)
		// root repairs it: the values are kept, the file gets an id
		code, out := r.trust("set", "--yes", "--jwks", writeJWKSFile(t, r.base, old.Keys))
		if code != 0 || !strings.Contains(out, "its values are kept and it gets one now") {
			t.Fatalf("set: %d\n%s", code, out)
		}
		if st := r.agentSees(); st.State != api.ApprovalRequired || api.CheckMachineID(st.MachineID) != nil || st.Issuer != approvaltest.IssuerURL || st.Users != 1 {
			t.Fatalf("the agent after root's set: %+v", st)
		}
	})

	t.Run("an agent that runs as root", func(t *testing.T) {
		r := newInstallRig(t, 0)
		if err := os.Chown(r.dir, 0, 4242); err != nil {
			t.Fatal(err)
		}
		put(r, 0, 4242, 0o640)
		code, out := r.as(0, "agent", "state")
		var st api.ApprovalStatus
		if code != 0 || json.Unmarshal([]byte(out), &st) != nil || st.State != api.ApprovalRequired || api.CheckMachineID(st.MachineID) != nil {
			t.Fatalf("the agent as root: %d %s", code, out)
		}
		if uid, mode, links := r.owner(r.path); uid != 0 || group(r.path) != 4242 || mode.Perm() != 0o640 || links != 1 {
			t.Errorf("the file after the id was added: uid %d gid %d mode %v links %d", uid, group(r.path), mode, links)
		}
		only(r)
	})
}

// writeJWKSFile writes keys as a JWKS file in dir (a folder root can read) and returns its name.
func writeJWKSFile(t *testing.T, dir string, keys []api.TrustKey) string {
	t.Helper()
	var list []any
	for _, k := range keys {
		list = append(list, map[string]any{"kty": k.Kty, "kid": k.Kid, "alg": k.Alg, "n": k.N, "e": k.E})
	}
	b, _ := json.Marshal(map[string]any{"keys": list})
	name := filepath.Join(dir, "jwks-for-set.json")
	if err := os.WriteFile(name, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}
