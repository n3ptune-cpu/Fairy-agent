package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

// fakeDataDirCheck replaces dataDirTrusted (the Windows check; a no-op elsewhere) for one test and returns the
// list of config paths it was asked about. With refuse it answers what the real check says about a config.yaml
// an ordinary user prepared.
func fakeDataDirCheck(t *testing.T, refuse bool) *[]string {
	t.Helper()
	old := dataDirTrusted
	t.Cleanup(func() { dataDirTrusted = old })
	asked := &[]string{}
	dataDirTrusted = func(p string) error {
		*asked = append(*asked, p)
		if refuse {
			return errors.New("the data folder cannot be trusted: " + p + " is owned by " + tUser + repairHint)
		}
		return nil
	}
	return asked
}

// stderrOf runs f with os.Stderr going to a pipe (localUpdate writes there) and returns what was written.
func stderrOf(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	f()
	os.Stderr = old
	w.Close()
	return <-done
}

// The commands an administrator types that act on config.yaml (`update`, `config set`, `secret set`,
// `bmc-relay add`, `fans-auto`) make the same data folder check as join, before they read config.yaml: a
// config.yaml someone else prepared neither names the file an administrator's secret is written to, nor the
// repository an update comes from, nor is it edited.
func TestTypedCommandsRefuseAnUntrustedDataFolder(t *testing.T) {
	if !isAdmin() {
		t.Skip("the check is made for an administrator; see TestTypedCommandsDoNotCheckWithoutAdminRights")
	}
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	victim := filepath.Join(t.TempDir(), "readable-by-the-planter.env")
	planted := "# planted\nenv_file: " + victim + "\nself_update:\n  repo: someone-else/not-fairy\nfan_control:\n  enabled: false\n"
	if err := os.WriteFile(p, []byte(planted), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(strings.Repeat("r", 30)), 0o600); err != nil {
		t.Fatal(err)
	}
	asked := fakeDataDirCheck(t, true)
	refused := func(what string, code int, stdout, stderr, wantPath string) {
		t.Helper()
		if code != 1 || !strings.Contains(stderr, "cannot be trusted") || !strings.Contains(stderr, "setup-self-update") {
			t.Fatalf("%s: exit %d, stderr %q", what, code, stderr)
		}
		if stdout != "" {
			t.Fatalf("%s: wrote %q although it was refused", what, stdout)
		}
		if len(*asked) != 1 || (*asked)[0] != wantPath {
			t.Fatalf("%s: the check was asked about %q, want once about %q", what, *asked, wantPath)
		}
		*asked = nil
		if b, _ := os.ReadFile(p); string(b) != planted {
			t.Fatalf("%s: config.yaml was changed: %q", what, b)
		}
		for _, f := range []string{victim, filepath.Join(dir, "secrets.env")} {
			if _, err := os.Lstat(f); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s: wrote %s", what, f)
			}
		}
	}

	var out, errb bytes.Buffer
	code := configCmd([]string{"set", "fan_control.enabled", "true", "--config", p}, &out, &errb)
	refused("config set", code, out.String(), errb.String(), p)

	// secret set: refused before the value is asked for (nothing is read from standard input), and nothing is
	// written to the file the planted config.yaml names
	out.Reset()
	errb.Reset()
	in := strings.NewReader("s3cret pass!\n")
	code = secretCmd([]string{"set", "BMC_CYRENE_PASSWORD", "--config", p}, in, &out, &errb)
	refused("secret set", code, out.String(), errb.String(), p)
	if in.Len() != len("s3cret pass!\n") {
		t.Fatal("secret set read the value before it refused")
	}
	if strings.Contains(out.String()+errb.String(), "s3cret") {
		t.Fatal("the value was printed")
	}

	out.Reset()
	errb.Reset()
	code = bmcRelayCmd([]string{"add", "--config", p, "--id", "cyrene-bmc", "--backend", "ipmitool", "--host", "192.168.254.254",
		"--username", "fairy", "--password-env", "BMC_CYRENE_PASSWORD"}, &out, &errb)
	refused("bmc-relay add", code, out.String(), errb.String(), p)

	// fans-auto always reads the installed config.yaml: that is the path it asks about
	out.Reset()
	errb.Reset()
	code = fansAutoCmd(nil, &out, &errb)
	refused("fans-auto", code, out.String(), errb.String(), agent.DefaultConfigPath())
	// ... and an argument is still refused before anything else (exit 2, the check is not even asked)
	if code := fansAutoCmd([]string{"--config", p}, &out, &errb); code != 2 || len(*asked) != 0 {
		t.Fatal(code, *asked)
	}

	// update, also with --check and --force: refused before config.yaml is read and before any download (the
	// planted repository is never asked: there is no network request in this test)
	for _, c := range []struct{ check, yes, force bool }{{true, false, false}, {false, true, false}, {false, true, true}} {
		code := 0
		msg := stderrOf(t, func() { code = localUpdate(p, c.check, c.yes, c.force) })
		refused("update", code, "", msg, p)
		if !strings.HasPrefix(msg, "fairy-agent update: ") {
			t.Fatal(msg)
		}
	}

	// reading only is not refused: get and show print what the file says and change nothing
	for _, args := range [][]string{{"get", "fan_control.enabled", "--config", p}, {"show", "--config", p}} {
		out.Reset()
		errb.Reset()
		if code := configCmd(args, &out, &errb); code != 0 || out.Len() == 0 || len(*asked) != 0 {
			t.Fatal(args, code, errb.String(), *asked)
		}
	}
}

// With a data folder that passes, each command asks once, about the config.yaml it was given, and then works
// as before. configSet itself does not ask: join calls it for the feature switches after its own check.
func TestTypedCommandsAskOnceAboutTheirConfig(t *testing.T) {
	if !isAdmin() || runtime.GOOS == "windows" { // as TestSecretSetAndBMCRelayAdd
		t.Skip("needs root (and the installed service on Windows)")
	}
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("fan_control:\n  enabled: false\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	for f, v := range map[string]string{"token": strings.Repeat("r", 30), "control-token": strings.Repeat("c", 30)} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	asked := fakeDataDirCheck(t, false)
	once := func(what string, code int, stderr string) {
		t.Helper()
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", what, code, stderr)
		}
		if len(*asked) != 1 || (*asked)[0] != p {
			t.Fatalf("%s: the check was asked about %q, want once about %q", what, *asked, p)
		}
		*asked = nil
	}
	var out, errb bytes.Buffer
	once("config set", configCmd([]string{"set", "fan_control.auto_mode", "standard", "--config=" + p}, &out, &errb), errb.String())
	// secret set writes secrets.env and then sets env_file through configSet: still one question
	once("secret set", secretCmd([]string{"set", "BMC_CYRENE_PASSWORD", "--config", p}, strings.NewReader("s3cret\n"), &out, &errb), errb.String())
	once("bmc-relay add", bmcRelayCmd([]string{"add", "--config", p, "--id", "cyrene-bmc", "--backend", "ipmitool", "--host", "192.168.254.254",
		"--username", "fairy", "--password-env", "BMC_CYRENE_PASSWORD"}, &out, &errb), errb.String())
	cfg, err := agent.Load(p)
	if err != nil || !cfg.BMCRelay.Enabled || cfg.EnvFile != filepath.Join(dir, "secrets.env") {
		t.Fatal(err, cfg)
	}

	// configSet (what join calls) is not held back by the check and does not ask it
	dataDirTrusted = func(string) error { t.Error("configSet asked the data folder check"); return errors.New("no") }
	if err := configSet(p, "fan_control.auto_mode", "optimal", io.Discard); err != nil {
		t.Fatal(err)
	}
}

// Without administrator rights nothing is checked (on Windows such a run cannot even read the folder's
// permissions) and nothing changes: the commands that write refuse by themselves, with their own message.
// And off Windows the real check never refuses anything.
func TestTypedCommandsDoNotCheckWithoutAdminRights(t *testing.T) {
	if runtime.GOOS != "windows" {
		if err := dataDirTrusted(filepath.Join(t.TempDir(), "nothing", "config.yaml")); err != nil {
			t.Fatal("the data folder check is for Windows only:", err)
		}
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("fan_control:\n  enabled: false\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	asked := fakeDataDirCheck(t, true)
	err := adminDataDirTrusted(p)
	if isAdmin() {
		if err == nil || len(*asked) != 1 || (*asked)[0] != p {
			t.Fatal(err, *asked)
		}
		return
	}
	if err != nil || len(*asked) != 0 {
		t.Fatal(err, *asked)
	}
	var out, errb bytes.Buffer
	if code := configCmd([]string{"set", "fan_control.enabled", "true", "--config", p}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "run it") {
		t.Fatal(code, errb.String())
	}
	errb.Reset()
	if code := secretCmd([]string{"set", "BMC_CYRENE_PASSWORD", "--config", p}, strings.NewReader("x\n"), &out, &errb); code != 1 || !strings.Contains(errb.String(), "run it") {
		t.Fatal(code, errb.String())
	}
	errb.Reset()
	if code := bmcRelayCmd([]string{"add", "--config", p, "--id", "x", "--host", "192.168.1.2", "--username", "u", "--password-env", "P"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "run it") {
		t.Fatal(code, errb.String())
	}
	if b, _ := os.ReadFile(p); string(b) != "fan_control:\n  enabled: false\n" || len(*asked) != 0 {
		t.Fatal(string(b), *asked)
	}
}
