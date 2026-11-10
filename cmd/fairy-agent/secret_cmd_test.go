package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

// `fairy-agent secret set` and `fairy-agent bmc-relay add`: a laptop's BMC relay setup, end to end on a temp
// config folder.
func TestSecretSetAndBMCRelayAdd(t *testing.T) {
	if !isAdmin() || runtime.GOOS == "windows" { // Windows needs the installed service's account for the ACL
		t.Skip("needs root (and the installed service on Windows)")
	}
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("# Laptop\npower_control:\n  enabled: false\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	for f, v := range map[string]string{"token": strings.Repeat("r", 30), "control-token": strings.Repeat("c", 30)} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out, errb bytes.Buffer
	if code := secretCmd([]string{"set", "BMC_SERVER_PASSWORD", "--config", p}, strings.NewReader("s3cret pass!\n"), &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	if strings.Contains(out.String(), "s3cret") {
		t.Fatal("the value was printed", out.String())
	}
	env := filepath.Join(dir, "secrets.env")
	b, _ := os.ReadFile(env)
	if !strings.Contains(string(b), "BMC_SERVER_PASSWORD=s3cret pass!\n") {
		t.Fatal(string(b))
	}
	if st, _ := os.Stat(env); st.Mode().Perm() != 0o640 {
		t.Fatal(st.Mode())
	}
	// again: replaced, not added twice; other lines kept
	_ = os.WriteFile(env, append(b, []byte("OTHER=1\n")...), 0o640)
	if code := secretCmd([]string{"set", "BMC_SERVER_PASSWORD", "--config", p}, strings.NewReader("new\n"), &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	b, _ = os.ReadFile(env)
	if strings.Count(string(b), "BMC_SERVER_PASSWORD=") != 1 || !strings.Contains(string(b), "BMC_SERVER_PASSWORD=new\n") || !strings.Contains(string(b), "OTHER=1") {
		t.Fatal(string(b))
	}
	for _, bad := range []string{"\n", " padded \n"} {
		if code := secretCmd([]string{"set", "BMC_SERVER_PASSWORD", "--config", p}, strings.NewReader(bad), &out, &errb); code != 1 {
			t.Fatalf("%q accepted", bad)
		}
	}
	if code := secretCmd([]string{"set", "FAIRY_AGENT_TOKEN", "--config", p}, strings.NewReader("x\n"), &out, &errb); code != 1 {
		t.Fatal("FAIRY_ names are the agent's own")
	}
	errb.Reset()
	code := bmcRelayCmd([]string{"add", "--config", p, "--id", "server-bmc", "--backend", "ipmitool", "--host", "192.168.1.5",
		"--username", "fairy", "--password-env", "BMC_SERVER_PASSWORD", "--cipher-suite", "17"}, &out, &errb)
	if code != 0 {
		t.Fatal(code, errb.String())
	}
	cfg, err := agent.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	tg := cfg.BMCRelay.Targets
	if !cfg.BMCRelay.Enabled || len(tg) != 1 || tg[0].Host != "192.168.1.5" || *tg[0].CipherSuite != 17 || cfg.EnvFile != env {
		t.Fatalf("%+v", cfg.BMCRelay)
	}
	if c, _ := os.ReadFile(p); !strings.HasPrefix(string(c), "# Laptop\n") {
		t.Fatal("comments lost", string(c))
	}
	if code := bmcRelayCmd([]string{"add", "--config", p, "--id", "x", "--host", "8.8.8.8", "--username", "u", "--password-env", "P"}, &out, &errb); code != 1 {
		t.Fatal("second target / public address accepted")
	}
}
