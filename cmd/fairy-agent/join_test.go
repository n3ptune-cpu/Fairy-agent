package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

func runJoin(t *testing.T, f func([]string, *bytes.Buffer, *bytes.Buffer) int, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := f(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestJoin(t *testing.T) {
	if !isAdmin() {
		t.Skip("join needs root / Administrator")
	}
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	dir, state := t.TempDir(), t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	code, _ := enroll.NewCode()
	join := func(a []string, o, e *bytes.Buffer) int { return joinCmd(a, o, e) }
	args := []string{"--code", strings.ToLower(code), "--panel", "100.88.109.47", "--config", cfgPath, "--state-dir", state,
		"--power-control", "--self-update", "--wol", "--ups-name", "cyberpower"}
	rc, out, errs := runJoin(t, join, args...)
	if rc != 0 {
		t.Fatal(rc, out, errs)
	}
	for _, want := range []string{"wrote a starter", "created", "shutdown / reboot", "self-update", "Wake-on-LAN", "UPS from the local NUT server cyberpower", "join code stored"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	tok, _ := os.ReadFile(filepath.Join(dir, "token"))
	if strings.Contains(out, strings.TrimSpace(string(tok))) || strings.Contains(out, strings.ReplaceAll(code, "-", "")) {
		t.Fatal("join printed a secret")
	}
	cfg, err := agent.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PowerControl.Enabled || !cfg.SelfUpdate.Enabled || !cfg.WOL.Enabled || len(cfg.UPS) != 1 || cfg.UPS[0]["host"] != "127.0.0.1" {
		t.Fatalf("config: %+v %v", cfg.PowerControl, cfg.UPS)
	}
	tokens, err := cfg.LoadTokens()
	if err != nil || tokens.Control == "" {
		t.Fatal(tokens.Control == "", err)
	}
	st, err := enroll.ReadState(filepath.Join(state, "pairing.json"))
	proof, _ := enroll.Proof(code)
	if err != nil || !st.Active(time.Now()) || st.Panel != "100.88.109.47" || !enroll.Check(proof, st.Verifier) {
		t.Fatalf("state: %+v %v", st, err)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "pairing.json")); bytes.Contains(b, []byte(strings.ReplaceAll(code, "-", ""))) {
		t.Fatal("the code itself was stored")
	}
	if rc, out, _ := runJoin(t, func(a []string, o, e *bytes.Buffer) int { return pairStatus(a, o, e) }, "--state-dir", state); rc != 3 || !strings.Contains(out, "waiting") {
		t.Fatal(rc, out)
	}

	// a re-run (re-pair) keeps the tokens and the UPS entry, stores the new code
	code2, _ := enroll.NewCode()
	args[1] = code2
	rc, out, errs = runJoin(t, join, args...)
	if rc != 0 || strings.Contains(out, "created") || !strings.Contains(out, "already lists UPSes") {
		t.Fatal(rc, out, errs)
	}
	if tok2, _ := os.ReadFile(filepath.Join(dir, "token")); !bytes.Equal(tok, tok2) {
		t.Fatal("token replaced")
	}
	st, _ = enroll.ReadState(filepath.Join(state, "pairing.json"))
	p2, _ := enroll.Proof(code2)
	if !enroll.Check(p2, st.Verifier) {
		t.Fatal("new code not stored")
	}

	for _, bad := range [][]string{{"--code", "nope", "--panel", "100.64.0.1"}, {"--code", code}, {"--code", code, "--panel", "panel.ts.net"},
		{"--code", code, "--panel", "100.64.0.1", "--ups-name", "a b"}, {"--code", code, "--panel", "100.64.0.1", "extra"}} {
		if rc, _, _ := runJoin(t, join, append(bad, "--config", cfgPath, "--state-dir", state)...); rc != 2 {
			t.Fatal(bad, rc)
		}
	}
	if rc, _, errs := runJoin(t, join, "--code", code, "--panel", "100.64.0.1", "--config", filepath.Join(dir, "nope", "c.yaml"), "--state-dir", state); rc != 1 || !strings.Contains(errs, "install the agent first") {
		t.Fatal(rc, errs)
	}
}

func TestVerifyRelease(t *testing.T) {
	pub, priv, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	k, _ := release.ParsePrivateKey(priv)
	dir := t.TempDir()
	files := map[string][]byte{"fairy-agent-linux-amd64": []byte("binary"), "install.sh": []byte("#!/bin/sh\n"),
		"VERSION": []byte("fairy-agent 9-abcdef0\n")}
	names := []string{"fairy-agent-linux-amd64", "install.sh", "VERSION"}
	sums := release.FormatSums(names, files)
	for n, b := range files {
		os.WriteFile(filepath.Join(dir, n), b, 0o644)
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), sums, 0o644)
	os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), release.Sign(k, sums), 0o644)
	vr := func(a []string, o, e *bytes.Buffer) int { return verifyRelease(a, o, e) }

	old := releaseKey
	t.Cleanup(func() { releaseKey = old })
	releaseKey = ""
	if rc, _, _ := runJoin(t, vr, dir); rc != 3 {
		t.Fatal("no key:", rc)
	}
	releaseKey = pub
	if rc, out, errs := runJoin(t, vr, dir); rc != 0 || !strings.Contains(out, "signature OK") || !strings.Contains(out, "install.sh") {
		t.Fatal(rc, out, errs)
	}
	os.WriteFile(filepath.Join(dir, "install.sh"), []byte("#!/bin/sh\nevil\n"), 0o644)
	if rc, _, _ := runJoin(t, vr, dir); rc != 1 {
		t.Fatal("tampered file accepted")
	}
	os.WriteFile(filepath.Join(dir, "install.sh"), files["install.sh"], 0o644)
	other, _, _ := release.GenerateKey()
	releaseKey = other
	if rc, _, _ := runJoin(t, vr, dir); rc != 1 {
		t.Fatal("other key accepted")
	}
}
