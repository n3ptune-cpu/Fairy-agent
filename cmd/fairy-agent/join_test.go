package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
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

	// a re-run (re-pair) issues NEW read and control tokens (the old ones are gone), keeps the settings and the
	// UPS entry, and stores the new code
	ctl, _ := os.ReadFile(filepath.Join(dir, "control-token"))
	code2, _ := enroll.NewCode()
	args[1] = code2
	rc, out, errs = runJoin(t, join, args...)
	if rc != 0 || strings.Contains(out, "created") || !strings.Contains(out, "new token in") || !strings.Contains(out, "already lists UPSes") {
		t.Fatal(rc, out, errs)
	}
	tok2, _ := os.ReadFile(filepath.Join(dir, "token"))
	ctl2, _ := os.ReadFile(filepath.Join(dir, "control-token"))
	if bytes.Equal(tok, tok2) || bytes.Equal(ctl, ctl2) || bytes.Equal(tok2, ctl2) || len(bytes.TrimSpace(tok2)) < agent.MinTokenLen {
		t.Fatal("re-pair must replace both tokens")
	}
	if strings.Contains(out, strings.TrimSpace(string(tok2))) {
		t.Fatal("join printed a secret")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 3 { // config.yaml, token, control-token: no temp files left
		t.Fatal(ents)
	}
	if st, _ := os.Stat(filepath.Join(dir, "token")); runtime.GOOS != "windows" && st.Mode().Perm() != 0o640 {
		t.Fatal(st.Mode())
	}
	if cfg, err := agent.Load(cfgPath); err != nil || !cfg.PowerControl.Enabled {
		t.Fatal("settings kept", err)
	} else if tk, err := cfg.LoadTokens(); err != nil || tk.Read != strings.TrimSpace(string(tok2)) {
		t.Fatal("the agent loads the new token", err)
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

// joinDirect runs parseJoin and join without the root / Administrator check of joinCmd, in temporary folders.
func joinDirect(t *testing.T, args ...string) (enroll.State, []byte, string) {
	t.Helper()
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	dir, state := t.TempDir(), t.TempDir()
	var out, errb bytes.Buffer
	o, err := parseJoin(append(args, "--config", filepath.Join(dir, "config.yaml"), "--state-dir", state), &errb)
	if err != nil {
		t.Fatal(err, errb.String())
	}
	if err := join(o, &out); err != nil {
		t.Fatal(err, out.String())
	}
	path := filepath.Join(state, "pairing.json")
	st, err := enroll.ReadState(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	return st, raw, out.String()
}

// M3: --pair-v2 stores the v2 pairing key and no v1 verifier; without it the state is what it always was, so
// an old panel's command still pairs the old way.
func TestJoinPairV2(t *testing.T) {
	code, _ := enroll.NewCode()
	bare := strings.ReplaceAll(code, "-", "")
	proof, _ := enroll.Proof(code)
	key, _ := enroll.PairingKey(code)

	st, raw, out := joinDirect(t, "--code", code, "--panel", "100.88.109.47", "--pair-v2")
	if st.PairVersion() != 2 || st.Verifier != "" || !st.Active(time.Now()) || st.Panel != "100.88.109.47" {
		t.Fatalf("v2 state: %+v", st)
	}
	if k, err := st.PairingKey2(); err != nil || !bytes.Equal(k, key) {
		t.Fatalf("stored key: %x %v", k, err)
	}
	for _, secret := range []string{bare, code, proof, enroll.Verifier(proof)} {
		if bytes.Contains(raw, []byte(secret)) || strings.Contains(out, secret) {
			t.Fatalf("%q in the v2 state or the output", secret)
		}
	}
	if strings.Contains(out, st.Key2) || !strings.Contains(out, "pairing v2") || !strings.Contains(out, "join code stored") {
		t.Fatalf("output:\n%s", out)
	}
	// the stored key is the one a panel derives from the same code: its request checks, another code's does not
	req, _ := enroll.NewRequestV2(key)
	stored, _ := st.PairingKey2()
	if err := enroll.CheckRequestV2(stored, req); err != nil {
		t.Fatal(err)
	}

	st, raw, out = joinDirect(t, "--code", code, "--panel", "100.88.109.47")
	if st.PairVersion() != 1 || st.Key2 != "" || !enroll.Check(proof, st.Verifier) || bytes.Contains(raw, []byte("key2")) || strings.Contains(out, "pairing v2") {
		t.Fatalf("v1 state: %+v\n%s", st, out)
	}
}

// L20: the join code does not have to be on the command line (where every local user can read it while the
// installer runs): --code-stdin reads it from standard input, FAIRY_JOIN_CODE from the environment. --code
// stays for the commands of older panels.
func TestJoinCodeNotInArgv(t *testing.T) {
	code, _ := enroll.NewCode()
	bare := strings.ReplaceAll(code, "-", "")
	proof, _ := enroll.Proof(code)
	stdin := func(text string) {
		old := joinStdin
		joinStdin = strings.NewReader(text)
		t.Cleanup(func() { joinStdin = old })
	}
	parse := func(args ...string) (joinOpts, string, error) {
		var errb bytes.Buffer
		o, err := parseJoin(append(args, "--panel", "100.88.109.47", "--config", filepath.Join(t.TempDir(), "config.yaml"), "--state-dir", t.TempDir()), &errb)
		return o, errb.String(), err
	}
	same := func(o joinOpts) bool { n, err := enroll.Normalize(o.code); return err == nil && n == bare }

	// standard input, in the spellings an installer or a person produces
	for _, text := range []string{code, code + "\n", code + "\r\n", strings.ToLower(code) + "\n", "  " + bare + "  \n", "\ufeff" + code + "\r\n", code + "\nsecond line\n"} {
		t.Setenv(joinCodeEnv, "")
		stdin(text)
		o, _, err := parse("--code-stdin")
		if err != nil || !same(o) {
			t.Fatalf("stdin %q: %q %v", text, o.code, err)
		}
	}
	// the environment variable, which join takes out of its own environment (its child processes do not get it)
	t.Setenv(joinCodeEnv, code)
	stdin("")
	if o, _, err := parse(); err != nil || !same(o) {
		t.Fatalf("environment: %q %v", o.code, err)
	}
	if v, ok := os.LookupEnv(joinCodeEnv); ok {
		t.Fatalf("%s still set after parsing: %q", joinCodeEnv, v)
	}
	// --code-stdin and --code win over the environment
	other, _ := enroll.NewCode()
	t.Setenv(joinCodeEnv, other)
	stdin(code + "\n")
	if o, _, err := parse("--code-stdin"); err != nil || !same(o) {
		t.Fatalf("stdin over environment: %q %v", o.code, err)
	}
	t.Setenv(joinCodeEnv, other)
	if o, _, err := parse("--code", code); err != nil || !same(o) {
		t.Fatalf("--code over environment: %q %v", o.code, err)
	}
	if _, ok := os.LookupEnv(joinCodeEnv); ok {
		t.Fatal("the environment variable outlived a join that did not use it")
	}
	// refused: nothing to read, a code with a line break inside, a wrong code, both sources, none
	t.Setenv(joinCodeEnv, "")
	for _, bad := range []string{"", "\n", "\n" + code + "\n", bare[:16] + "\n" + bare[16:] + "\n", "nope\n", code + "A\n", strings.Repeat("A", 5000)} {
		stdin(bad)
		if o, _, err := parse("--code-stdin"); err == nil {
			t.Fatalf("stdin %q accepted as %q", bad, o.code)
		}
	}
	stdin(code + "\n")
	if _, _, err := parse("--code-stdin", "--code", code); err == nil || !strings.Contains(err.Error(), "exclude") {
		t.Fatalf("both: %v", err)
	}
	if _, _, err := parse(); err == nil || !strings.Contains(err.Error(), "--code-stdin") {
		t.Fatalf("no code at all: %v", err)
	}
	// joinCmd reports these as usage errors (2) and never echoes what it read
	stdin(bare[:31] + "!\n")
	var out, errb bytes.Buffer
	if rc := joinCmd([]string{"--code-stdin", "--panel", "100.88.109.47"}, &out, &errb); rc != 2 || strings.Contains(out.String()+errb.String(), bare[:31]) {
		t.Fatalf("bad code on stdin: %d %q %q", rc, out.String(), errb.String())
	}

	// end to end: the state is the same as with --code, and the code is in no argument
	stdin(code + "\n")
	args := []string{"--code-stdin", "--panel", "100.88.109.47"}
	st, raw, outText := joinDirect(t, args...)
	if !enroll.Check(proof, st.Verifier) || bytes.Contains(raw, []byte(bare)) || strings.Contains(outText, bare) || strings.Contains(outText, code) {
		t.Fatalf("state: %+v\n%s", st, outText)
	}
	if strings.Contains(strings.Join(args, " "), bare) || strings.Contains(strings.Join(args, " "), code) {
		t.Fatal("the code is on the command line")
	}
	stdin(code + "\n")
	if st, _, _ := joinDirect(t, "--code-stdin", "--pair-v2", "--panel", "100.88.109.47"); st.PairVersion() != 2 {
		t.Fatalf("--code-stdin with --pair-v2: %+v", st)
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
