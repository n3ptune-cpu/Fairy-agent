package release_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release/releasetest"
)

type cliRig struct {
	gh      *releasetest.Server
	target  string
	out     bytes.Buffer
	starts  int
	healthy func(content, want string) bool
	done    []string
	steps   []string
}

func newCLIRig(t *testing.T) *cliRig {
	r := &cliRig{gh: releasetest.New(t, release.AgentRepo), healthy: func(string, string) bool { return true }}
	r.target = filepath.Join(t.TempDir(), "fairy-agent")
	_ = os.WriteFile(r.target, []byte("binary 41-0000000"), 0o755)
	return r
}

func (r *cliRig) cli(current string, key ed25519.PublicKey) *release.CLI {
	if key == nil {
		key = r.gh.Pub
	}
	return &release.CLI{Client: r.gh.Client(), Key: key, Program: "fairy-agent", Current: current, Target: r.target,
		Asset: "fairy-agent-linux-amd64", Out: &r.out, In: strings.NewReader(""), Yes: true,
		RunNew: func(p string) (string, error) {
			b, _ := os.ReadFile(p)
			return "fairy-agent " + strings.TrimPrefix(string(b), "binary ") + " linux/amd64", nil
		},
		Installer: func(target, want string) *release.Installer {
			return &release.Installer{Target: target, HealthTimeout: 200 * time.Millisecond, Interval: 10 * time.Millisecond,
				Start: func(context.Context) error { r.starts++; return nil },
				Healthy: func(context.Context) error {
					b, _ := os.ReadFile(target)
					if !r.healthy(string(b), want) {
						return errors.New("agent reports another version")
					}
					return nil
				}}
		},
		Progress: func(state, to, _ string) { r.steps = append(r.steps, state) },
		Done: func(from, to string, err error) {
			r.done = append(r.done, from+">"+to+":"+map[bool]string{true: "ok", false: "fail"}[err == nil])
		}}
}

func TestCLIUpdate(t *testing.T) {
	r := newCLIRig(t)
	r.gh.Publish("build-42", "fairy-agent", "42-1a2b3c4", map[string][]byte{"fairy-agent-linux-amd64": []byte("binary 42-1a2b3c4"),
		"fairy-agent-linux-arm64": []byte("arm")}, nil)
	c := r.cli("41-0000000", nil)
	c.Check = true
	if err := c.Run(context.Background()); err != nil || !strings.Contains(r.out.String(), "update is available") {
		t.Fatal(err, r.out.String())
	}
	c = r.cli("41-0000000", nil)
	c.Yes, c.In = false, strings.NewReader("n\n")
	if err := c.Run(context.Background()); err != nil || r.starts != 0 {
		t.Fatal(err, r.starts)
	}
	if b, _ := os.ReadFile(r.target); string(b) != "binary 41-0000000" {
		t.Fatal("changed without consent")
	}
	r.steps = nil
	if err := r.cli("41-0000000", nil).Run(context.Background()); err != nil {
		t.Fatal(err, r.out.String())
	}
	if got := strings.Join(r.steps, ","); got != "checking,downloading,staged,restarting,done" {
		t.Fatal("progress:", got)
	}
	if b, _ := os.ReadFile(r.target); string(b) != "binary 42-1a2b3c4" {
		t.Fatalf("%q", b)
	}
	if b, _ := os.ReadFile(r.target + ".old"); string(b) != "binary 41-0000000" {
		t.Fatalf(".old %q", b)
	}
	r.out.Reset()
	if err := r.cli("42-1a2b3c4", nil).Run(context.Background()); err != nil || !strings.Contains(r.out.String(), "Already up to date") {
		t.Fatal(err, r.out.String())
	}
	r.steps = nil
	if err := r.cli("50-fffffff", nil).Run(context.Background()); err == nil || !strings.Contains(err.Error(), "not downgrading") {
		t.Fatal(err)
	}
	if got := strings.Join(r.steps, ","); got != "checking,failed" {
		t.Fatal("progress:", got)
	}
	if strings.Join(r.done, ",") != "41-0000000>42-1a2b3c4:ok" {
		t.Fatal(r.done)
	}
}

func TestCLIRefusesAndRollsBack(t *testing.T) {
	r := newCLIRig(t)
	r.gh.Publish("build-42", "fairy-agent", "42-1a2b3c4", map[string][]byte{"fairy-agent-linux-amd64": []byte("binary 42-1a2b3c4")}, nil)
	other, _, _ := ed25519.GenerateKey(nil)
	if err := r.cli("41-0", other).Run(context.Background()); err == nil {
		t.Fatal("wrong key accepted")
	}
	r.gh.Publish("build-43", "fairy", "43-1a2b3c4", map[string][]byte{"fairy-agent-linux-amd64": []byte("x")}, nil)
	if err := r.cli("41-0", nil).Run(context.Background()); err == nil {
		t.Fatal("panel release accepted for the agent")
	}
	r.gh.Publish("build-44", "fairy-agent", "44-1a2b3c4", map[string][]byte{"fairy-agent-linux-amd64": []byte("binary 44-1a2b3c4")}, nil)
	r.gh.Replace("fairy-agent-linux-amd64", []byte("binary evil"))
	if err := r.cli("41-0", nil).Run(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatal(err)
	}
	// the new binary does not run here
	r.gh.Publish("build-45", "fairy-agent", "45-1a2b3c4", map[string][]byte{"fairy-agent-linux-amd64": []byte("binary 46-other")}, nil)
	if err := r.cli("41-0", nil).Run(context.Background()); err == nil || !strings.Contains(err.Error(), "does not run here") {
		t.Fatal(err)
	}
	// unhealthy after the restart: rolled back
	r.gh.Publish("build-47", "fairy-agent", "47-1a2b3c4", map[string][]byte{"fairy-agent-linux-amd64": []byte("binary 47-1a2b3c4")}, nil)
	r.healthy = func(c, _ string) bool { return c == "binary 41-0000000" }
	r.steps = nil
	err := r.cli("41-0", nil).Run(context.Background())
	if r.steps[len(r.steps)-1] != "rolled_back" {
		t.Fatal("progress:", r.steps)
	}
	var rb *release.RolledBackError
	if !errors.As(err, &rb) || rb.RollbackErr != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(r.target); string(b) != "binary 41-0000000" {
		t.Fatalf("not rolled back: %q", b)
	}
	if ents, _ := os.ReadDir(filepath.Dir(r.target)); len(ents) != 1 {
		t.Fatalf("left files: %v", ents)
	}
	if len(r.done) != 3 || !strings.HasSuffix(r.done[2], ":fail") {
		t.Fatal(r.done)
	}
}
