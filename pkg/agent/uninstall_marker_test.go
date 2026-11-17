package agent_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

func newMarker(t *testing.T) agent.UninstallMarker {
	t.Helper()
	return agent.UninstallMarker{Path: filepath.Join(t.TempDir(), agent.UninstallMarkerName)}
}

// The helper writes, the updater takes it once: who asked comes back, and the file is gone after.
func TestUninstallMarkerWriteTakeOnce(t *testing.T) {
	m := newMarker(t)
	now := time.Unix(1_800_000_000, 0)
	if _, err := m.Take(now); !errors.Is(err, agent.ErrNoUninstallMarker) {
		t.Fatalf("no request: %v", err)
	}
	if err := m.Write("panel 100.64.0.10", now); err != nil {
		t.Fatal(err)
	}
	by, err := m.Take(now.Add(5 * time.Second))
	if err != nil || by != "panel 100.64.0.10" {
		t.Fatalf("take: %q %v", by, err)
	}
	if _, err := os.Lstat(m.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the request is still there after it was taken")
	}
	if _, err := m.Take(now.Add(6 * time.Second)); !errors.Is(err, agent.ErrNoUninstallMarker) {
		t.Fatalf("taken twice: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(m.Path))
	if len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
}

// Not fresh (older than the TTL, or from the future): taken away and not acted on.
func TestUninstallMarkerMustBeFresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for what, at := range map[string]time.Time{
		"older than the TTL":  now.Add(-agent.UninstallMarkerTTL - time.Second),
		"from the far future": now.Add(time.Minute),
		"from long ago":       time.Unix(1, 0),
	} {
		m := newMarker(t)
		if err := m.Write("x", at); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Take(now); err == nil || errors.Is(err, agent.ErrNoUninstallMarker) {
			t.Errorf("%s: %v", what, err)
		}
		if _, err := os.Lstat(m.Path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: a stale request was left to be acted on later", what)
		}
	}
	m := newMarker(t)
	_ = m.Write("x", now.Add(-agent.UninstallMarkerTTL+time.Second))
	if _, err := m.Take(now); err != nil {
		t.Errorf("a second inside the TTL: %v", err)
	}
}

// Anything that is not exactly what the helper writes: not acted on.
func TestUninstallMarkerContent(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	fresh := "1800000000"
	for what, content := range map[string]string{
		"empty":            "",
		"not JSON":         "uninstall now",
		"another version":  `{"v":2,"at":` + fresh + `,"by":"x"}`,
		"no time":          `{"v":1,"by":"x"}`,
		"an unknown field": `{"v":1,"at":` + fresh + `,"by":"x","keep_data":false}`,
		"two objects":      `{"v":1,"at":` + fresh + `,"by":"x"}{"v":1,"at":` + fresh + `,"by":"y"}`,
		"too large":        `{"v":1,"at":` + fresh + `,"by":"` + strings.Repeat("x", 2000) + `"}`,
	} {
		m := newMarker(t)
		if err := os.WriteFile(m.Path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Take(now); err == nil || errors.Is(err, agent.ErrNoUninstallMarker) {
			t.Errorf("%s: accepted (%v)", what, err)
		}
	}
}

// The folder and the file must pass their checks (on Windows: owned by and writable only by administrators and
// SYSTEM). A request that does not is left where it is and not acted on; the helper writes nothing into a
// folder that does not pass.
func TestUninstallMarkerChecks(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	notSafe := errors.New("the agent's account may write here")
	m := newMarker(t)
	if err := m.Write("x", now); err != nil {
		t.Fatal(err)
	}
	dirBad := m
	dirBad.CheckDir = func(string) error { return notSafe }
	if _, err := dirBad.Take(now); !errors.Is(err, notSafe) {
		t.Fatalf("folder that does not pass: %v", err)
	}
	if err := dirBad.Write("x", now); !errors.Is(err, notSafe) {
		t.Fatalf("written into a folder that does not pass: %v", err)
	}
	fileBad := m
	fileBad.CheckFile = func(string) error { return notSafe }
	if _, err := fileBad.Take(now); !errors.Is(err, notSafe) {
		t.Fatalf("file that does not pass: %v", err)
	}
	if _, err := os.Lstat(m.Path); err != nil {
		t.Fatal("a request that did not pass its checks was removed: an administrator should see it")
	}
	// a folder in place of the file
	d := newMarker(t)
	if err := os.Mkdir(d.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Take(now); err == nil || errors.Is(err, agent.ErrNoUninstallMarker) {
		t.Fatalf("a folder: %v", err)
	}
	// and with every check passing, the same request is accepted
	ok := m
	ok.CheckDir, ok.CheckFile = func(string) error { return nil }, func(string) error { return nil }
	if by, err := ok.Take(now); err != nil || by != "x" {
		t.Fatalf("passing checks: %q %v", by, err)
	}
}
