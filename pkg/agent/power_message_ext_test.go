package agent_test

// The whole way on Windows, as far as it runs on Linux: the agent's HTTP API, the helper's client, the real
// helper server behind an in-memory pipe, the power part that remembers. What "Windows" is handed as the text
// of its notice has no word that begins with "-"; what the panel reads still has the name as it was sent.

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

// noticeExec is "Windows": it keeps the text it was handed with each action.
type noticeExec struct {
	mu      sync.Mutex
	notices []string
}

func (e *noticeExec) Schedule(_ string, _ time.Duration, message string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.notices = append(e.notices, message)
	return nil
}
func (e *noticeExec) Cancel() error            { return nil }
func (e *noticeExec) CanSleep() (bool, string) { return true, "" }

func TestWindowsNoticeForARequesterWithAHyphen(t *testing.T) {
	windows := &noticeExec{}
	store := agent.PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
	base, stop := startPair(t, windows, store)
	defer stop()
	st, b := do(t, base, "POST", "/power", ctlTok, map[string]any{"action": "shutdown", "delay_s": 60, "requested_by": "test-admin"})
	if st != 200 {
		t.Fatal(st, b)
	}
	if p, _ := b["pending"].(map[string]any); p["requested_by"] != "test-admin" {
		t.Errorf("requested_by in the answer to /power: %v", b)
	}
	if p := pendingIn(t, base, true); p["requested_by"] != "test-admin" || p["action"] != "shutdown" {
		t.Errorf("pending in /metrics: %v", p)
	}
	windows.mu.Lock()
	notices := append([]string(nil), windows.notices...)
	windows.mu.Unlock()
	if want := "Fairy: shutdown requested by test‑admin in 60 seconds."; len(notices) != 1 || notices[0] != want {
		t.Fatalf("Windows was handed %q, want %q", notices, want)
	}
	if file, err := os.ReadFile(store.Path); err != nil || !strings.Contains(string(file), `"by":"test-admin"`) {
		t.Errorf("the helper's record: %s %v", file, err)
	}
	if st, b := do(t, base, "POST", "/power", ctlTok, map[string]any{"action": "cancel"}); st != 200 {
		t.Fatal(st, b)
	}

	// a name made of switches
	st, b = do(t, base, "POST", "/power", ctlTok, map[string]any{"action": "reboot", "delay_s": 60, "requested_by": "a -u x.exe -a 11"})
	if p, _ := b["pending"].(map[string]any); st != 200 || p["requested_by"] != "a -u x.exe -a 11" {
		t.Fatal(st, b)
	}
	windows.mu.Lock()
	last := windows.notices[len(windows.notices)-1]
	windows.mu.Unlock()
	for _, w := range strings.Fields(last) {
		if strings.HasPrefix(w, "-") || strings.HasPrefix(w, "/") {
			t.Errorf("the word %q in what Windows was handed: %q", w, last)
		}
	}
	if want := "Fairy: reboot requested by a ‑u x.exe ‑a 11 in 60 seconds."; last != want {
		t.Errorf("Windows was handed %q, want %q", last, want)
	}
}
