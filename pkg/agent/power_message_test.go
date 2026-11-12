package agent

// The text Windows shows with a shutdown: no word of it may begin with "-". On the owner's test PC the notice
// for the requester "test-admin" ended after "test".

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// noBreakHyphen is U+2011, what a "-" of the requester's name is shown as.
const noBreakHyphen = "‑"

// switchWord is the first word of text that begins like a switch of a command line ("": none).
func switchWord(text string) string {
	for _, w := range strings.Fields(text) {
		if strings.HasPrefix(w, "-") || strings.HasPrefix(w, "/") {
			return w
		}
	}
	return ""
}

func TestPowerMessageHasNoWordThatBeginsWithAHyphen(t *testing.T) {
	msg := PowerMessage("shutdown", "test-admin", 60*time.Second)
	if want := "Fairy: shutdown requested by test" + noBreakHyphen + "admin in 60 seconds."; msg != want {
		t.Fatalf("shown: %q, want %q", msg, want)
	}
	if strings.Contains(msg, "-") {
		t.Fatalf("an ASCII hyphen in %q", msg)
	}
	// as Windows gets it (UTF-16): the hyphen is one unit, 0x2011, and there is no 0x002D
	var hyphens int
	for _, u := range utf16.Encode([]rune(msg)) {
		if u == 0x2D {
			t.Fatalf("0x002D in the UTF-16 text of %q", msg)
		}
		if u == 0x2011 {
			hyphens++
		}
	}
	if hyphens != 1 {
		t.Fatalf("%d units 0x2011 in the UTF-16 text of %q, want 1", hyphens, msg)
	}

	// names that would put switches into the text, as cleanWho lets them through
	for _, name := range []string{"a -u x.exe -a 11", "-admin", "--force", "x - y", "- -", "a-", "-", "-s -t 0 -f", " -a", "wake-update",
		"shutdown.exe -r -t 0", strings.Repeat("-", 64), strings.Repeat(" -x", 21)} {
		who := cleanWho(name)
		if who != name {
			t.Fatalf("%q is not a name the agent lets through as it is (%q)", name, who)
		}
		for _, action := range powerRecordActions {
			msg := PowerMessage(action, who, 90*time.Second)
			if w := switchWord(msg); w != "" || strings.Contains(msg, "-") {
				t.Errorf("%s by %q is shown as %q: word %q, ASCII hyphen: %v", action, name, msg, w, strings.Contains(msg, "-"))
			}
			// nothing else is different: with the hyphens put back it is the sentence as it always was
			if back, old := strings.ReplaceAll(msg, noBreakHyphen, "-"), fmt.Sprintf("Fairy: %s requested by %s in %d seconds.", action, who, 90); back != old {
				t.Errorf("%q differs from %q in more than its hyphens", msg, old)
			}
		}
	}
	// a name without a hyphen is shown as it always was, byte for byte
	for _, name := range []string{"alice@example.com", "panel", "Nika K.", "unknown", "wake update", "a_b.c@d"} {
		for _, action := range powerRecordActions {
			if msg, old := PowerMessage(action, name, time.Hour), fmt.Sprintf("Fairy: %s requested by %s in %d seconds.", action, name, 3600); msg != old {
				t.Errorf("%q, was %q", msg, old)
			}
		}
	}
	// whatever cleanWho makes of what a request may carry, no word of the text begins with "-" or "/"
	for _, raw := range []any{"/s /t 0", "a/b -c", `x" -f "y`, "tab\t-x", "nl\n-x", nil, 7, "-" + noBreakHyphen + "-"} {
		if msg := PowerMessage("reboot", cleanWho(raw), 10*time.Second); switchWord(msg) != "" || strings.Contains(msg, "-") {
			t.Errorf("%#v is shown as %q", raw, msg)
		}
	}
}

// Only the text that is shown changes. The name on record, in the answers, in the file and in the log is the
// name that was sent, hyphen and all: the panel compares and shows those.
func TestTheRequestersNameIsKeptAsItWasSentEverywhereButInTheNotice(t *testing.T) {
	const shown = "Fairy: shutdown requested by test" + noBreakHyphen + "admin in 60 seconds."
	store := PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
	win, c := &fakeOS{}, newClock()
	p := agentOver(start(win, store, c), c)
	logs := captureLog(t)
	d := 60
	st, b := p.Handle(PowerRequest{Action: "shutdown", DelayS: &d, RequestedBy: "test-admin"})
	if st != 200 {
		t.Fatal(st, b)
	}
	if len(win.scheduled) != 1 || win.scheduled[0] != "shutdown@1m0s "+shown {
		t.Fatalf("Windows was handed %q", win.scheduled)
	}
	if got := b["pending"].(Pending).RequestedBy; got != "test-admin" {
		t.Errorf("requested_by in the answer: %q", got)
	}
	if got := p.State()["pending"].(Pending).RequestedBy; got != "test-admin" {
		t.Errorf("requested_by in /metrics: %q", got)
	}
	file, err := os.ReadFile(store.Path)
	if err != nil || !strings.Contains(string(file), `"by":"test-admin"`) || strings.Contains(string(file), noBreakHyphen) {
		t.Errorf("the record's file: %s %v", file, err)
	}
	if rec, ok := start(win, store, c).PendingAction(); !ok || rec.RequestedBy != "test-admin" {
		t.Errorf("the record after a restart: %+v %v", rec, ok)
	}
	if l := logs.String(); !strings.Contains(l, "requested_by=test-admin") || strings.Contains(l, noBreakHyphen) {
		t.Errorf("the log:\n%s", l)
	}

	// a power part that is handed the text by Power itself (no ScheduleBy): the same text
	plain := &fakeOS{}
	p = NewPower(plain, 10)
	if st, b := p.Handle(PowerRequest{Action: "shutdown", DelayS: &d, RequestedBy: "test-admin"}); st != 200 ||
		b["pending"].(Pending).RequestedBy != "test-admin" {
		t.Fatal(st, b)
	}
	if len(plain.scheduled) != 1 || plain.scheduled[0] != "shutdown@1m0s "+shown {
		t.Fatalf("the power part was handed %q", plain.scheduled)
	}
}
