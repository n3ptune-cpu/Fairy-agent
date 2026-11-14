package agent

import (
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// The notice of a run's self-off is held to the rule of every notice Fairy hands to Windows (PowerMessage):
// no word of it begins with "-" or "/", and there is no ASCII hyphen in it at all. On a real PC the notice for
// "test-admin" was cut at the hyphen; the run's notice ended in "shutdown /a" (review of fd6d3be, T9).
func TestRunNoticePassesTheRuleOfEveryNotice(t *testing.T) {
	for _, name := range []string{"neptune", "test-admin", "a -x /s", "", "-rf", "x/y", strings.Repeat("n", 64)} {
		for _, s := range []int{30, 120, 600} {
			msg := approval.RunNotice(cleanWho(name), s)
			if w := switchWord(msg); w != "" || strings.Contains(msg, "-") {
				t.Errorf("the notice for %q has the word %q or an ASCII hyphen: %q", name, w, msg)
			}
			if strings.ContainsAny(msg, "\r\n\t\"") {
				t.Errorf("the notice for %q has a character that does not belong in one: %q", name, msg)
			}
			// Windows takes at most 512 characters for the message of a shutdown (InitiateSystemShutdownEx)
			if n := len(utf16.Encode([]rune(msg))); n > 511 {
				t.Errorf("the notice for %q is %d characters long", name, n)
			}
			// it still says what the person at the PC needs: why, when, and both ways to keep the PC on
			for _, part := range []string{"Fairy", "started for an update", "nobody confirmed", "seconds", "To keep it on", "Cancel", "Fairy panel", "shutdown", "slash", "letter a"} {
				if !strings.Contains(msg, part) {
					t.Errorf("the notice for %q does not say %q: %q", name, part, msg)
				}
			}
		}
	}
}
