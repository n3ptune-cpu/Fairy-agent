package agent

// Review of the audit 4 fixes (T-07): the panel shows only the first 300 bytes of an agent's error text
// (its maxAgentError). The two answers that show the fingerprint of a certificate nobody has checked were
// longer, so the owner saw the fingerprint without the warning to compare it, or a fingerprint cut short.

import (
	"context"
	"strings"
	"testing"
)

// panelShows is how many bytes of an agent's error text the panel keeps.
const panelShows = 300

func TestBMCRelayFingerprintTextsFitWhatThePanelShows(t *testing.T) {
	t.Setenv("T07_BMC_PW", "t07-test-bmc-password")
	l := newFakeBMCListener(t, true)
	other := strings.Repeat("ab", 32)                             // a fingerprint that is not the listener's
	for _, id := range []string{"x11", strings.Repeat("a", 40)} { // 40 letters is the longest id config.yaml allows
		for code, target := range map[string]BMCTarget{
			"bmc_fingerprint_missing": {ID: id, URL: l.url, Username: "fairy", PasswordEnv: "T07_BMC_PW"},
			"bmc_certificate_changed": {ID: id, URL: l.url, Username: "fairy", PasswordEnv: "T07_BMC_PW", TLSFingerprint: other},
		} {
			relay := NewBMCRelay(BMCRelayConfig{Enabled: true, Targets: []BMCTarget{target}}, "")
			_, body := relay.Handle(context.Background(), BMCRequest{Target: id, Action: "status"})
			msg, _ := body["error"].(string)
			if body["code"] != code {
				t.Fatalf("id %q: want %s, got %v", id, code, body)
			}
			warn, fp, set := strings.Index(msg, "Compare first"), strings.Index(msg, l.fingerprint), strings.Index(msg, "set tls_fingerprint")
			switch {
			case len(msg) > panelShows:
				t.Errorf("%s, id of %d letters: the text has %d bytes, the panel shows %d: %q", code, len(id), len(msg), panelShows, msg)
			case warn != 0 || fp < 0 || set < 0:
				t.Errorf("%s: the text must start with the warning, show the fingerprint and say what to set: %q", code, msg)
			case fp > set:
				t.Errorf("%s: what to set comes before the fingerprint it speaks of: %q", code, msg)
			case !strings.Contains(msg[:fp], "Only if the BMC's own web page shows"):
				t.Errorf("%s: the fingerprint comes before the words that say what to compare it with: %q", code, msg)
			case !strings.Contains(msg, id) || strings.Contains(msg, l.url):
				t.Errorf("%s: the text names the target by its id, not by an address of any length: %q", code, msg)
			}
		}
	}
	if creds, _ := l.seen(); len(creds) != 0 {
		t.Fatalf("the listener received a login: %q", creds)
	}
}
