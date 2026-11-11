package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

// Audit 4, T-07: check-config (and `bmc-relay add`) name every redfish relay target that has no tls_fingerprint,
// because the agent sends such a BMC nothing. The config itself stays valid: a target whose certificate an
// earlier version learned keeps working, so an update must not stop the agent over it.
func TestConfigNotesNameRedfishTargetsWithoutFingerprint(t *testing.T) {
	const y = `
bmc_relay:
  enabled: true
  targets:
    - {id: by-ipmi, host: 192.168.1.5, username: fairy, password_env: BMC_A}
    - {id: named, url: "https://192.168.1.6", username: fairy, password_env: BMC_B, tls_fingerprint: "` + "AB:" + `cd` + `"}
    - {id: unnamed, url: "https://192.168.1.7", username: fairy, password_env: BMC_C}
`
	fp := strings.Repeat("ab", 32)
	cfg, err := agent.Parse([]byte(strings.Replace(y, "AB:cd", fp, 1)), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	notes := configNotes(cfg)
	if len(notes) != 1 || !strings.Contains(notes[0], "bmc_relay target unnamed has no tls_fingerprint") ||
		!strings.Contains(notes[0], "set tls_fingerprint") {
		t.Fatalf("%q", notes)
	}
	cfg, err = agent.Parse([]byte("listen: 127.0.0.1:9100\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil || len(configNotes(cfg)) != 0 {
		t.Fatal(err, configNotes(cfg))
	}
}
