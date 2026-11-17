//go:build linux

package agent

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The Linux uninstall asks systemd for exactly one thing: start the fixed root unit, without waiting. It names
// that unit and no other, and the unit and the polkit rule in deploy/ are the ones it names.
func TestUnitUninstallerStartsTheOneUnit(t *testing.T) {
	var got []string
	u := unitUninstaller{run: func(_ context.Context, args ...string) error { got = args; return nil }}
	if err := u.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "start --no-block fairy-agent-uninstall.service" {
		t.Fatalf("systemctl %q", got)
	}
	if u.ThroughHelper() {
		t.Fatal("Linux has no helper")
	}
	u.run = func(context.Context, ...string) error { return errors.New("Access denied") }
	if err := u.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "fairy-agent-uninstall.polkit.rules") {
		t.Fatalf("a failed start says: %v", err)
	}

	rule, err := os.ReadFile("../../deploy/fairy-agent-uninstall.polkit.rules")
	if err != nil {
		t.Fatal(err)
	}
	// the rule's one condition: this user, manage-units, this unit, the verb start; and a single YES
	cond := regexp.MustCompile(`subject\.user === "fairy-agent" && action\.id === "org\.freedesktop\.systemd1\.manage-units" &&\s+` +
		`action\.lookup\("unit"\) === "` + regexp.QuoteMeta(uninstallUnit) + `" && action\.lookup\("verb"\) === "start"`)
	if !cond.Match(rule) || strings.Count(string(rule), "polkit.Result.YES") != 1 || strings.Count(string(rule), "addRule") != 1 {
		t.Fatalf("the polkit rule grants something else:\n%s", rule)
	}
	unit, err := os.ReadFile("../../deploy/" + uninstallUnit)
	if err != nil {
		t.Fatal(err)
	}
	// a section header at the start of a line; the file's comments may name it ("no [Install] section")
	if regexp.MustCompile(`(?m)^\s*\[Install\]`).Match(unit) {
		t.Fatal("the unit has an [Install] section: it must never start by itself")
	}
	if !strings.Contains(string(unit), "ExecStart=/bin/sh /usr/local/lib/fairy-agent/uninstall-fairy-agent.sh --yes --keep-data\n") {
		t.Fatal("the unit does not run the installed removal script with --keep-data")
	}
}
