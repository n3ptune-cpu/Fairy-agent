//go:build linux

package agent

import (
	"strings"
	"testing"
)

func TestLinuxSleepAnswers(t *testing.T) {
	for out, want := range map[string]bool{"s \"yes\"\n": true, "s \"challenge\"\n": false, "s \"na\"": false, "s \"no\"": false, "garbage": false} {
		if ok, why := sleepFromLogind(out); ok != want || (!ok && why == "") {
			t.Errorf("%q: %v %q", out, ok, why)
		}
	}
	// the message the owner sees names the rule file that exists and where the installer puts it (not the
	// combined file of older releases, which is gone)
	for _, v := range []string{`s "challenge"`, `s "no"`} {
		_, why := sleepFromLogind(v)
		if !strings.Contains(why, "deploy/fairy-agent-power.polkit.rules") || !strings.Contains(why, "/etc/polkit-1/rules.d/49-fairy-agent-power.rules") ||
			strings.Contains(why, "fairy-agent.polkit.rules") {
			t.Fatal(why)
		}
	}
	if ok, _ := sleepFromKernel("freeze mem disk\n"); !ok {
		t.Fatal("mem")
	}
	if ok, _ := sleepFromKernel("freeze disk\n"); ok {
		t.Fatal("no mem")
	}
	if linuxVerb["sleep"] != "suspend" || linuxVerb["shutdown"] != "poweroff" {
		t.Fatal(linuxVerb)
	}
}
