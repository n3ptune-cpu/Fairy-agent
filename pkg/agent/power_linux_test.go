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
	if _, why := sleepFromLogind(`s "challenge"`); !strings.Contains(why, "polkit") {
		t.Fatal(why)
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
