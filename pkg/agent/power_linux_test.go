//go:build linux

package agent

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
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

// ranLog is what a test's stand-in for `systemctl <verb>` was asked to run. Nothing is run.
type ranLog struct {
	mu   sync.Mutex
	runs []string
}

func (r *ranLog) run(_, verb string) {
	r.mu.Lock()
	r.runs = append(r.runs, verb)
	r.mu.Unlock()
}

func (r *ranLog) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.runs)
}

// linuxPower is the Linux power part with a stand-in in the place of `systemctl <verb>`: its timer, its lock
// and its Cancel are the product's, and no program is started. (It still looks for systemctl's path, as the
// product does before it takes a request; without one there is nothing to test.)
func linuxPower(t *testing.T) (*systemPower, *ranLog) {
	t.Helper()
	if _, err := systemctl(); err != nil {
		t.Skip("no systemctl on this machine: ", err)
	}
	log := &ranLog{}
	return &systemPower{run: log.run}, log
}

// Audit 6, r4-a1-03: once the timer has run systemctl, Cancel says so instead of "cancelled"; the next
// Schedule starts afresh.
func TestLinuxCancelAfterTheTimerRanIsTooLate(t *testing.T) {
	s, log := linuxPower(t)
	if err := s.Schedule("shutdown", 20*time.Millisecond, ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500 && log.count() == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if log.count() != 1 || log.runs[0] != "poweroff" {
		t.Fatalf("the timer ran %v", log.runs)
	}
	for i := 0; i < 2; i++ {
		err := s.Cancel()
		if !errors.Is(err, errTooLate) || err.Error() != "too late to cancel: systemctl poweroff was already run" {
			t.Fatalf("Cancel after the timer ran: %v", err)
		}
	}
	// a new request, cancelled in time: a plain cancel again, and nothing runs
	if err := s.Schedule("reboot", time.Hour, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Cancel(); err != nil {
		t.Fatalf("Cancel in time: %v", err)
	}
	if err := s.Cancel(); err != nil {
		t.Fatalf("a second Cancel with nothing scheduled: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if log.count() != 1 {
		t.Fatalf("something ran after a cancel in time: %v", log.runs)
	}
}

// A Cancel in the moment the timer fires: either it stopped the action (nil, and nothing is ever run) or the
// action was carried out (errTooLate, and it ran once). Never "cancelled" for an action that ran, which the
// timer's own Stop could not promise.
func TestLinuxCancelAndTheTimerNeverBothWin(t *testing.T) {
	s, log := linuxPower(t)
	cancelled, late := 0, 0
	for i := 0; i < 400; i++ {
		before := log.count()
		delay := time.Duration(i%8) * 50 * time.Microsecond
		if err := s.Schedule("shutdown", delay, ""); err != nil {
			t.Fatal(err)
		}
		time.Sleep(delay)
		err := s.Cancel()
		time.Sleep(time.Millisecond) // a timer that was let through has run its stand-in by now
		ran := log.count() - before
		switch {
		case err == nil && ran == 0:
			cancelled++
		case errors.Is(err, errTooLate):
			for j := 0; j < 200 && log.count() == before; j++ { // "written down before it is run": give it its moment
				time.Sleep(time.Millisecond)
			}
			if log.count()-before != 1 {
				t.Fatalf("round %d: Cancel said too late and systemctl ran %d time(s)", i, log.count()-before)
			}
			late++
		default:
			t.Fatalf("round %d: Cancel answered %v and systemctl ran %d time(s)", i, err, ran)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if log.count() != late {
		t.Fatalf("systemctl ran %d time(s) in all, and %d cancels were told it had", log.count(), late)
	}
	t.Logf("400 rounds: cancelled in time %d, too late %d", cancelled, late)
}

// The timer counts on a clock that stands still while the machine sleeps. What was left of a countdown ran
// when the machine woke, hours after the moment that was asked for (for the self-off of a run: hours after the
// notice said). Held against the uptime, which goes on through sleep: an action that is more than a minute
// late is dropped, and the machine stays on (review of fd6d3be, T2).
func TestLinuxTimerDropsAnActionWhoseTimePassedWhileTheMachineSlept(t *testing.T) {
	for _, c := range []struct {
		name  string
		slept time.Duration // how much more than the delay the uptime moved until the timer fired
		err   error
		runs  int
	}{
		{"on time", 0, nil, 1},
		{"59 s late", 59 * time.Second, nil, 1},
		{"60 s late", 60 * time.Second, nil, 0},
		{"the machine slept for 8 hours", 8 * time.Hour, nil, 0},
		{"the uptime cannot be read: as before", 8 * time.Hour, errors.New("no /proc"), 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, log := linuxPower(t)
			var mu sync.Mutex
			up := 100 * time.Second
			s.uptime = func() (time.Duration, error) { mu.Lock(); defer mu.Unlock(); return up, c.err }
			const delay = 30 * time.Millisecond
			if err := s.Schedule("shutdown", delay, ""); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			up += delay + c.slept
			mu.Unlock()
			for i := 0; i < 100 && log.count() == 0; i++ {
				time.Sleep(5 * time.Millisecond)
			}
			if log.count() != c.runs {
				t.Fatalf("systemctl was run %d times, want %d", log.count(), c.runs)
			}
			err := s.Cancel()
			if c.runs == 0 && err != nil {
				t.Fatalf("Cancel after a dropped action: %v", err)
			}
			if c.runs == 1 && !errors.Is(err, errTooLate) {
				t.Fatalf("Cancel after the action ran: %v", err)
			}
		})
	}
}
