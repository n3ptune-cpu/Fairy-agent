package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
)

// faultyBMC is a BMC whose answers to some questions fail (a busy BMC: completion code 0xC0), and which keeps
// what it was asked to change.
type faultyBMC struct {
	ipmi.Transport
	modeReads   int
	modeEvery   int  // every n-th "which fan mode?" fails (1: every one, 0: none)
	noDutyRead  bool // "which duty?" fails
	noDutyWrite bool // "set this duty" fails
	noModeWrite bool // "set this mode" fails
	dutyWrites  []byte
	modeWrites  []byte
}

func (f *faultyBMC) Raw(ctx context.Context, netfn, cmd byte, data []byte) ([]byte, error) {
	busy := &ipmi.CompletionError{Code: 0xC0}
	if netfn == ipmi.NetFnOEM {
		switch {
		case cmd == ipmi.CmdSMCFanMode && len(data) == 1:
			if f.modeReads++; f.modeEvery > 0 && f.modeReads%f.modeEvery == 0 {
				return nil, busy
			}
		case cmd == ipmi.CmdSMCFanMode && len(data) == 2:
			f.modeWrites = append(f.modeWrites, data[1])
			if f.noModeWrite {
				return nil, busy
			}
		case cmd == ipmi.CmdSMCFanDuty && len(data) == 3:
			if f.noDutyRead {
				return nil, busy
			}
		case cmd == ipmi.CmdSMCFanDuty && len(data) == 4:
			f.dutyWrites = append(f.dutyWrites, data[3])
			if f.noDutyWrite {
				return nil, busy
			}
		}
	}
	return f.Transport.Raw(ctx, netfn, cmd, data)
}

// writes is how many commands that change something the BMC was sent.
func (f *faultyBMC) writes() int { return len(f.dutyWrites) + len(f.modeWrites) }

// Review N9 (the reviewer's proof). When the BMC does not answer "which fan mode?" the watchdog did nothing
// for that check and forgot how many checks had no temperature. With a BMC that fails that one question on
// every third check, "no temperature for 30 s" never came true: the fans stayed at 30 % with no temperature
// known at all. And with a hot CPU, a check that could not read the mode did nothing.
func TestWatchdogFailsSafeWhenTheFanModeCannotBeRead(t *testing.T) {
	ctx := context.Background()
	r := manualRig(t, 30) // mode full, zone 0 at 30 %, BMC readings gone, no OS temperature
	r.fan.localTemps = func() []collect.Temp { return nil }
	r.fan.t = &faultyBMC{Transport: r.bmc, modeEvery: 3}
	r.fan.WatchdogOnce(ctx)
	r.fan.WatchdogOnce(ctx)
	r.fan.WatchdogOnce(ctx) // the third check without a temperature: this one cannot read the mode
	if _, d := r.bmc.State(); d[0] != 30 {
		t.Fatal("one failed question about the mode moved the fans:", d)
	}
	r.fan.WatchdogOnce(ctx) // the mode is readable again, and the count was not forgotten
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Fatalf("40 s without any temperature, fans left at %v: the check that could not read the fan mode "+
			"made the watchdog forget its count", d)
	}
	if m, _ := r.bmc.State(); m != modeFull {
		t.Fatal("the mode was changed:", m)
	}
	ev := r.fan.recentEvents()
	if last := ev[len(ev)-1]; last.Action != "watchdog: duty 100%" || strings.Contains(last.Detail, "does not say which fan mode is set") {
		t.Fatalf("%+v", last)
	}

	// a BMC that never says the mode and no temperature: 100 % at the third check, as with a readable mode
	r = manualRig(t, 30)
	r.fan.localTemps = func() []collect.Temp { return nil }
	r.fan.t = &faultyBMC{Transport: r.bmc, modeEvery: 1}
	r.fan.WatchdogOnce(ctx)
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d[0] != 30 {
		t.Fatal("acted before the third check:", d)
	}
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Fatalf("30 s without a temperature and without the fan mode, fans left at %v", d)
	}
	ev = r.fan.recentEvents()
	if last := ev[len(ev)-1]; last.Action != "watchdog: duty 100%" || !strings.Contains(last.Detail, "does not say which fan mode is set") {
		t.Fatalf("%+v", last)
	}

	// a hot CPU and a BMC that never says the mode: 100 % at the third check in a row (20 s), not before
	r = manualRig(t, 30, 95)
	r.fan.t = &faultyBMC{Transport: r.bmc, modeEvery: 1}
	r.fan.WatchdogOnce(ctx)
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d[0] != 30 {
		t.Fatal("acted before the third check that could not read the mode:", d)
	}
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Fatalf("CPU at 95 °C, fans left at %v: three checks in a row that cannot read the fan mode do nothing", d)
	}
	// a lower duty is then held off like after any other watchdog action
	if code, _ := r.fan.dutyRefusal(); code != "fan_watchdog_hold" {
		t.Fatal(code)
	}
}

// One failed IPMI call must not make the fans jump. A BMC that fails "which fan mode?" now and then (busy
// for a moment) is not a BMC whose mode is unknown: nothing is sent for such a check, whatever the temperature
// says and whatever mode the fans are in, and the next check that reads the mode acts as always.
func TestOneFailedModeReadDoesNotMoveTheFans(t *testing.T) {
	ctx := context.Background()

	// the BMC's automatic mode (the owner's choice), a hot CPU, every second question fails, for 4 minutes:
	// nothing is ever sent, the owner's mode stays, and a lower duty is not held off
	r := manualRig(t, 30, 95)
	if st, b := r.fan.SetMode(ctx, "heavyio", "owner"); st != 200 {
		t.Fatal(st, b)
	}
	f := &faultyBMC{Transport: r.bmc, modeEvery: 2}
	r.fan.t = f
	for i := 0; i < 24; i++ {
		r.fan.WatchdogOnce(ctx)
	}
	if m, _ := r.bmc.State(); m != modeHeavyIO || f.writes() != 0 || !r.fan.actedAt.IsZero() {
		t.Fatalf("mode %v, %d commands sent, acted %v", m, f.writes(), r.fan.actedAt)
	}
	// the same with two failed questions in a row out of three
	r = manualRig(t, 30, 95)
	if st, b := r.fan.SetMode(ctx, "heavyio", "owner"); st != 200 {
		t.Fatal(st, b)
	}
	two := &twoOfThree{Transport: r.bmc}
	r.fan.t = two
	for i := 0; i < 24; i++ {
		r.fan.WatchdogOnce(ctx)
	}
	if m, d := r.bmc.State(); m != modeHeavyIO || two.writes != 0 {
		t.Fatalf("mode %v duty %v, %d commands sent", m, d, two.writes)
	}

	// mode "full" at 30 %, a hot CPU, and the first question fails: nothing at that check, 100 % at the next
	// (which reads the mode), by the ordinary rule
	r = manualRig(t, 30, 95)
	f = &faultyBMC{Transport: r.bmc, modeEvery: 1}
	r.fan.t = f
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d[0] != 30 || f.writes() != 0 {
		t.Fatalf("one failed question moved the fans: %v, %d commands", d, f.writes())
	}
	f.modeEvery = 0
	r.fan.WatchdogOnce(ctx)
	if m, d := r.bmc.State(); m != modeFull || d != [2]byte{100, 100} || !r.fan.blindAt.IsZero() || r.fan.modeFails != 0 {
		t.Fatal(m, d, r.fan.blindAt, r.fan.modeFails)
	}
}

// twoOfThree fails "which fan mode?" twice out of every three times, and counts the commands that change
// something.
type twoOfThree struct {
	ipmi.Transport
	reads, writes int
}

func (f *twoOfThree) Raw(ctx context.Context, netfn, cmd byte, data []byte) ([]byte, error) {
	if netfn == ipmi.NetFnOEM {
		switch {
		case cmd == ipmi.CmdSMCFanMode && len(data) == 1:
			if f.reads++; f.reads%3 != 0 {
				return nil, &ipmi.CompletionError{Code: 0xC0}
			}
		case (cmd == ipmi.CmdSMCFanMode && len(data) == 2) || (cmd == ipmi.CmdSMCFanDuty && len(data) == 4):
			f.writes++
		}
	}
	return f.Transport.Raw(ctx, netfn, cmd, data)
}

// thrice runs three watchdog checks: as many as it takes before the watchdog acts without the fan mode.
func thrice(ctx context.Context, f *Fan) {
	for i := 0; i < fanBlindAfter; i++ {
		f.WatchdogOnce(ctx)
	}
}

// What the watchdog does not do when it cannot read the mode: it never acts on a cool CPU, never sets a duty
// below 100 %, never changes the mode while the BMC takes 100 %, does not send command after command to a
// BMC that answers nothing, says what it did once and not every 30 s, and stops as soon as the mode can be
// read again.
func TestWatchdogBlindIsConservative(t *testing.T) {
	ctx := context.Background()

	// cool CPU, mode unreadable: nothing is sent, the manual speed stays, for as long as it is cool
	r := manualRig(t, 30, 45)
	f := &faultyBMC{Transport: r.bmc, modeEvery: 1}
	r.fan.t = f
	for i := 0; i < 12; i++ {
		r.fan.WatchdogOnce(ctx)
	}
	if _, d := r.bmc.State(); d[0] != 30 || f.writes() != 0 {
		t.Fatalf("a cool CPU: duty %v, %d commands sent", d, f.writes())
	}

	// mode unreadable, but both zones answer 100 %: nothing lower can be in effect, nothing is sent
	r = manualRig(t, 100, 95)
	if st, b := r.fan.SetDuty(ctx, 1, 100, "test"); st != 200 {
		t.Fatal(st, b)
	}
	f = &faultyBMC{Transport: r.bmc, modeEvery: 1}
	r.fan.t = f
	thrice(ctx, r.fan)
	if f.writes() != 0 {
		t.Fatal("commands sent with both zones at 100 %:", f.dutyWrites, f.modeWrites)
	}

	// An automatic mode whose name the BMC does not give: 100 % is sent (the BMC goes on by its own curve),
	// the mode is not touched, and no duty below 100 % is ever sent.
	r = manualRig(t, 30, 95)
	if st, b := r.fan.SetMode(ctx, "heavyio", "owner"); st != 200 {
		t.Fatal(st, b)
	}
	f = &faultyBMC{Transport: r.bmc, modeEvery: 1}
	r.fan.t = f
	thrice(ctx, r.fan)
	if m, _ := r.bmc.State(); m != modeHeavyIO || len(f.modeWrites) != 0 || len(f.dutyWrites) == 0 {
		t.Fatal("the owner's mode was changed, or nothing was sent:", m, f.modeWrites, f.dutyWrites)
	}
	for _, d := range f.dutyWrites {
		if d != 100 {
			t.Fatal("a duty below 100 % was sent:", f.dutyWrites)
		}
	}

	// A BMC that answers nothing at all, with a hot CPU: nothing for two checks, then one try (100 % for both
	// zones, then its automatic mode), and the next one 30 s later at the earliest, however often the watchdog
	// looks. What happened is written once, not with every try.
	r = manualRig(t, 30, 95)
	f = &faultyBMC{Transport: r.bmc, modeEvery: 1, noDutyRead: true, noDutyWrite: true, noModeWrite: true}
	r.fan.t = f
	now := time.Now()
	r.fan.now = func() time.Time { return now }
	before := len(r.fan.recentEvents())
	for i := 0; i < fanBlindAfter-1; i++ {
		r.fan.WatchdogOnce(ctx)
		now = now.Add(WatchdogInterval)
	}
	if f.writes() != 0 {
		t.Fatalf("%d commands before the third check in a row", f.writes())
	}
	r.fan.WatchdogOnce(ctx)
	first := f.writes()
	if len(f.dutyWrites) != 2 || len(f.modeWrites) == 0 || len(f.modeWrites) > 2 {
		t.Fatalf("first try: duties %v, modes %v", f.dutyWrites, f.modeWrites)
	}
	for i := 0; i < 2; i++ { // the checks 10 and 20 s later
		now = now.Add(WatchdogInterval)
		r.fan.WatchdogOnce(ctx)
	}
	if f.writes() != first {
		t.Fatalf("%d more commands within 30 s to a BMC that does not answer", f.writes()-first)
	}
	now = now.Add(WatchdogInterval) // 30 s after the first try
	r.fan.WatchdogOnce(ctx)
	if f.writes() != 2*first {
		t.Fatalf("no second try after 30 s: %d commands, want %d", f.writes(), 2*first)
	}
	for i := 0; i < 60; i++ { // ten more minutes of it
		now = now.Add(WatchdogInterval)
		r.fan.WatchdogOnce(ctx)
	}
	if got := f.writes(); got != 22*first {
		t.Fatalf("%d commands in 10 minutes 50 s, want one try in 30 s (%d)", got, 22*first)
	}
	for _, d := range f.dutyWrites {
		if d != 100 {
			t.Fatal("a duty below 100 % was sent:", f.dutyWrites)
		}
	}
	ev := r.fan.recentEvents()[before:]
	if len(ev) != 2 || ev[0].Action != "watchdog failed" || ev[1].Action != "auto failed" {
		t.Fatalf("22 tries, want them written once: %+v", ev)
	}
	// the BMC answers again (mode full, 30 %, still hot): the ordinary rule, at once, and the spell is over
	f.modeEvery, f.noDutyRead, f.noDutyWrite, f.noModeWrite = 0, false, false, false
	now = now.Add(WatchdogInterval)
	r.fan.WatchdogOnce(ctx)
	if m, d := r.bmc.State(); m != modeFull || d != [2]byte{100, 100} || !r.fan.blindAt.IsZero() || r.fan.modeFails != 0 || r.fan.blindSaid != "" {
		t.Fatal(m, d, r.fan.blindAt, r.fan.modeFails, r.fan.blindSaid)
	}
	ev = r.fan.recentEvents()
	if last := ev[len(ev)-1]; last.Action != "watchdog: duty 100%" || strings.Contains(last.Detail, "does not say") {
		t.Fatalf("%+v", last)
	}

	// The BMC does not take 100 % but takes a mode: the fans are handed back to its automatic mode, so its own
	// control is in charge and not the fixed 30 %.
	r = manualRig(t, 30, 95)
	f = &faultyBMC{Transport: r.bmc, modeEvery: 1, noDutyWrite: true}
	r.fan.t = f
	thrice(ctx, r.fan)
	if m, _ := r.bmc.State(); m != modeOptimal {
		t.Fatal("not handed back to the BMC's automatic mode:", m)
	}

	// With a mode that can be read nothing changed: 100 %, at every check while it is hot, no mode change
	r = manualRig(t, 30, 95)
	f = &faultyBMC{Transport: r.bmc}
	r.fan.t = f
	r.fan.WatchdogOnce(ctx)
	if m, d := r.bmc.State(); m != modeFull || d != [2]byte{100, 100} || len(f.modeWrites) != 0 || !r.fan.blindAt.IsZero() {
		t.Fatal(m, d, f.modeWrites)
	}
}
