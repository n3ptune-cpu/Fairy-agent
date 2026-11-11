package agent

// Audit 4, T-08: GET /fan/status (read token) and the fan watchdog share one lock, /fan/status made up to
// three live BMC commands under it, four such requests may be in flight, and the watchdog's time limit (20 s)
// started before the watchdog had the lock. With a BMC that needs 1.5 s for a command the watchdog got the
// lock when its time was over: nothing reached the BMC, check after check, while the CPU was over the limit.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi/fakebmc"
)

// slowBMC is a BMC whose every command takes d. Like ipmitool it serves one command at a time and fails at
// once when the caller's time is already over.
type slowBMC struct {
	*fakebmc.BMC
	d        time.Duration
	mu       sync.Mutex
	commands atomic.Int32 // commands that reached the BMC
	expired  atomic.Int32 // commands refused because the caller's time was over
	sets     atomic.Int32 // "set duty" commands that reached the BMC
	fail     atomic.Bool  // answer every command with an error
}

func (b *slowBMC) Raw(ctx context.Context, netfn, cmd byte, data []byte) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ctx.Err() != nil {
		b.expired.Add(1)
		return nil, ctx.Err()
	}
	select {
	case <-ctx.Done():
		b.expired.Add(1)
		return nil, ctx.Err()
	case <-time.After(b.d):
	}
	b.commands.Add(1)
	if b.fail.Load() {
		return nil, context.DeadlineExceeded
	}
	if netfn == ipmi.NetFnOEM && cmd == ipmi.CmdSMCFanDuty && len(data) == 4 && data[1] == 0x01 {
		b.sets.Add(1)
	}
	return b.BMC.Raw(ctx, netfn, cmd, data)
}

func (b *slowBMC) duty() [2]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, d := b.BMC.State()
	return d
}

func hotCPU() []collect.Temp {
	return []collect.Temp{{Sensor: "coretemp", Label: collect.P("Package id 0"), Current: 97}}
}

// fanTimeScale runs these tests ten times faster than the real thing: 2 s instead of the 20 s a fan operation
// has, so 150 ms and 250 ms for a BMC command stand for 1.5 s and 2.5 s.
func fanTimeScale(t *testing.T) {
	t.Helper()
	old := fanBMCTimeout
	fanBMCTimeout = old / 10
	t.Cleanup(func() { fanBMCTimeout = old })
}

func TestFanStatusFloodDoesNotStarveTheWatchdog(t *testing.T) {
	fanTimeScale(t)
	cfg := mustParse(t, "ipmi: {enabled: true}\nfan_control: {enabled: true}\n")
	for _, per := range []time.Duration{150 * time.Millisecond, 250 * time.Millisecond} { // 1.5 s and 2.5 s for a command
		slow := &slowBMC{BMC: fakebmc.X11SCAF(), d: per}
		slow.BMC.Mode, slow.BMC.Duty = 1, [2]byte{30, 30} // "full" with a fixed 30 %: what the watchdog guards
		fan := NewFan(slow, nil, cfg.FanControl, hotCPU)

		// the watchdog alone, CPU at 97 °C (limit 80 °C): it sends both zones to 100 %
		start := time.Now()
		fan.WatchdogOnce(context.Background())
		alone := time.Since(start)
		if slow.duty() != [2]byte{100, 100} || slow.expired.Load() != 0 {
			t.Fatalf("%s a command, alone: duty %v, %d commands out of time", per, slow.duty(), slow.expired.Load())
		}

		// four callers ask /fan/status without a pause (the route lets four be in flight)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var asked atomic.Int32
		for i := 0; i < maxFanStatus; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second) // a direct caller is patient
					fan.Status(ctx)
					cancel()
					asked.Add(1)
				}
			}()
		}
		for check := 1; check <= 3; check++ {
			slow.mu.Lock()
			slow.BMC.Duty = [2]byte{30, 30} // an admin set a fixed duty again
			slow.mu.Unlock()
			time.Sleep(per / 2) // a status request is asking the BMC
			sets, expired := slow.sets.Load(), slow.expired.Load()
			start := time.Now()
			fan.WatchdogOnce(context.Background())
			took := time.Since(start)
			t.Logf("%s a command, next to 4 x /fan/status, check %d: %s (alone %s), duty now %v, duty commands %d, commands out of time %d",
				per, check, took.Round(10*time.Millisecond), alone.Round(10*time.Millisecond), slow.duty(), slow.sets.Load()-sets, slow.expired.Load()-expired)
			if slow.duty() != [2]byte{100, 100} {
				t.Errorf("%s a command, check %d: the watchdog did not get the fans to 100 %% (duty %v) with the CPU at 97 C; %d of its commands ran out of time",
					per, check, slow.duty(), slow.expired.Load()-expired)
			}
			// it waits for at most one status request (three commands), then needs what it needs alone
			if limit := alone + 3*per + 2*time.Second; took > limit {
				t.Errorf("%s a command, check %d: the watchdog took %s, more than %s", per, check, took, limit)
			}
		}
		close(stop)
		wg.Wait()
		if asked.Load() == 0 {
			t.Errorf("%s a command: no status request was answered during the test", per)
		}
	}
}

// One status request asks the BMC at a time; the requests that waited behind it get what it was told. Nothing
// is kept after that: a later request asks the BMC again, so a status is never older than its request.
func TestFanStatusAsksTheBMCOnceForThoseWhoWait(t *testing.T) {
	cfg := mustParse(t, "ipmi: {enabled: true}\nfan_control: {enabled: true}\n")
	slow := &slowBMC{BMC: fakebmc.X11SCAF(), d: 100 * time.Millisecond}
	slow.BMC.Mode, slow.BMC.Duty = 1, [2]byte{40, 50}
	cool := func() []collect.Temp {
		return []collect.Temp{{Sensor: "coretemp", Label: collect.P("Package id 0"), Current: 40}}
	}
	fan := NewFan(slow, nil, cfg.FanControl, cool)
	ctx := context.Background()
	status := func() (mode any, duty map[string]int, errText any, commands int32) {
		before := slow.commands.Load()
		s := fan.Status(ctx)
		return s["mode"], s["duty"].(map[string]int), s["error"], slow.commands.Load() - before
	}
	// eight at the same moment: the BMC is asked once or twice (three commands each), not eight times
	before := slow.commands.Load()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := fan.Status(ctx)
			if duty := s["duty"].(map[string]int); s["mode"] != "full" || duty["0"] != 40 || duty["1"] != 50 || s["error"] != nil {
				t.Error("burst:", s["mode"], duty, s["error"])
			}
			s["duty"].(map[string]int)["0"] = 1 // what a caller does with its answer reaches nobody else
		}()
	}
	wg.Wait()
	if n := slow.commands.Load() - before; n != 3 && n != 6 {
		t.Fatalf("8 status requests at once: %d BMC commands, want 3 (or 6)", n)
	}
	// one after the other: each asks the BMC
	slow.d = time.Millisecond
	for i := 0; i < 3; i++ {
		if mode, duty, e, n := status(); mode != "full" || duty["0"] != 40 || duty["1"] != 50 || e != nil || n != 3 {
			t.Fatal("one after the other:", mode, duty, e, n)
		}
	}
	// a change through the agent, and a change at the BMC itself: the next status shows it
	if st, body := fan.SetDuty(ctx, 0, 70, "test"); st != 200 {
		t.Fatal(st, body)
	}
	if _, duty, _, _ := status(); duty["0"] != 70 {
		t.Fatal("after SetDuty:", duty)
	}
	slow.mu.Lock()
	slow.BMC.Mode = 0
	slow.mu.Unlock()
	if mode, _, _, n := status(); mode != "standard" || n != 1 {
		t.Fatal("after a change at the BMC:", mode, n)
	}
	// a BMC that does not answer: every request says so, and the first good answer is used again
	slow.fail.Store(true)
	for i := 0; i < 2; i++ {
		if mode, _, e, n := status(); mode != nil || e == nil || n != 1 {
			t.Fatal("failing BMC:", mode, e, n)
		}
	}
	slow.fail.Store(false)
	if mode, _, e, _ := status(); mode != "standard" || e != nil {
		t.Fatal("BMC back:", mode, e)
	}
}
