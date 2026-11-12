//go:build linux

package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// setStat rewrites one fake process's stat file: CPU ticks (user time) and memory (pages).
func setStat(t *testing.T, l *Linux, pid int, ticks uint64, rssPages int64) {
	t.Helper()
	line := fmt.Sprintf("%d (tool) S 1 1 1 0 -1 4194560 100 0 0 0 %d 0 0 0 20 0 4 0 9000 123456789 %d 18446744073709551615\n", pid, ticks, rssPages)
	if err := os.WriteFile(filepath.Join(l.proc, strconv.Itoa(pid), "stat"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Review N8 (the rest of L18; the reviewer's measurement). One process costs little since L18, but the listing
// kept a row with its command line for every process before the caller sorted and cut it to at most 200: 20000
// small processes with 300-character command lines held 43 MiB after one listing, 373 MiB were allocated on
// the way, and the agent's unit has a hard limit of 64 MiB. With Top, as the agent's server asks, the listing
// keeps the rows that can be shown and reads the command line of those only.
func TestProcessListMemoryDoesNotGrowWithTheNumberOfProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a fake /proc with thousands of entries")
	}
	const procs = 20000
	cmd := []byte("/usr/local/bin/tool\x00" + strings.Repeat("\U0001F600", 400)) // 4-byte characters
	cmdlines := map[int][]byte{}
	for pid := 1000; pid < 1000+procs; pid++ {
		cmdlines[pid] = cmd
	}
	l := fakeProc(t, cmdlines)
	o := ProcOptions{Cmdline: true, MemTotal: 16 << 30, Interval: time.Millisecond, Top: 200}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	list, total, err := l.Processes(context.Background(), o)
	runtime.ReadMemStats(&after)
	if err != nil || total != procs {
		t.Fatal(total, err)
	}
	live := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	allocated := int64(after.TotalAlloc) - int64(before.TotalAlloc)
	chars := 0
	for _, p := range list {
		if p.Cmdline == nil || len([]rune(*p.Cmdline)) > maxCmdlineLen {
			t.Fatalf("pid %d: command line %v", p.PID, p.Cmdline)
		}
		chars += len(*p.Cmdline)
	}
	t.Logf("%d processes: %d rows listed, %d KiB of command lines; %d KiB live after the listing, %d MiB allocated in all "+
		"(before: 43 MiB live, 373 MiB allocated; the unit's MemoryMax is 64 MiB)", procs, len(list), chars>>10, live>>10, allocated>>20)
	if len(list) > 3*o.Top {
		t.Errorf("%d rows listed, want at most %d", len(list), 3*o.Top)
	}
	if live > 6<<20 {
		t.Errorf("a listing of %d processes holds %d KiB", procs, live>>10)
	}
	if allocated > 64<<20 {
		t.Errorf("a listing of %d processes allocated %d MiB on the way", procs, allocated>>20)
	}
	// a caller that does not say how many rows it uses gets the same bound (the reviewer's proof asks this way)
	runtime.GC()
	runtime.ReadMemStats(&before)
	list, total, err = l.Processes(context.Background(), ProcOptions{Cmdline: true, MemTotal: 16 << 30, Interval: time.Millisecond})
	runtime.ReadMemStats(&after)
	if live := int64(after.HeapAlloc) - int64(before.HeapAlloc); err != nil || total != procs || len(list) > 3*defaultProcTop || live > 6<<20 {
		t.Errorf("without Top: %d rows, %d KiB live, %v", len(list), live>>10, err)
	}
	// the second listing (the usual case: there is a previous one to compare with) is no different
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, _, err := l.Processes(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if live := int64(after.HeapAlloc) - int64(before.HeapAlloc); live > 6<<20 {
		t.Errorf("the second listing holds %d KiB", live>>10)
	}
}

// With Top the listing has every row a caller that sorts by CPU, by memory or by pid and cuts to Top would
// show, the rows Keep names, and the true number of processes.
func TestProcessListTopHasTheRowsACallerShows(t *testing.T) {
	const procs, top = 1500, 50
	cmdlines := map[int][]byte{}
	for pid := 100; pid < 100+procs; pid++ {
		cmdlines[pid] = []byte("/usr/local/bin/tool\x00--job\x00" + strconv.Itoa(pid))
	}
	l := fakeProc(t, cmdlines)
	rng := rand.New(rand.NewSource(7))
	for pid := range cmdlines {
		setStat(t, l, pid, 1000, int64(rng.Intn(400))) // many equal memory sizes: ties
	}
	ctx := context.Background()
	if _, _, err := l.Processes(ctx, ProcOptions{Interval: time.Millisecond}); err != nil { // the first listing: CPU times kept
		t.Fatal(err)
	}
	wantCPU := map[int]uint64{}
	for pid := range cmdlines {
		d := uint64(rng.Intn(60)) // many equal CPU times: ties
		wantCPU[pid] = d
		setStat(t, l, pid, 1000+d, int64(rng.Intn(400)))
	}
	prev, prevAt := l.procPrev, l.procPrevAt
	all, total, err := l.Processes(ctx, ProcOptions{Cmdline: true, MemTotal: 16 << 30, Top: procs}) // every row
	if err != nil || total != procs || len(all) != procs {
		t.Fatal(len(all), total, err)
	}
	l.procPrev, l.procPrevAt = prev, prevAt // the same comparison again
	keep := map[int]bool{777: true, 1234: true, 99999: true}
	got, total, err := l.Processes(ctx, ProcOptions{Cmdline: true, MemTotal: 16 << 30, Top: top, Keep: func(pid int) bool { return keep[pid] }})
	if err != nil || total != procs {
		t.Fatal(total, err)
	}
	if len(got) > 3*top+2 || len(got) < top {
		t.Fatalf("%d rows", len(got))
	}
	listed := map[int]Process{}
	for _, p := range got {
		listed[p.PID] = p
		if p.Name == nil || p.Username == nil || *p.Username != "alice" || p.Cmdline == nil || !strings.HasSuffix(*p.Cmdline, strconv.Itoa(p.PID)) ||
			p.CPUPercent == nil || p.RSS == nil || p.MemPercent == nil || p.Status == nil {
			t.Fatalf("an incomplete row: %+v", p)
		}
	}
	for _, pid := range []int{777, 1234} {
		if _, ok := listed[pid]; !ok {
			t.Errorf("the row Keep named, pid %d, is missing", pid)
		}
	}
	// the caller's orders (the agent's SortProcesses): highest first, then by pid. CPU is compared by the ticks
	// the test gave, so that the two listings' slightly different time spans do not matter.
	orders := map[string]func(a, b Process) bool{
		"cpu": func(a, b Process) bool {
			if wantCPU[a.PID] != wantCPU[b.PID] {
				return wantCPU[a.PID] > wantCPU[b.PID]
			}
			return a.PID < b.PID
		},
		"mem": func(a, b Process) bool {
			if *a.RSS != *b.RSS {
				return *a.RSS > *b.RSS
			}
			return a.PID < b.PID
		},
		"pid": func(a, b Process) bool { return a.PID < b.PID },
	}
	for name, less := range orders {
		want := append([]Process(nil), all...)
		sort.Slice(want, func(i, j int) bool { return less(want[i], want[j]) })
		for i, p := range want[:top] {
			if _, ok := listed[p.PID]; !ok {
				t.Errorf("order %s: row %d of the full listing (pid %d) is not in the short one", name, i, p.PID)
			}
		}
	}
	// the rows come in pid order, as before
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].PID < got[j].PID }) ||
		!sort.SliceIsSorted(all, func(i, j int) bool { return all[i].PID < all[j].PID }) {
		t.Error("the rows are not in pid order")
	}
}

// The CPU times of at most maxTrackedProcs processes are kept between listings; a process beyond that is
// listed with 0 % CPU instead of growing the table.
func TestProcessListTracksABoundedNumberOfProcesses(t *testing.T) {
	cmdlines := map[int][]byte{}
	for pid := 100; pid < 160; pid++ {
		cmdlines[pid] = []byte("tool")
	}
	l := fakeProc(t, cmdlines)
	l.trackProcs = 20
	ctx := context.Background()
	if _, _, err := l.Processes(ctx, ProcOptions{Interval: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if len(l.procPrev) != 20 {
		t.Fatalf("%d processes' CPU times are kept, want 20", len(l.procPrev))
	}
	for pid := range cmdlines {
		setStat(t, l, pid, 5000, 2048)
	}
	got, total, err := l.Processes(ctx, ProcOptions{Top: 100})
	if err != nil || total != 60 || len(got) != 60 || len(l.procPrev) != 20 {
		t.Fatal(len(got), total, err, len(l.procPrev))
	}
	busy := 0
	for _, p := range got {
		if p.CPUPercent == nil {
			t.Fatalf("pid %d has no CPU value", p.PID)
		}
		if *p.CPUPercent > 0 {
			busy++
		}
	}
	if busy != 20 {
		t.Fatalf("%d processes show CPU use, want the 20 that are tracked", busy)
	}
	if maxTrackedProcs != 32768 || procDirBatch > 4096 {
		t.Fatal(maxTrackedProcs, procDirBatch)
	}
}

// procTop holds at most 2n rows while it is fed, and ends with the n first of its order.
func TestProcTop(t *testing.T) {
	top := &procTop{n: 10, less: func(a, b *procRow) bool {
		if a.rss != b.rss {
			return a.rss > b.rss
		}
		return a.pid < b.pid
	}}
	rng := rand.New(rand.NewSource(1))
	var all []procRow
	for i := 0; i < 5000; i++ {
		r := procRow{pid: i + 1, rss: int64(rng.Intn(50))}
		all = append(all, r)
		top.add(r)
		if len(top.rows) >= 20 {
			t.Fatalf("%d rows held after %d", len(top.rows), i+1)
		}
	}
	top.cut()
	sort.Slice(all, func(i, j int) bool { return top.less(&all[i], &all[j]) })
	if len(top.rows) != 10 {
		t.Fatal(len(top.rows))
	}
	for i, r := range top.rows {
		if r.pid != all[i].pid {
			t.Fatalf("row %d: pid %d, want %d", i, r.pid, all[i].pid)
		}
	}
	none := &procTop{less: top.less}
	none.add(procRow{pid: 1})
	if none.cut(); len(none.rows) != 0 {
		t.Fatal("n = 0 keeps rows")
	}
}

// TestProcessListNameHoldsNoArguments (audit 5, r2-a2-02): a listing made with command lines off sends no
// argument of any process, also not in "name": a program with a name of 15 characters or more that wrote its
// own title has its arguments in its first argument.
func TestProcessListNameHoldsNoArguments(t *testing.T) {
	const secret = "POC-NOT-A-REAL-SECRET"
	l := fakeProc(t, map[int][]byte{
		300: []byte("verylongprogramname --db-password=" + secret + " --user=admin"),
		301: []byte("/opt/app/some-long-helper-name --type=renderer --secret=" + secret + "\x00"),
		302: []byte("/usr/bin/nvidia-persistenced\x00--token\x00" + secret + "\x00"),
	})
	for pid, comm := range map[int]string{300: "verylongprogram", 301: "some-long-helpe", 302: "nvidia-persiste"} {
		line := fmt.Sprintf("%d (%s) S 1 1 1 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 4 0 9000 123456789 2048 18446744073709551615\n", pid, comm)
		if err := os.WriteFile(filepath.Join(l.proc, strconv.Itoa(pid), "stat"), []byte(line), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want := map[int]string{300: "verylongprogramname", 301: "some-long-helper-name", 302: "nvidia-persistenced"}
	for _, withCmdline := range []bool{false, true} {
		list, _, err := l.Processes(context.Background(), ProcOptions{Cmdline: withCmdline, MemTotal: 16 << 30, Interval: time.Millisecond})
		if err != nil || len(list) != 3 {
			t.Fatal(len(list), err)
		}
		for _, p := range list {
			if p.Name == nil || *p.Name != want[p.PID] {
				t.Errorf("cmdline %v: pid %d has the name %q, want %q", withCmdline, p.PID, *p.Name, want[p.PID])
			}
			if !withCmdline && p.Cmdline != nil {
				t.Errorf("pid %d: a command line although they are off: %q", p.PID, *p.Cmdline)
			}
			if b, _ := json.Marshal(p); !withCmdline && bytes.Contains(b, []byte(secret)) {
				t.Errorf("pid %d: the row holds an argument although command lines are off: %s", p.PID, b)
			}
		}
	}
}
