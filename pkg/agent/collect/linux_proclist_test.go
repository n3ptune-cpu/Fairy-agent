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
// own title has its arguments in its first argument. Since audit 5, r3-a1-03 the name of such a listing is not
// taken from the command line at all: it is the kernel's name, completed from the link to the program's file
// where the agent may read that link.
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
	// the link to the program's file: 300 has one, 301 has none (another user's process: the agent may not
	// read it), 302 has one to a file that was removed since
	for pid, exe := range map[int]string{300: "/opt/tools/verylongprogramname", 302: "/usr/bin/nvidia-persistenced (deleted)"} {
		if err := os.Symlink(exe, filepath.Join(l.proc, strconv.Itoa(pid), "exe")); err != nil {
			t.Fatal(err)
		}
	}
	want := map[bool]map[int]string{
		true:  {300: "verylongprogramname", 301: "some-long-helper-name", 302: "nvidia-persistenced"},
		false: {300: "verylongprogramname", 301: "some-long-helpe", 302: "nvidia-persistenced"},
	}
	for _, withCmdline := range []bool{false, true} {
		list, _, err := l.Processes(context.Background(), ProcOptions{Cmdline: withCmdline, MemTotal: 16 << 30, Interval: time.Millisecond})
		if err != nil || len(list) != 3 {
			t.Fatal(len(list), err)
		}
		for _, p := range list {
			if p.Name == nil || *p.Name != want[withCmdline][p.PID] {
				t.Errorf("cmdline %v: pid %d has the name %q, want %q", withCmdline, p.PID, *p.Name, want[withCmdline][p.PID])
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

// TestProcessListNamesWithCommandLinesOff (audit 5, r3-a1-03, and the second review's note on F5): the 22
// titles the reviewer started real programs with, four of which still put argument text into "name" (no
// separator after the name, a no-break space or an ideographic space for one, the name first seen inside an
// argument). With command lines off the name is the program file's name, or the kernel's 15 characters of it
// where the link to the file cannot be read, whatever the title says; with a made-up secret in every title,
// none is in any row. Each shape runs twice: with the link (a process the agent may look into) and without.
func TestProcessListNamesWithCommandLinesOff(t *testing.T) {
	const dir = "/srv/f5"
	shapes := []struct {
		what, file, title string
	}{
		{"a title with arguments (Electron style)", dir + "/verylongprogramname", dir + "/verylongprogramname --db-password=SECRET-A --user=admin"},
		{"spaces in the real path", dir + "/dir with space/verylongprogramname", dir + "/dir with space/verylongprogramname"},
		{"spaces in the path, title with arguments", dir + "/dir with space/verylongprogramname", dir + "/dir with space/verylongprogramname --token=SECRET-B2"},
		{"a file name with spaces", dir + "/very long program name with spaces", dir + "/very long program name with spaces"},
		{"a file name with spaces + arguments in the title", dir + "/very long program name with spaces", dir + "/very long program name with spaces --pw=SECRET-C2"},
		{"a name of exactly 15 characters", dir + "/exactly15chars_", dir + "/exactly15chars_"},
		{"exactly 15 characters, title with arguments", dir + "/exactly15chars_", "exactly15chars_ --key=SECRET-D2"},
		{"a long name, plain", dir + "/averyveryverylongname", dir + "/averyveryverylongname"},
		{"a deleted executable", dir + "/deletedprogramnamelong (deleted)", dir + "/deletedprogramnamelong"},
		{"a file name that is not UTF-8", dir + "/nonutf8-\xff\xfe-programname", dir + "/nonutf8-\xff\xfe-programname"},
		{"not UTF-8 after the name, with arguments", dir + "/verylongprogramname", dir + "/verylongprogramname\xff\xfe --pw=SECRET-H2"},
		{"the name first shows up inside an argument", dir + "/verylongprogramname", "worker --socket=/run/verylongprogramname.sock;token=SECRET-I"},
		{"a tab between name and arguments", dir + "/verylongprogramname", "verylongprogramname\t--pw=SECRET-J"},
		{"a line feed between name and arguments", dir + "/verylongprogramname", "verylongprogramname\n--pw=SECRET-K"},
		{"a no-break space (U+00A0) between name and arguments", dir + "/verylongprogramname", "verylongprogramname\u00a0--pw=SECRET-L"},
		{"no separator at all", dir + "/verylongprogramname", "verylongprogramname--pw=SECRET-M"},
		{"a relative path", dir + "/verylongprogramname", "./verylongprogramname --pw=SECRET-N"},
		{"a login shell's dash", dir + "/verylongshellname", "-verylongshellname"},
		{"a folder of the same beginning, then arguments", dir + "/verylongprogramname-dir/shortname", dir + "/verylongprogramname-dir/shortname --pw=SECRET-P"},
		{"the name after a colon, then arguments", dir + "/verylongprogramname", "sshd: verylongprogramname --pw=SECRET-Q"},
		{"an empty argv[0]", dir + "/verylongprogramname", ""},
		{"U+3000 (ideographic space) before the arguments", dir + "/verylongprogramname", "verylongprogramname\u3000--pw=SECRET-S"},
	}
	if len(shapes) != 22 {
		t.Fatal(len(shapes))
	}
	fileName := func(exe string) string {
		return strings.TrimSuffix(exe[strings.LastIndexByte(exe, '/')+1:], " (deleted)")
	}
	comm := func(exe string) string { // the kernel's name: the file's name, cut at 15
		n := fileName(exe)
		if len(n) > 15 {
			n = n[:15]
		}
		return n
	}
	cmdlines := map[int][]byte{}
	for i, c := range shapes {
		cmdlines[1000+i], cmdlines[2000+i] = []byte(c.title+"\x00600\x00"), []byte(c.title+"\x00600\x00")
	}
	l := fakeProc(t, cmdlines)
	for i, c := range shapes {
		for _, pid := range []int{1000 + i, 2000 + i} {
			line := fmt.Sprintf("%d (%s) S 1 1 1 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 4 0 9000 123456789 2048 18446744073709551615\n", pid, comm(c.file))
			if err := os.WriteFile(filepath.Join(l.proc, strconv.Itoa(pid), "stat"), []byte(line), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(c.file, filepath.Join(l.proc, strconv.Itoa(1000+i), "exe")); err != nil { // 2000+i: no link
			t.Fatal(err)
		}
	}
	list, _, err := l.Processes(context.Background(), ProcOptions{Cmdline: false, MemTotal: 16 << 30, Interval: time.Millisecond})
	if err != nil || len(list) != 2*len(shapes) {
		t.Fatal(len(list), err)
	}
	for _, p := range list {
		c := shapes[p.PID%1000]
		want := fileName(c.file) // with the link: the file's whole name
		if p.PID >= 2000 {
			want = comm(c.file) // without: the kernel's 15 characters
		}
		if p.Name == nil || *p.Name != want {
			t.Errorf("%s (pid %d): name %q, want %q", c.what, p.PID, *p.Name, want)
		}
		if b, _ := json.Marshal(p); p.Cmdline != nil || bytes.Contains(b, []byte("SECRET")) || bytes.Contains(b, []byte("--")) {
			t.Errorf("%s (pid %d): the row holds argument text although command lines are off: %s", c.what, p.PID, b)
		}
	}
	// the same titles with command lines ON: the four shapes the name cannot be told from still carry
	// argument text in "name" (ProcName says why); this pins what the guide says about that setting
	list, _, err = l.Processes(context.Background(), ProcOptions{Cmdline: true, MemTotal: 16 << 30, Interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var inName []string
	for _, p := range list {
		if p.PID < 2000 && strings.Contains(*p.Name, "SECRET") {
			inName = append(inName, *p.Name)
		}
	}
	sort.Strings(inName)
	if want := []string{"verylongprogramname--pw=SECRET-M", "verylongprogramname.sock;token=SECRET-I",
		"verylongprogramname\u00a0--pw=SECRET-L", "verylongprogramname\u3000--pw=SECRET-S"}; strings.Join(inName, "|") != strings.Join(want, "|") {
		t.Errorf("with command lines on, names that hold argument text: %q, want the four known shapes %q", inName, want)
	}
}
