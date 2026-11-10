//go:build linux

package collect

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The real collector on the machine running the tests: values must be present and sane.
func TestLinuxCollector(t *testing.T) {
	c := NewSystem()
	st := c.Static()
	if st.Platform.System != "Linux" || st.Logical < 1 || st.Hostname == "" {
		t.Fatalf("%+v", st)
	}
	time.Sleep(600 * time.Millisecond)
	s := c.Sample(context.Background())
	if s.CPUPercent == nil || *s.CPUPercent < 0 || *s.CPUPercent > 100 || s.Memory.Total <= 0 || s.Memory.Used <= 0 ||
		s.UptimeS == nil || len(s.LoadAvg) != 3 {
		t.Fatalf("%+v", s)
	}
	procs, total, err := c.Processes(context.Background(), ProcOptions{Cmdline: true, MemTotal: s.Memory.Total, Interval: 100 * time.Millisecond})
	if err != nil || total < 1 || len(procs) == 0 {
		t.Fatal(total, len(procs), err)
	}
	me := false
	for _, p := range procs {
		if p.PID == os.Getpid() {
			me = p.Name != nil && p.RSS != nil && *p.RSS > 0 && p.CPUPercent != nil && p.CreateTime != nil && p.Cmdline != nil
		}
	}
	if !me {
		t.Fatal("own process missing or incomplete")
	}
}

// fakeProc writes a /proc with these processes (pid -> cmdline bytes) and returns a collector reading it.
func fakeProc(t *testing.T, cmdlines map[int][]byte) *Linux {
	t.Helper()
	root := t.TempDir()
	proc, etc := filepath.Join(root, "proc"), filepath.Join(root, "etc")
	for _, d := range []string{proc, etc, filepath.Join(root, "sys")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, data []byte) {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(etc, "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n"))
	for pid, cmd := range cmdlines {
		dir := filepath.Join(proc, strconv.Itoa(pid))
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(dir, "stat"), []byte(strconv.Itoa(pid)+" (tool) S 1 1 1 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 4 0 9000 123456789 2048 18446744073709551615\n"))
		write(filepath.Join(dir, "status"), []byte("Name:\ttool\nUid:\t1000\t1000\t1000\t1000\n"))
		write(filepath.Join(dir, "cmdline"), cmd)
	}
	return &Linux{proc: proc, sys: filepath.Join(root, "sys"), etc: etc, prevRAPL: map[string]RAPLZone{}, lastRAPL: map[string]float64{}, btime: 1700000000}
}

// Audit 3, L18: every process's whole command line was read into memory before it was cut. 60 processes with
// about 1.8 MB of arguments each pushed the agent over its 64 MB limit and the system killed it. Now 4 KiB of
// each are read and 300 characters kept, with the secrets hidden while reading.
func TestProcessListMemoryIsBounded(t *testing.T) {
	const procs, size = 24, 2 << 20
	big := append([]byte("/usr/local/bin/tool\x00--password=hunter2\x00--name\x00job\x00"), bytes.Repeat([]byte("A"), size)...)
	cmdlines := map[int][]byte{}
	for pid := 100; pid < 100+procs; pid++ {
		cmdlines[pid] = big
	}
	cmdlines[7] = []byte("/usr/sbin/sshd\x00-D\x00")
	cmdlines[8] = nil // a kernel thread: empty cmdline
	cmdlines[9] = []byte("mysql\x00-uroot\x00-pS3cretPw\x00appdb\x00")
	l := fakeProc(t, cmdlines)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	list, total, err := l.Processes(context.Background(), ProcOptions{Cmdline: true, MemTotal: 16 << 30, Interval: time.Millisecond})
	runtime.ReadMemStats(&after)
	if err != nil || total != procs+3 || len(list) != procs+3 {
		t.Fatal(total, len(list), err)
	}
	// Two scans of 24 processes with 2 MiB each: reading them whole allocated more than 96 MiB.
	grown := int64(after.TotalAlloc) - int64(before.TotalAlloc)
	t.Logf("allocated %d KiB for %d processes", grown>>10, len(list))
	if grown > 4<<20 {
		t.Fatalf("listing %d processes with %d MiB command lines allocated %d bytes", procs, size>>20, grown)
	}
	kept := 0
	for _, p := range list {
		switch {
		case p.PID >= 100:
			if p.Cmdline == nil {
				t.Fatalf("pid %d: no command line", p.PID)
			}
			c := *p.Cmdline
			kept += len(c)
			if n := utf8.RuneCountInString(c); n != maxCmdlineLen || !strings.HasSuffix(c, "…") {
				t.Fatalf("pid %d: %d characters: %.80q", p.PID, n, c)
			}
			if !strings.HasPrefix(c, "/usr/local/bin/tool --password=*** --name job AAAA") || strings.Contains(c, "hunter2") {
				t.Fatalf("pid %d: %.80q", p.PID, c)
			}
			if p.Name == nil || *p.Name != "tool" || p.Username == nil || *p.Username != "alice" {
				t.Fatalf("pid %d: %+v", p.PID, p)
			}
		case p.PID == 7:
			if p.Cmdline == nil || *p.Cmdline != "/usr/sbin/sshd -D" {
				t.Fatalf("short command line: %v", p.Cmdline)
			}
		case p.PID == 8:
			if p.Cmdline != nil {
				t.Fatalf("kernel thread: %q", *p.Cmdline)
			}
		case p.PID == 9:
			if p.Cmdline == nil || *p.Cmdline != "mysql -uroot -p*** appdb" {
				t.Fatalf("secret hidden per argument while reading: %v", *p.Cmdline)
			}
		}
	}
	if kept > procs*maxCmdlineLen*utf8.UTFMax {
		t.Fatalf("kept %d bytes of command lines", kept)
	}
	// without command lines nothing of them is kept at all
	list, _, _ = l.Processes(context.Background(), ProcOptions{Interval: time.Millisecond})
	for _, p := range list {
		if p.Cmdline != nil {
			t.Fatalf("cmdline off: %q", *p.Cmdline)
		}
	}
}

func TestReadCmdline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdline")
	buf := make([]byte, maxCmdlineRead)
	for name, tc := range map[string]struct {
		data    []byte
		wantLen int
		cut     bool
	}{
		"empty":                         {nil, 0, false},
		"short":                         {[]byte("a\x00b\x00"), 4, false},
		"exactly the limit":             {bytes.Repeat([]byte("x"), maxCmdlineRead), maxCmdlineRead, false},
		"one byte below the limit":      {bytes.Repeat([]byte("x"), maxCmdlineRead-1), maxCmdlineRead - 1, false},
		"long":                          {bytes.Repeat([]byte("x"), 1<<20), maxCmdlineRead, true},
		"cut inside a 2-byte character": {append(bytes.Repeat([]byte("x"), maxCmdlineRead-1), []byte("ä")...), maxCmdlineRead - 1, true},
		"cut inside a 4-byte character": {append(bytes.Repeat([]byte("x"), maxCmdlineRead-2), []byte("😀")...), maxCmdlineRead - 2, true},
		"cut after a whole character":   {append(bytes.Repeat([]byte("x"), maxCmdlineRead-2), []byte("äxx")...), maxCmdlineRead, true},
	} {
		if err := os.WriteFile(path, tc.data, 0o600); err != nil {
			t.Fatal(err)
		}
		got, cut := readCmdline(path, buf)
		if len(got) != tc.wantLen || cut != tc.cut || !utf8.Valid(got) {
			t.Errorf("%s: %d bytes, cut %v (want %d, %v)", name, len(got), cut, tc.wantLen, tc.cut)
		}
	}
	if got, cut := readCmdline(filepath.Join(dir, "gone"), buf); got != nil || cut {
		t.Error("missing file")
	}
	if a := cmdlineArgs([]byte("a\x00b c\x00\x00")); len(a) != 2 || a[1] != "b c" {
		t.Error(a)
	}
	if a := cmdlineArgs(nil); a != nil {
		t.Error(a)
	}
}
