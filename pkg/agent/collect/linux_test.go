//go:build linux

package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
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

// Audit 3, I35: the agent's own sources are trusted, but a driver can still report "nan" or "inf", and one such
// value made the whole /metrics answer impossible to write. The sample leaves them out and keeps the rest.
func TestSampleDropsImpossibleReadings(t *testing.T) {
	l := fakeProc(t, nil)
	write := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(l.proc, "loadavg"), "nan 0.50 0.10 1/100 4242\n")
	write(filepath.Join(l.proc, "uptime"), "-5.00 1.00\n")
	write(filepath.Join(l.proc, "meminfo"), "MemTotal: 16000000 kB\nMemAvailable: 8000000 kB\n")
	hw := filepath.Join(l.sys, "class", "hwmon", "hwmon0")
	write(filepath.Join(hw, "name"), "k10temp\n")
	for file, v := range map[string]string{
		"temp1_input": "nan", "temp1_label": "Tctl",
		"temp2_input": "45000", "temp2_label": "Tccd1", "temp2_max": "nan", "temp2_crit": "95000",
		"temp3_input": "inf", "temp4_input": "-inf", "temp5_input": "1e400", "temp6_input": "9e20",
		"fan1_input": "nan", "fan1_label": "cpu", "fan2_input": "1200", "fan2_label": "rear", "fan3_input": "inf", "fan3_label": "x",
		"fan4_input": "-1", "fan4_label": "y",
		"in0_input": "inf", "in1_input": "12000", "in2_input": "nan",
	} {
		write(filepath.Join(hw, file), v+"\n")
	}
	bat := filepath.Join(l.sys, "class", "power_supply", "BAT0")
	for file, v := range map[string]string{"type": "Battery", "status": "Discharging", "capacity": "nan", "energy_now": "1e308",
		"energy_full": "1e308", "energy_full_design": "1e308", "power_now": "nan"} {
		write(filepath.Join(bat, file), v+"\n")
	}
	bat1 := filepath.Join(l.sys, "class", "power_supply", "BAT1") // two batteries: their sums overflow
	for file, v := range map[string]string{"type": "Battery", "status": "Discharging", "energy_now": "1e308",
		"energy_full": "1e308", "energy_full_design": "1e308"} {
		write(filepath.Join(bat1, file), v+"\n")
	}

	s := l.Sample(context.Background())
	if _, err := json.Marshal(s); err != nil {
		t.Fatalf("the sample cannot be written: %v\n%+v", err, s)
	}
	if s.LoadAvg != nil || s.UptimeS != nil {
		t.Errorf("load %v uptime %v", s.LoadAvg, s.UptimeS)
	}
	if len(s.Temps) != 1 || s.Temps[0].Current != 45 || *s.Temps[0].Label != "Tccd1" || s.Temps[0].High != nil || *s.Temps[0].Critical != 95 {
		t.Errorf("temps %+v", s.Temps)
	}
	if len(s.Fans) != 1 || s.Fans[0].RPM != 1200 || len(s.Voltages) != 1 || s.Voltages[0].Volts != 12 {
		t.Errorf("fans %+v voltages %+v", s.Fans, s.Voltages)
	}
	if s.Battery == nil || s.Battery.State != "discharging" || s.Battery.Percent != nil || s.Battery.HealthPct != nil || s.Battery.PowerW != nil {
		t.Errorf("battery %+v", s.Battery)
	}
	if s.Power.BatteryW != nil || s.Memory.Total != 16000000<<10 {
		t.Errorf("power %+v memory %+v", s.Power, s.Memory)
	}

	// good values pass unchanged
	write(filepath.Join(l.proc, "loadavg"), "1.25 0.50 0.10 1/100 4242\n")
	write(filepath.Join(l.proc, "uptime"), "86400.55 1.00\n")
	s = l.Sample(context.Background())
	if len(s.LoadAvg) != 3 || s.LoadAvg[0] != 1.25 || s.UptimeS == nil || *s.UptimeS != 86400 {
		t.Errorf("load %v uptime %v", s.LoadAvg, s.UptimeS)
	}
}

func TestCleanSample(t *testing.T) {
	nan, inf, big := math.NaN(), math.Inf(1), 1e308
	s := Sample{CPUPercent: &nan, UptimeS: P(int64(-1)), LoadAvg: []float64{0.1, inf, 0.3},
		Power:   Power{CPUPackageW: &inf, GPUW: &big, BatteryW: &nan, BMCW: P(180.0)},
		Battery: &BatteryStatus{Percent: P(250.0), HealthPct: &nan, PowerW: &inf, TimeRemainingS: P(int64(-9))}}
	cleanSample(&s)
	if s.CPUPercent != nil || s.UptimeS != nil || s.LoadAvg != nil || s.Power.CPUPackageW != nil || s.Power.GPUW != nil ||
		s.Power.BatteryW != nil || *s.Power.BMCW != 180 || s.Battery.Percent != nil || s.Battery.HealthPct != nil ||
		s.Battery.PowerW != nil || s.Battery.TimeRemainingS != nil {
		t.Fatalf("%+v %+v", s, s.Battery)
	}
	if _, err := json.Marshal(s); err != nil {
		t.Fatal(err)
	}
	ok := Sample{CPUPercent: P(12.5), UptimeS: P(int64(600)), LoadAvg: []float64{0, 0.2, 0.3},
		Power:   Power{CPUPackageW: P(45.5), BatteryW: P(-12.0)},
		Battery: &BatteryStatus{Percent: P(100.0), HealthPct: P(103.2), PowerW: P(-30.0), TimeRemainingS: P(int64(0))}}
	cleanSample(&ok)
	if *ok.CPUPercent != 12.5 || *ok.UptimeS != 600 || len(ok.LoadAvg) != 3 || *ok.Power.CPUPackageW != 45.5 || *ok.Power.BatteryW != -12 ||
		*ok.Battery.Percent != 100 || *ok.Battery.HealthPct != 103.2 || *ok.Battery.PowerW != -30 || *ok.Battery.TimeRemainingS != 0 {
		t.Fatalf("good values changed: %+v %+v", ok, ok.Battery)
	}
	t1, f1, v1 := cleanSensors(
		[]Temp{{Sensor: "a", Current: nan}, {Sensor: "b", Current: 40, High: &inf, Critical: P(90.0)}, {Sensor: "c", Current: big}},
		[]Fan{{Name: "a", RPM: inf}, {Name: "b", RPM: 900}, {Name: "c", RPM: 0}},
		[]Voltage{{Name: "a", Volts: -inf}, {Name: "b", Volts: 3.3}})
	if len(t1) != 1 || t1[0].Sensor != "b" || t1[0].High != nil || *t1[0].Critical != 90 || len(f1) != 2 || len(v1) != 1 || v1[0].Volts != 3.3 {
		t.Fatalf("%+v %+v %+v", t1, f1, v1)
	}
}
