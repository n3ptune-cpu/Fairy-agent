//go:build linux

package collect

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/redact"
)

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat times: 100 on every Linux architecture Fairy builds for.
const clockTicks = 100

// Limits on what one process's command line may cost the agent. A command line can be megabytes long (any
// local user can start such processes), and the agent runs inside a memory limit: only the first
// maxCmdlineRead bytes of /proc/<pid>/cmdline are read, and what is kept per process is the redacted text cut
// to maxCmdlineLen characters.
const (
	maxCmdlineRead = 4096
	maxCmdlineLen  = 300
)

// readCmdline reads at most len(buf) bytes of a /proc/<pid>/cmdline file into buf. cut reports that the
// command line is longer than that (the last, incomplete character is then left off).
func readCmdline(path string, buf []byte) (data []byte, cut bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	n, err := io.ReadFull(f, buf)
	if err != nil { // io.EOF (empty: a kernel thread) or io.ErrUnexpectedEOF (shorter than buf): all of it
		return buf[:n], false
	}
	var more [1]byte
	if m, _ := f.Read(more[:]); m == 0 { // exactly len(buf) bytes long
		return buf[:n], false
	}
	for i := n - 1; i >= 0 && i >= n-utf8.UTFMax; i-- {
		if utf8.RuneStart(buf[i]) {
			if !utf8.FullRune(buf[i:n]) {
				n = i
			}
			break
		}
	}
	return buf[:n], true
}

// cmdlineArgs splits /proc/<pid>/cmdline (arguments separated by NUL) into the arguments.
func cmdlineArgs(data []byte) []string {
	s := strings.TrimRight(string(data), "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

type procSample struct {
	ticks uint64
	start uint64
}

// Linux reads /proc and /sys. Everything it reads is world-readable except the RAPL energy counters (root-only
// on most kernels; see AGENT.md for the one-line tmpfiles rule that shares them with the agent's group).
type Linux struct {
	proc, sys, etc string
	static         Static

	mu         sync.Mutex
	prevCPU    CPUTimes
	prevCPUAt  time.Time
	lastPct    *float64
	btime      int64
	diskCache  []Disk
	diskAt     time.Time
	netFilter  func(string) bool
	netAt      time.Time
	sensors    [3]any
	sensorsAt  time.Time
	prevRAPL   map[string]RAPLZone
	prevRAPLAt time.Time
	lastRAPL   map[string]float64
	procPrev   map[int]procSample
	trackProcs int // maxTrackedProcs unless a test sets it
	procPrevAt time.Time
	users      map[int]string
	usersAt    time.Time
}

// NewSystem returns the collector for this machine.
func NewSystem() Collector {
	l := &Linux{proc: "/proc", sys: "/sys", etc: "/etc", prevRAPL: map[string]RAPLZone{}, lastRAPL: map[string]float64{}}
	l.static = l.readStatic()
	if b, err := os.ReadFile(filepath.Join(l.proc, "stat")); err == nil {
		l.prevCPU, l.btime, _ = ParseProcStat(b)
		l.prevCPUAt = time.Now()
	}
	l.readRAPL(time.Now())
	return l
}

func (l *Linux) readStatic() Static {
	s := Static{Platform: Platform{System: "Linux", Pretty: "Linux"}}
	s.Hostname, _ = os.Hostname()
	for _, p := range []string{filepath.Join(l.etc, "os-release"), "/usr/lib/os-release"} {
		if b, err := os.ReadFile(p); err == nil {
			if pretty := ParseOSRelease(b); pretty != "" {
				s.Platform.Pretty = pretty
				break
			}
		}
	}
	if _, err := os.Stat("/usr/bin/pveversion"); err == nil { // a Proxmox node: its os-release says Debian
		if b, err := os.ReadFile("/var/lib/dpkg/status"); err == nil {
			if p := ProxmoxPretty(b); p != "" {
				s.Platform.Pretty = p
			}
		}
	}
	cpuinfo, _ := os.ReadFile(filepath.Join(l.proc, "cpuinfo"))
	if _, cores := ParseCPUInfo(cpuinfo); cores > 0 {
		s.Physical = &cores
	}
	s.Logical = onlineCPUs(l.sys)
	s.Hardware = ReadDMI(l.sys, l.proc, cpuinfo)
	return s
}

// onlineCPUs counts the CPUs in /sys/devices/system/cpu/online ("0-7,9").
func onlineCPUs(sys string) int {
	s, ok := readTrim(filepath.Join(sys, "devices", "system", "cpu", "online"))
	if n := CountCPUList(s); ok && n > 0 {
		return n
	}
	return numCPU()
}

// Static returns what was read at start.
func (l *Linux) Static() Static { return l.static }

// Sample reads the changing values.
func (l *Linux) Sample(context.Context) Sample {
	now := time.Now()
	var s Sample
	if b, err := os.ReadFile(filepath.Join(l.proc, "stat")); err == nil {
		if cur, bt, err := ParseProcStat(b); err == nil {
			l.mu.Lock()
			if now.Sub(l.prevCPUAt) >= 500*time.Millisecond || l.lastPct == nil {
				if p := BusyPercent(l.prevCPU, cur); p != nil {
					l.lastPct = p
				}
				l.prevCPU, l.prevCPUAt, l.btime = cur, now, bt
			}
			s.CPUPercent = l.lastPct
			l.mu.Unlock()
		}
	}
	if b, err := os.ReadFile(filepath.Join(l.proc, "meminfo")); err == nil {
		if t, a, err := ParseMeminfo(b); err == nil {
			s.Memory = Memory{Total: t, Used: max(0, t-a)}
		}
	}
	s.Disks = l.disks(now)
	if b, err := os.ReadFile(filepath.Join(l.proc, "net", "dev")); err == nil {
		l.mu.Lock()
		if l.netFilter == nil || now.Sub(l.netAt) > time.Minute {
			l.netFilter, l.netAt = NetFilter(l.sys, NetDevNames(b)), now
		}
		f := l.netFilter
		l.mu.Unlock()
		s.Net.BytesRecv, s.Net.BytesSent = ParseNetDev(b, f)
	}
	if b, err := os.ReadFile(filepath.Join(l.proc, "uptime")); err == nil {
		s.UptimeS = ParseUptime(b)
	}
	if b, err := os.ReadFile(filepath.Join(l.proc, "loadavg")); err == nil {
		s.LoadAvg = ParseLoadavg(b)
	}
	s.Temps, s.Fans, s.Voltages = l.hwmon(now)
	s.Power = l.power(now)
	s.Battery = ReadBatteryStatus(l.sys)
	cleanSample(&s)
	return s
}

// cleanSample leaves out of a sample what cannot be a reading: a value that is not a number, an infinity, or
// beyond devices.MaxMagnitude (the kernel's files are trusted, but a driver can write "nan", and sums and
// ratios of large numbers can overflow), a percentage outside 0-100, a negative time. One such value would make
// the whole /metrics answer impossible to write. The sensor lists are cleaned where they are read (hwmon).
func cleanSample(s *Sample) {
	s.CPUPercent = devices.NumIn(s.CPUPercent, 0, 100)
	if s.UptimeS != nil && *s.UptimeS < 0 {
		s.UptimeS = nil
	}
	for _, v := range s.LoadAvg {
		if !(v >= 0 && devices.Finite(v)) {
			s.LoadAvg = nil
			break
		}
	}
	s.Power.CPUPackageW, s.Power.GPUW = devices.Num(s.Power.CPUPackageW), devices.Num(s.Power.GPUW)
	s.Power.BatteryW, s.Power.BMCW = devices.Num(s.Power.BatteryW), devices.Num(s.Power.BMCW)
	if b := s.Battery; b != nil {
		b.Percent, b.HealthPct = devices.NumIn(b.Percent, 0, 100), devices.NumIn(b.HealthPct, 0, devices.MaxMagnitude)
		b.PowerW = devices.Num(b.PowerW)
		if b.TimeRemainingS != nil && *b.TimeRemainingS < 0 {
			b.TimeRemainingS = nil
		}
	}
}

// cleanSensors returns the sensor lists without the entries whose value is not a possible number.
func cleanSensors(temps []Temp, fans []Fan, volts []Voltage) ([]Temp, []Fan, []Voltage) {
	t, f, v := make([]Temp, 0, len(temps)), make([]Fan, 0, len(fans)), make([]Voltage, 0, len(volts))
	for _, x := range temps {
		if devices.Finite(x.Current) {
			x.High, x.Critical = devices.Num(x.High), devices.Num(x.Critical)
			t = append(t, x)
		}
	}
	for _, x := range fans {
		if devices.Finite(x.RPM) && x.RPM >= 0 {
			f = append(f, x)
		}
	}
	for _, x := range volts {
		if devices.Finite(x.Volts) {
			v = append(v, x)
		}
	}
	return t, f, v
}

func (l *Linux) hwmon(now time.Time) ([]Temp, []Fan, []Voltage) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sensors[0] == nil || now.Sub(l.sensorsAt) >= 2*time.Second {
		t, f, v := cleanSensors(ReadHwmon(l.sys))
		l.sensors, l.sensorsAt = [3]any{t, f, v}, now
	}
	return l.sensors[0].([]Temp), l.sensors[1].([]Fan), l.sensors[2].([]Voltage)
}

func (l *Linux) disks(now time.Time) []Disk {
	l.mu.Lock()
	if l.diskCache != nil && now.Sub(l.diskAt) < 10*time.Second {
		d := l.diskCache
		l.mu.Unlock()
		return d
	}
	l.mu.Unlock()
	disks := []Disk{}
	b, err := os.ReadFile(filepath.Join(l.proc, "self", "mountinfo"))
	if err == nil {
		for _, m := range ParseMountinfo(b) {
			var st syscall.Statfs_t
			if syscall.Statfs(m.Point, &st) != nil || st.Blocks == 0 {
				continue
			}
			bs := int64(st.Frsize)
			if bs == 0 {
				bs = int64(st.Bsize)
			}
			total := int64(st.Blocks) * bs
			disks = append(disks, Disk{Mount: m.Point, FSType: m.FSType, Total: total, Used: total - int64(st.Bfree)*bs})
		}
	}
	l.mu.Lock()
	l.diskCache, l.diskAt = disks, now
	l.mu.Unlock()
	return disks
}

// readRAPL updates the per-package watts (needs two readings at least half a second apart).
func (l *Linux) readRAPL(now time.Time) {
	zones := ReadRAPL(l.sys)
	dt := now.Sub(l.prevRAPLAt).Seconds()
	if dt < 0.5 && len(l.prevRAPL) > 0 {
		return
	}
	watts := map[string]float64{}
	for _, z := range zones {
		if p, ok := l.prevRAPL[z.Name]; ok {
			if w, ok := RAPLWatts(p, z, dt); ok {
				watts[z.Name] = w
			}
		}
	}
	l.prevRAPL = map[string]RAPLZone{}
	for _, z := range zones {
		l.prevRAPL[z.Name] = z
	}
	l.prevRAPLAt, l.lastRAPL = now, watts
}

func (l *Linux) power(now time.Time) Power {
	l.mu.Lock()
	l.readRAPL(now)
	watts := l.lastRAPL
	l.mu.Unlock()
	p := Power{Sensors: []PowerSensor{}, Source: []string{}}
	var pkg float64
	names := make([]string, 0, len(watts))
	for n := range watts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if !devices.Finite(watts[n]) {
			continue
		}
		p.Sensors = append(p.Sensors, PowerSensor{Name: "rapl " + n, Watts: watts[n]})
		if n != "psys" {
			pkg += watts[n]
			p.CPUPackageW = P(Round(pkg, 1)) // the sum is checked in cleanSample
		}
	}
	if len(p.Sensors) > 0 {
		p.Source = append(p.Source, "rapl")
	}
	if b, ok := ReadBattery(l.sys); ok {
		p.BatteryW, p.BatteryState = b.Watts, &b.State
		p.Source = append(p.Source, "battery")
	}
	return p
}

func (l *Linux) usernames(now time.Time) map[int]string {
	if l.users == nil || now.Sub(l.usersAt) > 5*time.Minute {
		b, _ := os.ReadFile(filepath.Join(l.etc, "passwd"))
		l.users, l.usersAt = ParsePasswd(b), now
	}
	return l.users
}

// What a process listing may cost the agent in memory, however many processes there are (a local user can
// start tens of thousands, and the agent's unit has a hard limit of 64 MiB).
const (
	// procDirBatch is how many names of /proc are read at a time: the directory is never held as a whole.
	procDirBatch = 512
	// maxTrackedProcs is how many processes' CPU times are kept from one listing to the next (two numbers
	// each). A process beyond that is listed with 0 % CPU.
	maxTrackedProcs = 32768
	// maxKeptProcs is how many rows are kept for ProcOptions.Keep.
	maxKeptProcs = 200
	// defaultProcTop is ProcOptions.Top for a caller that does not say: a listing is never unbounded.
	defaultProcTop = 200
)

// procRow is what one scan keeps of a process before it is known whether the process will be listed: a few
// numbers and the kernel's short name, never the command line.
type procRow struct {
	pid    int
	ticks  uint64
	start  uint64
	rss    int64 // pages
	cpu    float64
	hasCPU bool
	state  byte
	comm   string
}

// procTop keeps the n highest rows of one order while the scan runs: it holds at most 2n rows at any time.
type procTop struct {
	n    int
	less func(a, b *procRow) bool // a comes before b
	rows []procRow
}

func (t *procTop) add(r procRow) {
	if t.n <= 0 {
		return
	}
	t.rows = append(t.rows, r)
	if len(t.rows) >= 2*t.n {
		t.cut()
	}
}

func (t *procTop) cut() {
	sort.Slice(t.rows, func(i, j int) bool { return t.less(&t.rows[i], &t.rows[j]) })
	if len(t.rows) > t.n {
		t.rows = t.rows[:t.n]
	}
}

// readSmall reads a small /proc file into buf (what does not fit is left off).
func readSmall(path string, buf []byte) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:n], nil
}

// scanProcs reads /proc/<pid>/stat of every process and calls each with its row. It returns how many
// processes there are. Nothing is kept here.
func (l *Linux) scanProcs(each func(procRow)) (total int) {
	d, err := os.Open(l.proc)
	if err != nil {
		return 0
	}
	defer d.Close()
	buf := make([]byte, 2048) // one buffer for every process of this scan; a stat line is some 300 bytes
	for {
		names, err := d.Readdirnames(procDirBatch)
		for _, name := range names {
			pid, perr := strconv.Atoi(name)
			if perr != nil {
				continue
			}
			total++
			b, rerr := readSmall(filepath.Join(l.proc, name, "stat"), buf)
			if rerr != nil {
				continue // exited, or hidden from us: skip silently
			}
			st, serr := ParseProcPIDStat(b)
			if serr != nil {
				continue
			}
			each(procRow{pid: pid, ticks: st.UTime + st.STime, start: st.StartTime, rss: st.RSSPages, state: st.State,
				comm: strings.Clone(st.Comm)})
		}
		if err != nil || len(names) == 0 {
			return total
		}
	}
}

// describe reads the rest of one listed process: its name, its command line when o.Cmdline is on, and its
// user. With o.Cmdline off the command line is not even opened: the name then comes from the kernel's name of
// the process and from the link to its program file (ExeProcName), so that nothing a program wrote into its
// title can be in it.
func (l *Linux) describe(r procRow, o ProcOptions, users map[int]string, btime, page int64, cmdBuf, statusBuf []byte) Process {
	dir := filepath.Join(l.proc, strconv.Itoa(r.pid))
	var (
		cmd  []byte
		cut  bool
		name string
	)
	if o.Cmdline {
		cmd, cut = readCmdline(filepath.Join(dir, "cmdline"), cmdBuf)
		name = ProcName(r.comm, cmd)
	} else {
		exe := ""
		if len(r.comm) >= 15 { // only a name that may have been cut is looked up
			exe, _ = os.Readlink(filepath.Join(dir, "exe"))
		}
		name = ExeProcName(r.comm, exe)
	}
	p := Process{PID: r.pid, Name: &name, RSS: P(r.rss * page),
		CreateTime: P(Round(float64(btime)+float64(r.start)/clockTicks, 2))}
	if r.hasCPU {
		p.CPUPercent = P(r.cpu)
	}
	if w, ok := ProcStates[r.state]; ok {
		p.Status = &w
	}
	if sb, err := readSmall(filepath.Join(dir, "status"), statusBuf); err == nil {
		if uid, ok := ParseStatusUID(sb); ok {
			u, known := users[uid]
			if !known {
				u = strconv.Itoa(uid)
			}
			p.Username = &u
		}
	}
	if o.Cmdline {
		// Secrets are hidden here, argument by argument, and the text is cut to its final length here:
		// a full command line is never kept.
		if args := cmdlineArgs(cmd); len(args) > 0 {
			if cut {
				args = append(args, "…")
			}
			if c := strings.TrimSpace(redact.Args(args, maxCmdlineLen)); c != "" {
				p.Cmdline = &c
			}
		}
	}
	if o.MemTotal > 0 {
		p.MemPercent = P(Round(float64(*p.RSS)/float64(o.MemTotal)*100, 2))
	}
	return p
}

// Processes lists the processes with CPU use since the previous listing (or over o.Interval when there is no
// recent one): the rows a caller that sorts and cuts to o.Top can need (see ProcOptions; defaultProcTop when
// the caller does not say). With no more than Top processes that is all of them.
//
// It works in two steps so that its memory does not grow with the number of processes (review N8: 20000
// processes with long command lines held 43 MiB after one listing). The scan reads one small file per process
// and keeps a few numbers of the rows that may be listed; only for those are the command line and the user
// read afterwards. That is at most 3 x Top + maxKeptProcs rows, each with at most maxCmdlineLen characters of
// command line.
func (l *Linux) Processes(ctx context.Context, o ProcOptions) ([]Process, int, error) {
	l.mu.Lock()
	prev, prevAt := l.procPrev, l.procPrevAt
	l.mu.Unlock()
	track := l.trackProcs
	if track <= 0 {
		track = maxTrackedProcs
	}
	if prev == nil || time.Since(prevAt) > 30*time.Second {
		prev, prevAt = map[int]procSample{}, time.Now()
		l.scanProcs(func(r procRow) {
			if len(prev) < track {
				prev[r.pid] = procSample{r.ticks, r.start}
			}
		})
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(o.Interval):
		}
	}
	top := o.Top
	if top <= 0 {
		top = defaultProcTop
	}
	now := time.Now()
	dt := now.Sub(prevAt).Seconds()
	cur := make(map[int]procSample, min(len(prev)+64, track))
	// the orders a caller sorts by (server.go SortProcesses): highest first, unknown last, then by pid
	byCPU := &procTop{n: top, less: func(a, b *procRow) bool {
		if a.hasCPU != b.hasCPU {
			return a.hasCPU
		}
		if a.cpu != b.cpu {
			return a.cpu > b.cpu
		}
		return a.pid < b.pid
	}}
	byMem := &procTop{n: top, less: func(a, b *procRow) bool {
		if a.rss != b.rss {
			return a.rss > b.rss
		}
		return a.pid < b.pid
	}}
	byPID := &procTop{n: top, less: func(a, b *procRow) bool { return a.pid < b.pid }}
	var kept []procRow
	total := l.scanProcs(func(r procRow) {
		if len(cur) < track {
			cur[r.pid] = procSample{r.ticks, r.start}
		}
		if dt > 0 {
			r.hasCPU = true
			if pr, ok := prev[r.pid]; ok && pr.start == r.start && r.ticks >= pr.ticks {
				r.cpu = Round(float64(r.ticks-pr.ticks)/clockTicks/dt*100, 1)
			}
		}
		byCPU.add(r)
		byMem.add(r)
		byPID.add(r)
		if o.Keep != nil && len(kept) < maxKeptProcs && o.Keep(r.pid) {
			kept = append(kept, r)
		}
	})
	l.mu.Lock()
	l.procPrev, l.procPrevAt = cur, now
	users := l.usernames(now)
	btime := l.btime
	l.mu.Unlock()

	var rows []procRow
	seen := make(map[int]bool, 3*top+len(kept))
	for _, t := range []*procTop{byCPU, byMem, byPID} {
		t.cut()
		for _, r := range t.rows {
			if !seen[r.pid] {
				seen[r.pid] = true
				rows = append(rows, r)
			}
		}
	}
	for _, r := range kept {
		if !seen[r.pid] {
			seen[r.pid] = true
			rows = append(rows, r)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].pid < rows[j].pid })
	page := int64(os.Getpagesize())
	cmdBuf := make([]byte, maxCmdlineRead) // one buffer for every process of this listing
	statusBuf := make([]byte, 2048)        // "Uid:" is in the first lines of /proc/<pid>/status
	out := make([]Process, 0, len(rows))
	for _, r := range rows {
		out = append(out, l.describe(r, o, users, btime, page, cmdBuf, statusBuf))
	}
	return out, total, nil
}
