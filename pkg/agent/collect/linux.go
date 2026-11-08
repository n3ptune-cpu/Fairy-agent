//go:build linux

package collect

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat times: 100 on every Linux architecture Fairy builds for.
const clockTicks = 100

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
	return s
}

func (l *Linux) hwmon(now time.Time) ([]Temp, []Fan, []Voltage) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sensors[0] == nil || now.Sub(l.sensorsAt) >= 2*time.Second {
		t, f, v := ReadHwmon(l.sys)
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
		p.Sensors = append(p.Sensors, PowerSensor{Name: "rapl " + n, Watts: watts[n]})
		if n != "psys" {
			pkg += watts[n]
			p.CPUPackageW = P(Round(pkg, 1))
		}
	}
	if len(names) > 0 {
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

type procRow struct {
	p     Process
	ticks uint64
	start uint64
}

func (l *Linux) scanProcs(now time.Time, o ProcOptions) ([]procRow, int) {
	ents, _ := os.ReadDir(l.proc)
	l.mu.Lock()
	users := l.usernames(now)
	btime := l.btime
	l.mu.Unlock()
	page := int64(os.Getpagesize())
	var rows []procRow
	total := 0
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		total++
		dir := filepath.Join(l.proc, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			continue // exited, or hidden from us: skip silently
		}
		st, err := ParseProcPIDStat(b)
		if err != nil {
			continue
		}
		cmd, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
		name := ProcName(st.Comm, cmd)
		p := Process{PID: pid, Name: &name, RSS: P(st.RSSPages * page),
			CreateTime: P(Round(float64(btime)+float64(st.StartTime)/clockTicks, 2))}
		if w, ok := ProcStates[st.State]; ok {
			p.Status = &w
		}
		if sb, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
			if uid, ok := ParseStatusUID(sb); ok {
				u, known := users[uid]
				if !known {
					u = strconv.Itoa(uid)
				}
				p.Username = &u
			}
		}
		if o.Cmdline {
			if c := CmdlineString(cmd); c != "" {
				p.Cmdline = &c
			}
		}
		if o.MemTotal > 0 {
			p.MemPercent = P(Round(float64(*p.RSS)/float64(o.MemTotal)*100, 2))
		}
		rows = append(rows, procRow{p: p, ticks: st.UTime + st.STime, start: st.StartTime})
	}
	return rows, total
}

// Processes lists every process with CPU use since the previous listing (or over o.Interval when there is no
// recent one).
func (l *Linux) Processes(ctx context.Context, o ProcOptions) ([]Process, int, error) {
	l.mu.Lock()
	prev, prevAt := l.procPrev, l.procPrevAt
	l.mu.Unlock()
	if prev == nil || time.Since(prevAt) > 30*time.Second {
		rows, _ := l.scanProcs(time.Now(), ProcOptions{})
		prev, prevAt = map[int]procSample{}, time.Now()
		for _, r := range rows {
			prev[r.p.PID] = procSample{r.ticks, r.start}
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(o.Interval):
		}
	}
	now := time.Now()
	rows, total := l.scanProcs(now, o)
	dt := now.Sub(prevAt).Seconds()
	cur := map[int]procSample{}
	out := make([]Process, 0, len(rows))
	for _, r := range rows {
		cur[r.p.PID] = procSample{r.ticks, r.start}
		if pr, ok := prev[r.p.PID]; ok && pr.start == r.start && r.ticks >= pr.ticks && dt > 0 {
			r.p.CPUPercent = P(Round(float64(r.ticks-pr.ticks)/clockTicks/dt*100, 1))
		} else if dt > 0 {
			r.p.CPUPercent = P(0.0)
		}
		out = append(out, r.p)
	}
	l.mu.Lock()
	l.procPrev, l.procPrevAt = cur, now
	l.mu.Unlock()
	return out, total, nil
}
