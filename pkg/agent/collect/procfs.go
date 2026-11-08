package collect

// Parsers for Linux /proc and /sys. They take the file contents (or a root directory) so the tests can run them
// on fixtures on any OS; linux.go wires them to the real files.

import (
	"bufio"
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// CPUTimes are the aggregate jiffies of the `cpu` line of /proc/stat.
type CPUTimes struct {
	Total, Idle uint64
}

// ParseProcStat returns the aggregate CPU times and the boot time (Unix seconds) from /proc/stat.
func ParseProcStat(data []byte) (CPUTimes, int64, error) {
	var t CPUTimes
	var btime int64
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "cpu":
			// user nice system idle iowait irq softirq steal [guest guest_nice: already counted in user/nice]
			for i := 1; i < len(f) && i <= 8; i++ {
				v, err := strconv.ParseUint(f[i], 10, 64)
				if err != nil {
					return t, 0, errors.New("bad /proc/stat cpu line")
				}
				t.Total += v
				if i == 4 || i == 5 { // idle + iowait
					t.Idle += v
				}
			}
			found = true
		case "btime":
			if len(f) > 1 {
				btime, _ = strconv.ParseInt(f[1], 10, 64)
			}
		}
	}
	if !found {
		return t, btime, errors.New("no cpu line in /proc/stat")
	}
	return t, btime, nil
}

// BusyPercent is the share of non-idle time between two samples (nil if no time passed or counters reset).
func BusyPercent(prev, cur CPUTimes) *float64 {
	if cur.Total <= prev.Total || cur.Idle < prev.Idle {
		return nil
	}
	dt := float64(cur.Total - prev.Total)
	busy := dt - float64(cur.Idle-prev.Idle)
	v := Round(math.Max(0, math.Min(100, busy/dt*100)), 1)
	return &v
}

// ParseMeminfo returns MemTotal and MemAvailable in bytes.
func ParseMeminfo(data []byte) (total, available int64, err error) {
	got := 0
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, perr := strconv.ParseInt(f[0], 10, 64)
		if perr != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			n *= 1024
		}
		switch k {
		case "MemTotal":
			total = n
			got++
		case "MemAvailable":
			available = n
			got++
		}
	}
	if got < 2 || total <= 0 {
		return 0, 0, errors.New("bad /proc/meminfo")
	}
	return total, available, nil
}

// ParseNetDev sums received / sent bytes of the interfaces include accepts (/proc/net/dev).
func ParseNetDev(data []byte, include func(name string) bool) (rx, tx int64) {
	for _, line := range strings.Split(string(data), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if len(f) < 9 || !include(name) {
			continue
		}
		r, err1 := strconv.ParseInt(f[0], 10, 64)
		t, err2 := strconv.ParseInt(f[8], 10, 64)
		if err1 == nil && err2 == nil {
			rx += r
			tx += t
		}
	}
	return rx, tx
}

// NetFilter picks the interfaces to count: the physical ones (with a device link in sysfs), so traffic is not
// counted twice through bridges, VPN tunnels and container veths. Without any physical interface (a container),
// every interface except loopback counts.
func NetFilter(sysRoot string, names []string) func(string) bool {
	phys := map[string]bool{}
	for _, n := range names {
		if n == "lo" {
			continue
		}
		if _, err := os.Stat(filepath.Join(sysRoot, "class", "net", n, "device")); err == nil {
			phys[n] = true
		}
	}
	if len(phys) == 0 {
		return func(n string) bool { return n != "lo" }
	}
	return func(n string) bool { return phys[n] }
}

// NetDevNames lists the interface names of /proc/net/dev.
func NetDevNames(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if name, _, ok := strings.Cut(line, ":"); ok && !strings.Contains(name, "|") {
			out = append(out, strings.TrimSpace(name))
		}
	}
	return out
}

// ParseUptime returns whole seconds since boot from /proc/uptime.
func ParseUptime(data []byte) *int64 {
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return nil
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return nil
	}
	s := int64(v)
	return &s
}

// ParseLoadavg returns the 1, 5 and 15 minute load averages from /proc/loadavg.
func ParseLoadavg(data []byte) []float64 {
	f := strings.Fields(string(data))
	if len(f) < 3 {
		return nil
	}
	out := make([]float64, 0, 3)
	for _, s := range f[:3] {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil
		}
		out = append(out, Round(v, 2))
	}
	return out
}

func readTrim(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func readNum(path string) (float64, bool) {
	s, ok := readTrim(path)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil
}

// sensorIndexes returns the N of every <prefix>N_input file in dir, sorted.
func sensorIndexes(dir, prefix string) []int {
	ents, _ := os.ReadDir(dir)
	var out []int
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, "_input") {
			continue
		}
		if i, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(n, prefix), "_input")); err == nil {
			out = append(out, i)
		}
	}
	sort.Ints(out)
	return out
}

// ReadHwmon reads every hwmon chip under sysRoot (/sys): temperatures (milli-degrees), fans (RPM) and voltages
// (millivolts). Unreadable files are skipped. Fans reading 0 RPM are skipped unless the chip labels them (an
// unlabelled 0 RPM header is almost always an empty header).
func ReadHwmon(sysRoot string) ([]Temp, []Fan, []Voltage) {
	temps, fans, volts := []Temp{}, []Fan{}, []Voltage{}
	chips, _ := filepath.Glob(filepath.Join(sysRoot, "class", "hwmon", "hwmon*"))
	sort.Slice(chips, func(i, j int) bool { return hwmonNum(chips[i]) < hwmonNum(chips[j]) })
	for _, chip := range chips {
		dir := chip
		name, ok := readTrim(filepath.Join(dir, "name"))
		if !ok { // old kernels keep the attributes under device/
			dir = filepath.Join(chip, "device")
			if name, ok = readTrim(filepath.Join(dir, "name")); !ok {
				continue
			}
		}
		label := func(kind string, i int) (string, bool) {
			return readTrim(filepath.Join(dir, kind+strconv.Itoa(i)+"_label"))
		}
		for _, i := range sensorIndexes(dir, "temp") {
			v, ok := readNum(filepath.Join(dir, "temp"+strconv.Itoa(i)+"_input"))
			if !ok {
				continue
			}
			t := Temp{Sensor: name, Current: Round(v/1000, 1)}
			if l, ok := label("temp", i); ok && l != "" {
				t.Label = &l
			}
			if h, ok := readNum(filepath.Join(dir, "temp"+strconv.Itoa(i)+"_max")); ok && h > 0 && h < 200000 {
				t.High = P(Round(h/1000, 1))
			}
			if c, ok := readNum(filepath.Join(dir, "temp"+strconv.Itoa(i)+"_crit")); ok && c > 0 && c < 200000 {
				t.Critical = P(Round(c/1000, 1))
			}
			temps = append(temps, t)
		}
		for _, i := range sensorIndexes(dir, "fan") {
			v, ok := readNum(filepath.Join(dir, "fan"+strconv.Itoa(i)+"_input"))
			if !ok {
				continue
			}
			l, labelled := label("fan", i)
			if v == 0 && !labelled {
				continue
			}
			if !labelled || l == "" {
				l = "fan" + strconv.Itoa(i)
			}
			fans = append(fans, Fan{Name: name + " " + l, RPM: v})
		}
		for _, i := range sensorIndexes(dir, "in") {
			v, ok := readNum(filepath.Join(dir, "in"+strconv.Itoa(i)+"_input"))
			if !ok {
				continue
			}
			l, labelled := label("in", i)
			if !labelled || l == "" {
				l = "in" + strconv.Itoa(i)
			}
			volts = append(volts, Voltage{Name: name + " " + l, Volts: Round(v/1000, 3)})
		}
	}
	return temps, fans, volts
}

func hwmonNum(path string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(filepath.Base(path), "hwmon"))
	return n
}

// RAPLZone is one top-level powercap zone (a CPU package, or psys) with its energy counter.
type RAPLZone struct {
	Name     string // package-0, psys ...
	EnergyUJ uint64
	MaxUJ    uint64
}

// ReadRAPL reads the top-level powercap zones (intel-rapl:N, also used for AMD). energy_uj is root-only on most
// kernels (CVE-2020-8694); unreadable zones are skipped, so without access there is simply no CPU power.
func ReadRAPL(sysRoot string) []RAPLZone {
	dirs, _ := filepath.Glob(filepath.Join(sysRoot, "class", "powercap", "intel-rapl:*"))
	sort.Strings(dirs)
	var out []RAPLZone
	for _, d := range dirs {
		if strings.Count(filepath.Base(d), ":") != 1 { // sub-zones (core, uncore, dram) are inside packages
			continue
		}
		name, ok := readTrim(filepath.Join(d, "name"))
		if !ok {
			continue
		}
		e, ok1 := readTrim(filepath.Join(d, "energy_uj"))
		m, ok2 := readTrim(filepath.Join(d, "max_energy_range_uj"))
		if !ok1 || !ok2 {
			continue
		}
		ev, err1 := strconv.ParseUint(e, 10, 64)
		mv, err2 := strconv.ParseUint(m, 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, RAPLZone{Name: name, EnergyUJ: ev, MaxUJ: mv})
	}
	return out
}

// RAPLWatts converts two energy readings dt seconds apart to watts, handling one counter wrap.
func RAPLWatts(prev, cur RAPLZone, dt float64) (float64, bool) {
	if dt <= 0 {
		return 0, false
	}
	var d uint64
	switch {
	case cur.EnergyUJ >= prev.EnergyUJ:
		d = cur.EnergyUJ - prev.EnergyUJ
	case cur.MaxUJ > 0 && prev.EnergyUJ <= cur.MaxUJ:
		d = cur.MaxUJ - prev.EnergyUJ + cur.EnergyUJ
	default:
		return 0, false
	}
	return Round(float64(d)/1e6/dt, 1), true
}

// Battery is the state of the main battery (laptops).
type Battery struct {
	Watts *float64
	State string // charging | discharging | full | not charging | unknown
}

// ReadBattery reads the first system battery under /sys/class/power_supply (scope "Device" batteries, such as a
// mouse, are ignored). ok is false without a battery.
func ReadBattery(sysRoot string) (Battery, bool) {
	dirs, _ := filepath.Glob(filepath.Join(sysRoot, "class", "power_supply", "*"))
	sort.Strings(dirs)
	for _, d := range dirs {
		if t, _ := readTrim(filepath.Join(d, "type")); t != "Battery" {
			continue
		}
		if s, _ := readTrim(filepath.Join(d, "scope")); s == "Device" {
			continue
		}
		b := Battery{State: "unknown"}
		if s, ok := readTrim(filepath.Join(d, "status")); ok && s != "" {
			b.State = strings.ToLower(s)
		}
		if p, ok := readNum(filepath.Join(d, "power_now")); ok {
			b.Watts = P(Round(math.Abs(p)/1e6, 1))
		} else if c, ok := readNum(filepath.Join(d, "current_now")); ok {
			if v, ok := readNum(filepath.Join(d, "voltage_now")); ok {
				b.Watts = P(Round(math.Abs(c*v)/1e12, 1))
			}
		}
		return b, true
	}
	return Battery{}, false
}

func optStr(path string) *string {
	if s, ok := readTrim(path); ok && s != "" {
		return &s
	}
	return nil
}

// ReadDMI reads the SMBIOS strings from /sys/class/dmi/id (or, on boards without SMBIOS such as a Raspberry
// Pi, the device-tree model) plus the CPU model.
func ReadDMI(sysRoot, procRoot string, cpuinfo []byte) *Hardware {
	id := filepath.Join(sysRoot, "class", "dmi", "id")
	h := &Hardware{SystemVendor: optStr(filepath.Join(id, "sys_vendor")), SystemModel: optStr(filepath.Join(id, "product_name")),
		BoardVendor: optStr(filepath.Join(id, "board_vendor")), BoardModel: optStr(filepath.Join(id, "board_name")),
		BIOSVersion: optStr(filepath.Join(id, "bios_version"))}
	if h.SystemModel == nil && h.BoardModel == nil {
		if m := optStr(filepath.Join(procRoot, "device-tree", "model")); m != nil {
			s := strings.TrimRight(*m, "\x00")
			h.SystemModel = &s
		}
	}
	if m, _ := ParseCPUInfo(cpuinfo); m != "" {
		h.CPUModel = &m
	}
	if *h == (Hardware{}) {
		return nil
	}
	return h
}

// ParseCPUInfo returns the CPU model name and the number of physical cores (0 if unknown) from /proc/cpuinfo.
func ParseCPUInfo(data []byte) (string, int) {
	model := ""
	cores := map[string]bool{}
	phys := ""
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "model name", "Processor", "cpu model":
			if model == "" {
				model = v
			}
		case "physical id":
			phys = v
		case "core id":
			cores[phys+"/"+v] = true
		}
	}
	return model, len(cores)
}

// ParseOSRelease returns PRETTY_NAME (or NAME VERSION) from os-release.
func ParseOSRelease(data []byte) string {
	vals := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `'"`)
		}
		vals[k] = v
	}
	if p := vals["PRETTY_NAME"]; p != "" {
		return p
	}
	return strings.TrimSpace(vals["NAME"] + " " + vals["VERSION"])
}

// Mount is one filesystem from /proc/self/mountinfo.
type Mount struct {
	Point, FSType, Source, Dev string
}

// localFS are the filesystems reported as disks. Network filesystems are left out on purpose: statfs on a
// dead NFS/CIFS server hangs.
var localFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "fuseblk": true, "bcachefs": true,
	"jfs": true, "reiserfs": true}

var skipDirs = []string{"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containers",
	"/var/lib/kubelet", "/var/snap"}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ParseMountinfo returns the local filesystems worth showing, one per device (bind mounts, btrfs subvolumes and
// the extra mounts systemd sandboxing adds appear once, under their shortest path) and one per ZFS pool.
func ParseMountinfo(data []byte) []Mount {
	best := map[string]Mount{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		f, g := strings.Fields(pre), strings.Fields(post)
		if len(f) < 5 || len(g) < 2 {
			continue
		}
		m := Mount{Point: unescapeMount(f[4]), FSType: g[0], Source: g[1], Dev: f[2]}
		if !localFS[m.FSType] {
			continue
		}
		skip := false
		for _, d := range skipDirs {
			if m.Point == d || strings.HasPrefix(m.Point, d+"/") {
				skip = true
			}
		}
		if skip && !strings.HasPrefix(m.Point, "/run/media/") {
			continue
		}
		key := m.Dev
		if m.FSType == "zfs" { // datasets of one pool share its free space: show the pool once
			pool, _, _ := strings.Cut(m.Source, "/")
			key = "zfs:" + pool
		}
		if prev, ok := best[key]; !ok || len(m.Point) < len(prev.Point) {
			best[key] = m
		}
	}
	out := make([]Mount, 0, len(best))
	for _, m := range best {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Point < out[j].Point })
	return out
}

// ProcStat is what fairy-agent needs from /proc/<pid>/stat (times in clock ticks, RSS in pages).
type ProcStat struct {
	Comm      string
	State     byte
	UTime     uint64
	STime     uint64
	StartTime uint64
	RSSPages  int64
}

// ParseProcPIDStat parses /proc/<pid>/stat. The command name may contain spaces and parentheses, so it is cut
// at the last ')'.
func ParseProcPIDStat(data []byte) (ProcStat, error) {
	s := string(data)
	open, end := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || end < open || end+2 > len(s) {
		return ProcStat{}, errors.New("bad stat")
	}
	f := strings.Fields(s[end+2:])
	if len(f) < 22 {
		return ProcStat{}, errors.New("bad stat")
	}
	p := ProcStat{Comm: s[open+1 : end], State: f[0][0]}
	var err error
	if p.UTime, err = strconv.ParseUint(f[11], 10, 64); err != nil {
		return p, err
	}
	if p.STime, err = strconv.ParseUint(f[12], 10, 64); err != nil {
		return p, err
	}
	if p.StartTime, err = strconv.ParseUint(f[19], 10, 64); err != nil {
		return p, err
	}
	if p.RSSPages, err = strconv.ParseInt(f[21], 10, 64); err != nil {
		return p, err
	}
	return p, nil
}

// ProcStates maps /proc state letters to the words the panel shows (as psutil names them).
var ProcStates = map[byte]string{'R': "running", 'S': "sleeping", 'D': "disk-sleep", 'Z': "zombie", 'T': "stopped",
	't': "tracing-stop", 'X': "dead", 'x': "dead", 'I': "idle", 'P': "parked", 'W': "waking", 'K': "wake-kill"}

// ParseStatusUID returns the real uid from /proc/<pid>/status.
func ParseStatusUID(data []byte) (int, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line[4:])
			if len(f) > 0 {
				if v, err := strconv.Atoi(f[0]); err == nil {
					return v, true
				}
			}
		}
	}
	return 0, false
}

// ParsePasswd maps uid -> user name from /etc/passwd.
func ParsePasswd(data []byte) map[int]string {
	out := map[int]string{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		if uid, err := strconv.Atoi(f[2]); err == nil {
			if _, dup := out[uid]; !dup {
				out[uid] = f[0]
			}
		}
	}
	return out
}

// CmdlineString joins /proc/<pid>/cmdline arguments with spaces ("" for kernel threads).
func CmdlineString(data []byte) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " "))
}

// ProcName is the process name: comm, or the program's file name when comm was cut at 15 characters.
func ProcName(comm string, cmdline []byte) string {
	if len(comm) < 15 || len(cmdline) == 0 {
		return comm
	}
	arg0, _, _ := strings.Cut(string(cmdline), "\x00")
	base := filepath.Base(arg0)
	if strings.HasPrefix(base, comm) {
		return base
	}
	return comm
}

// Round rounds v to the given number of decimal places.
func Round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

// ProxmoxPretty returns "Proxmox VE 9.0" from dpkg's status file (the pve-manager package), "" if absent.
// A Proxmox node's os-release only says Debian.
func ProxmoxPretty(dpkgStatus []byte) string {
	inPkg := false
	for _, line := range strings.Split(string(dpkgStatus), "\n") {
		switch {
		case line == "":
			inPkg = false
		case line == "Package: pve-manager":
			inPkg = true
		case inPkg && strings.HasPrefix(line, "Version: "):
			v := strings.TrimPrefix(line, "Version: ")
			parts := strings.SplitN(v, ".", 3)
			if len(parts) >= 2 {
				v = parts[0] + "." + parts[1]
			}
			return "Proxmox VE " + v
		}
	}
	return ""
}
