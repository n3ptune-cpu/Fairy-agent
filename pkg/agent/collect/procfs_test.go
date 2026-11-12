package collect

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProcStatAndBusyPercent(t *testing.T) {
	a, bt, err := ParseProcStat([]byte("cpu  100 0 100 700 100 0 0 0 50 0\ncpu0 1 2 3 4\nbtime 1700000000\n"))
	if err != nil || bt != 1700000000 || a.Total != 1000 || a.Idle != 800 {
		t.Fatal(a, bt, err)
	}
	b, _, _ := ParseProcStat([]byte("cpu  200 0 200 1400 200 0 0 0 0 0\n"))
	if p := BusyPercent(a, b); p == nil || *p != 20 { // 200 busy of 1000
		t.Fatal(p)
	}
	if BusyPercent(b, a) != nil {
		t.Fatal("counter reset must give nil")
	}
	if _, _, err := ParseProcStat([]byte("intr 1\n")); err == nil {
		t.Fatal("missing cpu line")
	}
}

func TestMeminfoNetUptimeLoad(t *testing.T) {
	total, avail, err := ParseMeminfo([]byte("MemTotal:       16318704 kB\nMemFree: 1 kB\nMemAvailable:    8000000 kB\n"))
	if err != nil || total != 16318704*1024 || avail != 8000000*1024 {
		t.Fatal(total, avail, err)
	}
	if _, _, err := ParseMeminfo([]byte("MemTotal: 5 kB\n")); err == nil {
		t.Fatal("no MemAvailable")
	}
	dev := []byte(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999 10 0 0 0 0 0 0 9999 10 0 0 0 0 0 0
  eno1: 1000 10 0 0 0 0 0 0 500 10 0 0 0 0 0 0
vmbr0: 900 10 0 0 0 0 0 0 400 10 0 0 0 0 0 0
tailscale0: 50 1 0 0 0 0 0 0 60 1 0 0 0 0 0 0
`)
	names := NetDevNames(dev)
	if !reflect.DeepEqual(names, []string{"lo", "eno1", "vmbr0", "tailscale0"}) {
		t.Fatal(names)
	}
	sys := t.TempDir()
	write(t, sys, map[string]string{"class/net/eno1/device/uevent": ""})
	rx, tx := ParseNetDev(dev, NetFilter(sys, names))
	if rx != 1000 || tx != 500 {
		t.Fatal("physical only", rx, tx)
	}
	rx, tx = ParseNetDev(dev, NetFilter(t.TempDir(), names)) // container: no physical interface
	if rx != 1950 || tx != 960 {
		t.Fatal("all but lo", rx, tx)
	}
	if u := ParseUptime([]byte("12345.67 999.0\n")); u == nil || *u != 12345 {
		t.Fatal(u)
	}
	if l := ParseLoadavg([]byte("0.50 0.414 0.30 1/200 999\n")); !reflect.DeepEqual(l, []float64{0.5, 0.41, 0.3}) {
		t.Fatal(l)
	}
}

func TestHwmon(t *testing.T) {
	sys := t.TempDir()
	write(t, sys, map[string]string{
		"class/hwmon/hwmon0/name": "coretemp\n", "class/hwmon/hwmon0/temp1_input": "55000\n",
		"class/hwmon/hwmon0/temp1_label": "Package id 0\n", "class/hwmon/hwmon0/temp1_max": "90000\n",
		"class/hwmon/hwmon0/temp1_crit": "100000\n", "class/hwmon/hwmon0/temp2_input": "51500\n",
		"class/hwmon/hwmon2/name": "nct6798\n", "class/hwmon/hwmon2/fan1_input": "1200\n",
		"class/hwmon/hwmon2/fan2_input": "0\n", "class/hwmon/hwmon2/fan3_input": "0\n", "class/hwmon/hwmon2/fan3_label": "CPU_OPT\n",
		"class/hwmon/hwmon2/in0_input": "1032\n", "class/hwmon/hwmon2/in1_input": "12096\n", "class/hwmon/hwmon2/in1_label": "+12V\n",
		// old kernel layout: attributes under device/
		"class/hwmon/hwmon10/device/name": "acpitz\n", "class/hwmon/hwmon10/device/temp1_input": "27800\n",
	})
	temps, fans, volts := ReadHwmon(sys)
	if len(temps) != 3 || temps[0].Sensor != "coretemp" || *temps[0].Label != "Package id 0" || temps[0].Current != 55 ||
		*temps[0].High != 90 || *temps[0].Critical != 100 || temps[1].Label != nil || temps[1].Current != 51.5 ||
		temps[2].Sensor != "acpitz" || temps[2].Current != 27.8 {
		t.Fatalf("%+v", temps)
	}
	// unlabelled 0 RPM header skipped, labelled one kept
	if !reflect.DeepEqual(fans, []Fan{{"nct6798 fan1", 1200}, {"nct6798 CPU_OPT", 0}}) {
		t.Fatal(fans)
	}
	if !reflect.DeepEqual(volts, []Voltage{{"nct6798 in0", 1.032}, {"nct6798 +12V", 12.096}}) {
		t.Fatal(volts)
	}
}

func TestBatteryDMIOS(t *testing.T) {
	sys := t.TempDir()
	write(t, sys, map[string]string{
		"class/power_supply/AC/type": "Mains", "class/power_supply/hidpp_battery_0/type": "Battery",
		"class/power_supply/hidpp_battery_0/scope": "Device", "class/power_supply/BAT0/type": "Battery",
		"class/power_supply/BAT0/status": "Discharging", "class/power_supply/BAT0/power_now": "15200000",
		"class/dmi/id/sys_vendor": "Supermicro\n", "class/dmi/id/product_name": "Super Server\n",
		"class/dmi/id/board_vendor": "Supermicro", "class/dmi/id/board_name": "X11SCA-F", "class/dmi/id/bios_version": "1.8",
	})
	b, ok := ReadBattery(sys)
	if !ok || b.State != "discharging" || b.Watts == nil || *b.Watts != 15.2 {
		t.Fatal(b, ok)
	}
	write(t, sys, map[string]string{"class/power_supply/BAT0/power_now": "x", "class/power_supply/BAT0/current_now": "1000000",
		"class/power_supply/BAT0/voltage_now": "12000000"})
	if b, _ := ReadBattery(sys); *b.Watts != 12 {
		t.Fatal(*b.Watts)
	}
	cpuinfo := []byte("processor\t: 0\nmodel name\t: Intel(R) Xeon(R) E-2278G CPU @ 3.40GHz\nphysical id\t: 0\ncore id\t\t: 0\n\n" +
		"processor\t: 1\nmodel name\t: Intel(R) Xeon(R) E-2278G CPU @ 3.40GHz\nphysical id\t: 0\ncore id\t\t: 0\n\n" +
		"processor\t: 2\nphysical id\t: 0\ncore id\t\t: 1\n")
	if m, cores := ParseCPUInfo(cpuinfo); m != "Intel(R) Xeon(R) E-2278G CPU @ 3.40GHz" || cores != 2 {
		t.Fatal(m, cores)
	}
	h := ReadDMI(sys, t.TempDir(), cpuinfo)
	if *h.BoardModel != "X11SCA-F" || *h.SystemVendor != "Supermicro" || *h.CPUModel == "" || *h.BIOSVersion != "1.8" {
		t.Fatalf("%+v", h)
	}
	proc := t.TempDir()
	write(t, proc, map[string]string{"device-tree/model": "Raspberry Pi 4 Model B Rev 1.4\x00"})
	if h := ReadDMI(t.TempDir(), proc, nil); h == nil || *h.SystemModel != "Raspberry Pi 4 Model B Rev 1.4" {
		t.Fatalf("%+v", h)
	}
	if ReadDMI(t.TempDir(), t.TempDir(), nil) != nil {
		t.Fatal("nothing known = no hardware block")
	}
	if p := ParseOSRelease([]byte("NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n")); p != "Debian GNU/Linux 12 (bookworm)" {
		t.Fatal(p)
	}
	if p := ParseOSRelease([]byte("NAME=Alpine\nVERSION='3.20'\n")); p != "Alpine 3.20" {
		t.Fatal(p)
	}
	status := []byte("Package: pve-docs\nVersion: 9.0.1\n\nPackage: pve-manager\nStatus: install ok installed\nVersion: 9.0.3\n\n")
	if p := ProxmoxPretty(status); p != "Proxmox VE 9.0" || ProxmoxPretty([]byte("Package: bash\nVersion: 5\n")) != "" {
		t.Fatal(p)
	}
	if n := CountCPUList("0-7,9,12-13\n"); n != 11 {
		t.Fatal(n)
	}
	if CountCPUList("x") != 0 {
		t.Fatal("bad list")
	}
}

func TestMountinfo(t *testing.T) {
	data := []byte(`22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
23 22 0:21 / /proc rw - proc proc rw
24 22 259:1 / /boot/efi rw - vfat /dev/nvme0n1p1 rw
25 22 259:2 /var/tmp /tmp rw - ext4 /dev/nvme0n1p2 rw
26 22 0:50 / /rpool rw - zfs rpool rw
27 22 0:51 / /rpool/data/subvol-101-disk-0 rw - zfs rpool/data/subvol-101-disk-0 rw
28 22 0:52 / /tank rw - zfs tank rw
29 22 0:30 / /run/user/1000 rw - tmpfs tmpfs rw
30 22 8:17 / /run/media/me/USB\040Stick rw - exfat /dev/sdb1 rw
31 22 8:33 / /mnt/nas rw - nfs4 nas:/export rw
32 22 8:2 / /var/lib/docker/overlay2/x rw - ext4 /dev/sda2 rw
`)
	var got []string
	for _, m := range ParseMountinfo(data) {
		got = append(got, m.Point+" "+m.FSType)
	}
	want := []string{"/ ext4", "/boot/efi vfat", "/rpool zfs", "/run/media/me/USB Stick exfat", "/tank zfs"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestProcParsers(t *testing.T) {
	st, err := ParseProcPIDStat([]byte("1234 (my (weird) prog) S 1 1234 1234 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 4 0 9000 123456789 2048 18446744073709551615"))
	if err != nil || st.Comm != "my (weird) prog" || st.State != 'S' || st.UTime != 250 || st.STime != 50 ||
		st.StartTime != 9000 || st.RSSPages != 2048 {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := ParseProcPIDStat([]byte("1 (x) S 1")); err == nil {
		t.Fatal("short stat")
	}
	if uid, ok := ParseStatusUID([]byte("Name:\tx\nUid:\t1000\t1000\t1000\t1000\n")); !ok || uid != 1000 {
		t.Fatal(uid)
	}
	users := ParsePasswd([]byte("root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/n:/bin/sh\nbad\n"))
	if users[0] != "root" || users[1000] != "alice" || len(users) != 2 {
		t.Fatal(users)
	}
	cmd := []byte("/usr/bin/llama-server\x00-m\x00/models/x.gguf\x00")
	if CmdlineString(cmd) != "/usr/bin/llama-server -m /models/x.gguf" || CmdlineString(nil) != "" {
		t.Fatal(CmdlineString(cmd))
	}
	if ProcName("llama-server", cmd) != "llama-server" || ProcName("nvidia-persiste", []byte("/usr/bin/nvidia-persistenced\x00")) != "nvidia-persistenced" {
		t.Fatal("name")
	}
	if ProcStates['D'] != "disk-sleep" {
		t.Fatal("states")
	}
}

func TestNvidiaSMI(t *testing.T) {
	g, ok := ParseNvidiaGPULine("0, GPU-1234-abcd, NVIDIA GeForce RTX 2080 SUPER, 37, 1024, 8192, 61, 87.53")
	if !ok || g.Index != 0 || g.UUID != "GPU-1234-abcd" || g.Name != "NVIDIA GeForce RTX 2080 SUPER" || g.Vendor != "nvidia" ||
		*g.UtilPercent != 37 || *g.VRAMUsed != 1024<<20 || *g.VRAMTotal != 8192<<20 || *g.TempC != 61 || *g.PowerW != 87.5 {
		t.Fatalf("%+v", g)
	}
	g, ok = ParseNvidiaGPULine("1, GPU-x, Tesla P4, [N/A], 0, 7680, 40, [Not Supported]")
	if !ok || g.UtilPercent != nil || g.PowerW != nil || *g.VRAMUsed != 0 {
		t.Fatalf("%+v", g)
	}
	if _, ok := ParseNvidiaGPULine("NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver."); ok {
		t.Fatal("error text is not a GPU")
	}
	apps := ParseComputeApps([]byte("2417, GPU-a, 21000\n2417, GPU-b, 1000\n999, GPU-a, [N/A]\n5, GPU-zzz, 10\n"),
		map[string]int{"GPU-a": 0, "GPU-b": 1}, 2)
	if !reflect.DeepEqual(apps, map[int][]int64{2417: {21000 << 20, 1000 << 20}}) {
		t.Fatal(apps)
	}
	n := NewNvidiaSMI("", time.Second)
	if n.GPUs() != nil || n.ComputeApps(t.Context()) != nil {
		t.Fatal("no nvidia-smi = no GPUs")
	}
}

func TestWindowsHelpers(t *testing.T) {
	if p := WindowsPretty("Windows 10 Pro", "24H2", 26100); p != "Windows 11 Pro 24H2" {
		t.Fatal(p)
	}
	if p := WindowsPretty("Windows 10 Enterprise", "22H2", 19045); p != "Windows 10 Enterprise 22H2" {
		t.Fatal(p)
	}
	if p := WindowsPretty("", "", 0); p != "Windows" {
		t.Fatal(p)
	}
	if u := FiletimeToUnix(116444736000000000 + 15e6); u != 1.5 {
		t.Fatal(u)
	}
	if c, ok := KelvinToC(300.15); !ok || c != 27 {
		t.Fatal(c)
	}
	if _, ok := KelvinToC(0); ok {
		t.Fatal("0 K")
	}
	if p := CPUDelta(100, 1000, 500, 150, 1100, 600); p == nil || *p != 75 { // 200 total, 50 idle
		t.Fatal(p)
	}
	if ProcCPUPercent(2e7, 2*time.Second) != 100 {
		t.Fatal("one full CPU")
	}
}

// TestExeProcName (audit 5, r3-a1-03): the name of a process where command lines are off, from the kernel's
// name and the link to the program's file alone.
func TestExeProcName(t *testing.T) {
	for _, c := range []struct{ comm, exe, want string }{
		{"nvidia-persiste", "/usr/bin/nvidia-persistenced", "nvidia-persistenced"},
		{"nvidia-persiste", "", "nvidia-persiste"},                                           // the link cannot be read: another user's process
		{"nvidia-persiste", "/usr/bin/nvidia-persistenced (deleted)", "nvidia-persistenced"}, // the file was replaced by an update
		{"exactly15chars!", "/usr/bin/exactly15chars!", "exactly15chars!"},
		{"very long progr", "/opt/very long program name with spaces", "very long program name with spaces"},
		{"averyveryverylo", "/opt/x/averyveryverylongname--token=in-the-file-name", "averyveryverylongname--token=in-the-file-name"}, // a file that is really called so
		{"llama-server", "/usr/bin/llama-server", "llama-server"},                                                                    // not cut: never looked up
		{"sshd", "/usr/sbin/sshd", "sshd"},
		{"my_long_script.", "/usr/bin/python3.12", "my_long_script."},            // a script: the file is the interpreter, the name stays the script's
		{"ThreadPoolForeg", "/opt/app/some-long-helper-name", "ThreadPoolForeg"}, // a name the program gave itself
		{"kworker/u16:3-e", "", "kworker/u16:3-e"},                               // a kernel thread has no file
		{"verylongprogram", "verylongprogramname", "verylongprogramname"},        // no folder in the link
		{"verylongprogram", "/opt/verylongprogramname/", "verylongprogram"},      // not a file name
		{"verylongprogram", "/opt/" + "verylongprogram" + strings.Repeat("x", 250), "verylongprogram"},
	} {
		if got := ExeProcName(c.comm, c.exe); got != c.want {
			t.Errorf("ExeProcName(%q, %q) = %q, want %q", c.comm, c.exe, got, c.want)
		}
	}
}

// TestProcNameHoldsNoArguments (audit 5, r2-a2-02): comm is cut at 15 characters, so a longer program name is
// completed from the first argument. A program that wrote its own title has its whole command line in that
// argument, and "name" carried it, secrets included, also with processes.cmdline off. The name is the file
// name and nothing after it.
func TestProcNameHoldsNoArguments(t *testing.T) {
	for _, c := range []struct{ comm, cmdline, want string }{
		// a title: everything in argv[0]
		{"some-long-helpe", "/opt/app/some-long-helper-name --type=renderer --secret=x", "some-long-helper-name"},
		{"some-long-helpe", "/opt/app/some-long-helper-name --type=renderer --secret=x\x00", "some-long-helper-name"},
		{"verylongprogram", "verylongprogramname --db-password=POC-NOT-A-REAL-SECRET --user=admin\x00", "verylongprogramname"},
		{"verylongprogram", "./verylongprogramname\t--token=abc", "verylongprogramname"},
		{"verylongprogram", "verylongprogramname\n--token=abc", "verylongprogramname"},
		{"some-long-helpe", "/opt/app/some-long-helper-name --config=/etc/some-long-helper-name/secret-pw.conf", "some-long-helper-name"},
		{"some-long-helpe", "/opt/some-long-helper-name/bin/some-long-helper-name --pw=x", "some-long-helper-name"},
		{"some-long-helpe", "/opt/some-long-helper-name.d/some-long-helper-name-2 --pw=x", "some-long-helper-name-2"},
		{"chrome_crashpad", "/opt/google/chrome/chrome_crashpad_handler --monitor-self --database=/home/u/.config/google-chrome/Crash Reports --annotation=token=abc", "chrome_crashpad_handler"},
		{"Isolated Web Co", "/usr/lib/firefox/Isolated Web Content -contentproc -childID 3 -prefsLen 30000", "Isolated Web Content"},
		// the usual shape: arguments apart
		{"nvidia-persiste", "/usr/bin/nvidia-persistenced\x00--user\x00nvpd\x00", "nvidia-persistenced"},
		{"some-long-helpe", "some-long-helper-name\x00--secret=x\x00", "some-long-helper-name"},
		{"systemd-journal", "/usr/lib/systemd/systemd-journald\x00", "systemd-journald"},
		{"exactly15chars!", "/usr/bin/exactly15chars!\x00--pw=x\x00", "exactly15chars!"},
		// a file name with a space after the fifteenth character: cut there, which is still only file name
		{"my-long-program", "/opt/my-long-programs name with spaces --pw=x", "my-long-programs"},
		// comm that is not the start of the file name (set by the program, an interpreter, a path the agent cannot split)
		{"ThreadPoolForeg", "/opt/app/some-long-helper-name --secret=x", "ThreadPoolForeg"},
		{"some-long-helpe", "/usr/bin/python3\x00/opt/app/some-long-helper-name\x00--secret=x\x00", "some-long-helpe"},
		{"some-long-helpe", "/usr/bin/python3 /opt/app/some-long-helper-name --secret=x", "some-long-helper-name"},
		{"some-long-name.", `C:\Program Files\App\some-long-name.exe --pw=x`, "some-long-name."},
		{"some-long-helpe", "--secret=some-long-helper-name-is-not-a-path", "some-long-helpe"},
		{"some-long-helpe", "x=some-long-helper-name --secret=x", "some-long-helpe"},
		{"some-long-helpe", "", "some-long-helpe"},
		{"some-long-helpe", "some-long-helpe" + strings.Repeat("r", 300), "some-long-helpe"},
		// short names never look at the command line
		{"llama-server", "/usr/bin/llama-server -m /models/x.gguf --api-key=k", "llama-server"},
		{"sshd", "sshd: alice@pts/0", "sshd"},
	} {
		got := ProcName(c.comm, []byte(c.cmdline))
		if got != c.want {
			t.Errorf("ProcName(%q, %q) = %q, want %q", c.comm, c.cmdline, got, c.want)
		}
		if strings.ContainsAny(got, " \t\n=") && !strings.ContainsAny(c.comm, " =") {
			t.Errorf("ProcName(%q, %q) = %q: more than a file name", c.comm, c.cmdline, got)
		}
	}
}
