//go:build !windows

package collect

// Tests whose fixtures need file names that Linux's /sys uses and Windows does not allow (a colon:
// "intel-rapl:0", "ucsi-source-psy-USBC000:001"). The code they test reads /sys and only ever runs on Linux.

import "testing"

// A USB-C supply as Linux names it counts as mains power.
func TestBatteryUSBCSupply(t *testing.T) {
	root := psTree(t, map[string]map[string]string{
		"BAT0":                        {"type": "Battery", "status": "Not charging", "capacity": "60"},
		"ucsi-source-psy-USBC000:001": {"type": "USB", "online": "1"},
	})
	b := ReadBatteryStatus(root)
	if b == nil || *b.Percent != 60 || b.State != "idle" || !*b.ACOnline || b.PowerW != nil || b.TimeRemainingS != nil || b.HealthPct != nil {
		t.Fatalf("%+v", b)
	}
}

func TestRAPL(t *testing.T) {
	sys := t.TempDir()
	write(t, sys, map[string]string{
		"class/powercap/intel-rapl:0/name": "package-0", "class/powercap/intel-rapl:0/energy_uj": "1000000",
		"class/powercap/intel-rapl:0/max_energy_range_uj": "262143328850",
		"class/powercap/intel-rapl:0:0/name":              "core", "class/powercap/intel-rapl:0:0/energy_uj": "5",
		"class/powercap/intel-rapl:0:0/max_energy_range_uj": "10",
		"class/powercap/intel-rapl:1/name":                  "psys", // energy_uj unreadable/missing: skipped
	})
	z := ReadRAPL(sys)
	if len(z) != 1 || z[0].Name != "package-0" || z[0].EnergyUJ != 1000000 {
		t.Fatal(z)
	}
	cur := z[0]
	cur.EnergyUJ = 21000000
	if w, ok := RAPLWatts(z[0], cur, 2); !ok || w != 10 {
		t.Fatal(w, ok)
	}
	wrapped := RAPLZone{Name: "package-0", EnergyUJ: 500000, MaxUJ: 1000000}
	if w, ok := RAPLWatts(RAPLZone{EnergyUJ: 900000}, wrapped, 1); !ok || w != 0.6 {
		t.Fatal("wrap", w, ok)
	}
}
