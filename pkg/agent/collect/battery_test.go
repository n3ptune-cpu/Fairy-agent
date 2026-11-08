package collect

import (
	"os"
	"path/filepath"
	"testing"
)

// psTree writes a fake /sys/class/power_supply: supply name -> file -> contents.
func psTree(t *testing.T, supplies map[string]map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, files := range supplies {
		dir := filepath.Join(root, "class", "power_supply", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for f, v := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte(v+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func TestBatteryEnergyDischarging(t *testing.T) {
	root := psTree(t, map[string]map[string]string{
		"AC": {"type": "Mains", "online": "0"},
		"BAT0": {"type": "Battery", "present": "1", "status": "Discharging", "capacity": "80", "energy_now": "40000000",
			"energy_full": "50000000", "energy_full_design": "57000000", "power_now": "10000000", "voltage_now": "11800000"},
		"hidpp_battery_0": {"type": "Battery", "scope": "Device", "status": "Discharging", "capacity": "5"},
	})
	b := ReadBatteryStatus(root)
	if b == nil || *b.Percent != 80 || b.State != "discharging" || *b.ACOnline || *b.PowerW != 10 ||
		*b.TimeRemainingS != 4*3600 || *b.HealthPct != 87.7 {
		t.Fatalf("%+v", b)
	}
}

func TestBatteryChargeUnitsCharging(t *testing.T) {
	// charge_* in µAh with voltage_min_design; no power_now: current_now x voltage_now
	root := psTree(t, map[string]map[string]string{
		"ADP1": {"type": "Mains", "online": "1"},
		"BAT1": {"type": "Battery", "status": "Charging", "capacity": "50", "charge_now": "2000000", "charge_full": "4000000",
			"charge_full_design": "5000000", "voltage_min_design": "10000000", "voltage_now": "12000000", "current_now": "-2000000"},
	})
	b := ReadBatteryStatus(root)
	// 2 Ah x 10 V = 20 Wh of 40 Wh; 2 A x 12 V = 24 W charging; 20 Wh to go at 24 W = 50 min
	if b == nil || *b.Percent != 50 || b.State != "charging" || !*b.ACOnline || *b.PowerW != -24 ||
		*b.TimeRemainingS != 3000 || *b.HealthPct != 80 {
		t.Fatalf("%+v", b)
	}
}

func TestBatteryMinimal(t *testing.T) {
	// capacity and status only (no energy, no rate): percent and state, nothing invented
	root := psTree(t, map[string]map[string]string{
		"BAT0":                        {"type": "Battery", "status": "Not charging", "capacity": "60"},
		"ucsi-source-psy-USBC000:001": {"type": "USB", "online": "1"},
	})
	b := ReadBatteryStatus(root)
	if b == nil || *b.Percent != 60 || b.State != "idle" || !*b.ACOnline || b.PowerW != nil || b.TimeRemainingS != nil || b.HealthPct != nil {
		t.Fatalf("%+v", b)
	}
	// "Full" and an unknown status with AC
	root = psTree(t, map[string]map[string]string{"AC": {"type": "Mains", "online": "1"},
		"BAT0": {"type": "Battery", "status": "Full", "capacity": "100", "power_now": "0"}})
	if b := ReadBatteryStatus(root); b.State != "full" || *b.PowerW != 0 || b.TimeRemainingS != nil {
		t.Fatalf("%+v", b)
	}
	root = psTree(t, map[string]map[string]string{"AC": {"type": "Mains", "online": "1"},
		"BAT0": {"type": "Battery", "status": "Unknown", "capacity": "97"}})
	if b := ReadBatteryStatus(root); b.State != "idle" {
		t.Fatalf("%+v", b)
	}
	// time_to_empty_now from the driver wins over the estimate
	root = psTree(t, map[string]map[string]string{"BAT0": {"type": "Battery", "status": "Discharging", "capacity": "40",
		"energy_now": "20000000", "energy_full": "50000000", "power_now": "5000000", "time_to_empty_now": "7000"}})
	if b := ReadBatteryStatus(root); *b.TimeRemainingS != 7000 || b.ACOnline != nil {
		t.Fatalf("%+v", b)
	}
}

func TestBatteryTwoPacks(t *testing.T) {
	root := psTree(t, map[string]map[string]string{
		"AC":   {"type": "Mains", "online": "0"},
		"BAT0": {"type": "Battery", "status": "Unknown", "energy_now": "10000000", "energy_full": "20000000", "power_now": "0"},
		"BAT1": {"type": "Battery", "status": "Discharging", "energy_now": "20000000", "energy_full": "20000000", "power_now": "15000000"},
	})
	b := ReadBatteryStatus(root)
	if b == nil || *b.Percent != 75 || b.State != "discharging" || *b.PowerW != 15 || *b.TimeRemainingS != 7200 {
		t.Fatalf("%+v", b)
	}
}

func TestNoBattery(t *testing.T) {
	root := psTree(t, map[string]map[string]string{"AC": {"type": "Mains", "online": "1"},
		"BAT0": {"type": "Battery", "present": "0"}, "hid-mouse": {"type": "Battery", "scope": "Device", "capacity": "50"}})
	if b := ReadBatteryStatus(root); b != nil {
		t.Fatalf("%+v", b)
	}
	if ReadBatteryStatus(t.TempDir()) != nil {
		t.Fatal("no power_supply = no battery")
	}
}

func TestWindowsBattery(t *testing.T) {
	if WindowsBattery(0, 128, 255, 0xFFFFFFFF) != nil || WindowsBattery(1, 255, 255, 0xFFFFFFFF) != nil {
		t.Fatal("no battery / unknown status")
	}
	b := WindowsBattery(0, 0, 63, 5400)
	if *b.Percent != 63 || b.State != "discharging" || *b.ACOnline || *b.TimeRemainingS != 5400 || b.PowerW != nil {
		t.Fatalf("%+v", b)
	}
	if b := WindowsBattery(1, 8, 40, 0xFFFFFFFF); b.State != "charging" || !*b.ACOnline || b.TimeRemainingS != nil {
		t.Fatalf("%+v", b)
	}
	if b := WindowsBattery(1, 1, 100, 0xFFFFFFFF); b.State != "full" {
		t.Fatalf("%+v", b)
	}
	if b := WindowsBattery(255, 2, 255, 0xFFFFFFFF); b.ACOnline != nil || b.Percent != nil || b.State != "discharging" {
		t.Fatalf("%+v", b)
	}
}
