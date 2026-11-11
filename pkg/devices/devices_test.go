package devices

// Parser and error tests, moved here with the code from the panel's power, UPS and normalise packages.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestShellyGen1Emeter(t *testing.T) {
	r, err := ParseShellyGen1(map[string]any{"emeters": []any{map[string]any{"power": 100.0, "voltage": 230.0, "current": 0.5, "total": 2500.0}}}, 0)
	if err != nil || *r.Watts != 100 || *r.Voltage != 230 || *r.Current != 0.5 || *r.EnergyKWh != 2.5 {
		t.Fatal(r, err)
	}
}

func TestParseUPSStatus(t *testing.T) {
	cases := map[string]string{"OL": "online", "OL CHRG": "online", "OB DISCHRG": "on_battery", "OB LB": "low_battery",
		"OFF": "off", "": "unknown"}
	for raw, want := range cases {
		if st, _ := ParseUPSStatus(raw); st != want {
			t.Errorf("%q: %s want %s", raw, st, want)
		}
	}
	_, flags := ParseUPSStatus("OL RB OVER")
	if strings.Join(flags, ",") != "online,replace_battery,overload" {
		t.Fatal(flags)
	}
}

func TestEstimatedWattsWithoutRealpower(t *testing.T) {
	r := UPSFromVars("cp", map[string]string{"ups.status": "OL", "ups.load": "25", "ups.realpower.nominal": "900",
		"battery.runtime": "2100", "battery.mfr.date": "2023/05/14"}, "CyberPower")
	if *r.Watts != 225 || !r.WattsEstimated || *r.BatteryRuntimeS != 2100 || *r.BatteryDate != "2023/05/14" || *r.Description != "CyberPower" {
		t.Fatalf("%+v", r)
	}
}

func TestUPSPlaceholders(t *testing.T) {
	r := UPSFromVars("cp", map[string]string{"ups.status": "OL", "battery.date": "1", "battery.mfr.date": "2021/03/01",
		"ups.mfr": "1", "device.mfr": "CPS", "ups.model": "1500", "ups.serial": "unknown"}, "")
	if r.BatteryDate == nil || *r.BatteryDate != "2021/03/01" || r.Mfr == nil || *r.Mfr != "CPS" || *r.Model != "1500" || r.Serial != nil {
		t.Fatalf("%+v", r)
	}
	r = UPSFromVars("cp", map[string]string{"ups.status": "OL", "battery.date": "1", "ups.mfr": " 1 "}, "")
	if r.BatteryDate != nil || r.Mfr != nil {
		t.Fatalf("placeholders kept: %+v", r)
	}
}

func TestDescribeNeverLeaksDetails(t *testing.T) {
	if Describe(context.DeadlineExceeded) != "timeout" || Describe(&HTTPStatusError{Code: 500}) != "http 500" ||
		Describe(Errf("nut: ERR ACCESS-DENIED")) != "nut: ERR ACCESS-DENIED" ||
		Describe(errors.New("Get https://user:pw@host/: something")) != "error" {
		t.Fatal("describe")
	}
}
