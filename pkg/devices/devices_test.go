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

func TestTuyaDPSParsingAndCustomMapping(t *testing.T) {
	r := ParseTuyaDPS(map[string]any{"1": true, "17": 3.0, "18": 412.0, "19": 935.0, "20": 2301.0}, nil)
	if *r.Watts != 93.5 || *r.Voltage != 230.1 || *r.Current != 0.412 || r.EnergyKWh != nil {
		t.Fatalf("%+v", r)
	}
	custom := map[string]DpsField{"power": {DP: "104", Scale: 1}, "voltage": {DP: "106", Scale: 0.1}, "energy_kwh_total": {DP: "101", Scale: 0.01}}
	r = ParseTuyaDPS(map[string]any{"104": 55.0, "106": 2299.0, "101": 12345.0}, custom)
	if *r.Watts != 55 || *r.Voltage != 229.9 || r.Current != nil || *r.EnergyKWh != 123.45 {
		t.Fatalf("%+v", r)
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

func TestDescribeNeverLeaksDetails(t *testing.T) {
	if Describe(context.DeadlineExceeded) != "timeout" || Describe(&HTTPStatusError{Code: 500}) != "http 500" ||
		Describe(Errf("nut: ERR ACCESS-DENIED")) != "nut: ERR ACCESS-DENIED" ||
		Describe(errors.New("Get https://user:pw@host/: something")) != "error" {
		t.Fatal("describe")
	}
}
