package devices

// Fuzz targets from the independent review of the fixes: what a plug, a BMC or a UPS server sends.
// They run on their seeds with every `go test`; `go test -fuzz <name>` searches further.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func reviewFinite(t *testing.T, what string, ps ...*float64) {
	for _, p := range ps {
		if p != nil && !Finite(*p) {
			t.Fatalf("%s: %v is not a possible number", what, *p)
		}
	}
}

// Any JSON object a device answers with: every parser returns only possible numbers, and the reading can be
// written as JSON.
func FuzzDeviceJSON(f *testing.F) {
	f.Add([]byte(`{"StatusSNS":{"ENERGY":{"Power":[1e308,1e308],"Voltage":230,"Current":[1,"x"],"Total":-1e308}}}`), 0)
	f.Add([]byte(`{"apower":1e308,"voltage":1e400,"aenergy":{"total":1e15}}`), 0)
	f.Add([]byte(`{"emeters":[{"power":1,"total":1e300}],"meters":[{"power":2,"total":9e307}]}`), 1)
	f.Add([]byte(`{"PowerControl":[{"PowerConsumedWatts":1e13}],"PowerSupplies":[{"LineInputVoltage":-1e13}]}`), 0)
	f.Add([]byte(`{"state":"1e308","attributes":{"unit_of_measurement":"MW"},"last_reported":"2026-01-01T12:00:00+00:00"}`), 0)
	f.Add([]byte(`{"state":"99999.9996","attributes":{"unit_of_measurement":"kW","device_class":"power"},"last_updated":"x"}`), 0)
	f.Add([]byte(`{"state":"-0","attributes":{"device_class":"power"}}`), 0)
	f.Fuzz(func(t *testing.T, raw []byte, channel int) {
		var d map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		if dec.Decode(&d) != nil {
			return
		}
		var all []Reading
		all = append(all, ParseShellyGen2(d))
		if channel >= 0 && channel < 8 {
			if r, err := ParseShellyGen1(d, channel); err == nil {
				all = append(all, r)
			}
		}
		if r, err := ParseTasmotaStatus8(d); err == nil {
			all = append(all, r)
		}
		if w, v, err := ParseRedfishPower(d); err == nil {
			all = append(all, Reading{Watts: w, Voltage: v})
		}
		// a Home Assistant state: with and without an age limit, never more than a plug can draw
		for _, maxAge := range []time.Duration{0, time.Minute} {
			if r, err := ParseHAState(d, maxAge, time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)); err == nil {
				if r.Watts == nil || !(*r.Watts >= 0 && *r.Watts <= MaxHAWatts) {
					t.Fatalf("%s: a Home Assistant reading of %v", raw, r.Watts)
				}
				all = append(all, r)
			} else if _, fixed := err.(*Error); !fixed || strings.ContainsAny(err.Error(), "\"{}[]") {
				t.Fatalf("%s: the reason is not one of the fixed texts: %v", raw, err)
			}
		}
		for _, r := range all {
			reviewFinite(t, string(raw), r.Watts, r.Voltage, r.Current, r.EnergyKWh)
			if _, err := json.Marshal(r); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// Any text a UPS server reports for its variables: the row has only possible numbers and can be written.
func FuzzUPSVars(f *testing.F) {
	f.Add("NaN", "Inf", "-5", "1e999", "OB LB")
	f.Add("100.5", "1e12", "1e13", "0x1p10", "OL")
	f.Add("1_000", " 7 ", "+Infinity", "-0", "")
	f.Fuzz(func(t *testing.T, a, b, c, d, status string) {
		v := map[string]string{"ups.status": status, "ups.realpower": a, "ups.load": b, "ups.realpower.nominal": c,
			"battery.runtime": d, "battery.charge": a, "battery.voltage": b, "input.voltage": c, "output.voltage": d,
			"input.frequency": a, "output.current": b}
		row := UPSFromVars("u", v, "")
		reviewFinite(t, strings.Join([]string{a, b, c, d}, "|"), row.BatteryCharge, row.BatteryVoltage, row.LoadPercent,
			row.Watts, row.NominalW, row.InputVoltage, row.OutputVoltage, row.InputFrequency)
		if row.BatteryCharge != nil && (*row.BatteryCharge < 0 || *row.BatteryCharge > 100) {
			t.Fatalf("charge %v", *row.BatteryCharge)
		}
		if row.BatteryRuntimeS != nil && (*row.BatteryRuntimeS < 0 || *row.BatteryRuntimeS > MaxUPSRuntimeS) {
			t.Fatalf("runtime %v", *row.BatteryRuntimeS)
		}
		if row.LoadPercent != nil && *row.LoadPercent < 0 {
			t.Fatalf("load %v", *row.LoadPercent)
		}
		if _, err := json.Marshal(row); err != nil {
			t.Fatal(err)
		}
		w, vv, am := NUTWatts(v)
		reviewFinite(t, "NUTWatts", w, vv, am)
	})
}
