package devices

// Audit 3, L11: values a UPS server sends that cannot be readings. Before, "NaN" in one variable made the row
// impossible to write, the UPS dropped out of the answer without an error and the panel kept showing its last
// good state.

import (
	"strings"
	"testing"
)

func TestUPSImpossibleValuesBecomeUnknown(t *testing.T) {
	base := func(extra map[string]string) map[string]string {
		v := map[string]string{"ups.status": "OB LB", "battery.charge": "12", "battery.runtime": "95", "ups.load": "40",
			"ups.realpower.nominal": "900", "input.voltage": "0", "battery.voltage": "23.1"}
		for k, x := range extra {
			v[k] = x
		}
		return v
	}
	// the audit's input: the row must still say "low battery"
	for _, bad := range []string{"NaN", "nan", "Inf", "-Inf", "+Infinity", "1e999", "1e308"} {
		r := UPSFromVars("cp", base(map[string]string{"ups.realpower": bad}), "CyberPower")
		if !r.OK || r.State != "low_battery" || r.BatteryCharge == nil || *r.BatteryCharge != 12 || *r.BatteryRuntimeS != 95 {
			t.Errorf("ups.realpower %q: state and good values must stay: %+v", bad, r)
		}
		if r.Watts == nil || *r.Watts != 360 || !r.WattsEstimated {
			t.Errorf("ups.realpower %q: watts fall back to the estimate (40 %% of 900 W): %v", bad, show(r.Watts))
		}
		mustMarshal(t, "ups.realpower "+bad, r)
	}
	type check func(r UPSRow) bool
	cases := []struct {
		key, val string
		ok       check
		what     string
	}{
		{"battery.runtime", "-5", func(r UPSRow) bool { return r.BatteryRuntimeS == nil }, "negative run time"},
		{"battery.runtime", "1e300", func(r UPSRow) bool { return r.BatteryRuntimeS == nil }, "huge run time"},
		{"battery.runtime", "1000000001", func(r UPSRow) bool { return r.BatteryRuntimeS == nil }, "run time above the limit"},
		{"battery.runtime", "NaN", func(r UPSRow) bool { return r.BatteryRuntimeS == nil }, "NaN run time"},
		{"battery.runtime", "Inf", func(r UPSRow) bool { return r.BatteryRuntimeS == nil }, "Inf run time"},
		{"battery.runtime", "1000000000", func(r UPSRow) bool { return r.BatteryRuntimeS != nil && *r.BatteryRuntimeS == 1000000000 }, "run time at the limit"},
		{"battery.runtime", "0", func(r UPSRow) bool { return r.BatteryRuntimeS != nil && *r.BatteryRuntimeS == 0 }, "run time 0"},
		{"battery.runtime", "2100.9", func(r UPSRow) bool { return r.BatteryRuntimeS != nil && *r.BatteryRuntimeS == 2100 }, "run time with a fraction"},
		{"battery.charge", "250", func(r UPSRow) bool { return r.BatteryCharge == nil }, "charge above 100"},
		{"battery.charge", "100.5", func(r UPSRow) bool { return r.BatteryCharge == nil }, "charge just above 100"},
		{"battery.charge", "-1", func(r UPSRow) bool { return r.BatteryCharge == nil }, "negative charge"},
		{"battery.charge", "NaN", func(r UPSRow) bool { return r.BatteryCharge == nil }, "NaN charge"},
		{"battery.charge", "100", func(r UPSRow) bool { return r.BatteryCharge != nil && *r.BatteryCharge == 100 }, "charge 100"},
		{"battery.charge", "0", func(r UPSRow) bool { return r.BatteryCharge != nil && *r.BatteryCharge == 0 }, "charge 0"},
		{"ups.load", "-3", func(r UPSRow) bool { return r.LoadPercent == nil && r.Watts == nil && !r.WattsEstimated }, "negative load: no value, no estimate"},
		{"ups.load", "NaN", func(r UPSRow) bool { return r.LoadPercent == nil && r.Watts == nil && !r.WattsEstimated }, "NaN load"},
		{"ups.load", "130", func(r UPSRow) bool { return r.LoadPercent != nil && *r.LoadPercent == 130 && *r.Watts == 1170 }, "overload above 100 % is a reading"},
		{"ups.realpower.nominal", "-900", func(r UPSRow) bool { return r.NominalW == nil && r.Watts == nil }, "negative nominal power"},
		{"ups.realpower.nominal", "9e11", func(r UPSRow) bool { return r.Watts != nil && *r.Watts == 3.6e11 }, "large but possible"},
		{"ups.realpower.nominal", "1e12", func(r UPSRow) bool { return r.Watts != nil && *r.Watts == 4e11 }, "nominal at the limit"},
		{"ups.realpower", "-1e13", func(r UPSRow) bool { return r.Watts != nil && *r.Watts == 360 && r.WattsEstimated }, "impossible watts: estimate"},
		{"input.voltage", "Inf", func(r UPSRow) bool { return r.InputVoltage == nil }, "Inf voltage"},
		{"output.voltage", "NaN", func(r UPSRow) bool { return r.OutputVoltage == nil }, "NaN voltage"},
		{"battery.voltage", "-Inf", func(r UPSRow) bool { return r.BatteryVoltage == nil }, "-Inf battery voltage"},
		{"input.frequency", "nan", func(r UPSRow) bool { return r.InputFrequency == nil }, "nan frequency"},
	}
	for _, c := range cases {
		r := UPSFromVars("cp", base(map[string]string{c.key: c.val}), "")
		if !c.ok(r) {
			t.Errorf("%s (%s %q): %+v", c.what, c.key, c.val, r)
		}
		if !r.OK || r.State != "low_battery" {
			t.Errorf("%s: the row itself must stay usable: %+v", c.what, r)
		}
		mustMarshal(t, c.what, r)
	}
}

// Every numeric variable set to every hostile text at once: the row can always be written.
func TestUPSRowCanAlwaysBeWritten(t *testing.T) {
	keys := []string{"ups.realpower", "ups.load", "ups.realpower.nominal", "battery.charge", "battery.runtime",
		"battery.voltage", "input.voltage", "output.voltage", "input.frequency", "output.frequency", "output.current"}
	for _, bad := range []string{"NaN", "-nan", "Inf", "-Inf", "infinity", "1e999", "-1e999", "1e308", "-1e308",
		"1.7976931348623157e308", "0x1p1023", "9e11", "-9e11", "1e12", strings.Repeat("9", 400)} {
		v := map[string]string{"ups.status": "OL"}
		for _, k := range keys {
			v[k] = bad
		}
		r := UPSFromVars("cp", v, "")
		mustMarshal(t, bad, r)
		w, vo, a := NUTWatts(v)
		mustMarshal(t, "NUTWatts "+bad, []*float64{w, vo, a})
		if r.State != "online" || !r.OK {
			t.Errorf("%q: %+v", bad, r)
		}
	}
}
