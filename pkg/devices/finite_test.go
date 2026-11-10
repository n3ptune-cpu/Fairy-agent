package devices

// Impossible numbers from a device (audit 3, M2): a huge value, NaN, an infinity, and possible values that add
// up or scale to an impossible one. None may reach a Reading, because one of them makes a whole JSON answer fail.

import (
	"encoding/json"
	"math"
	"testing"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(s, err)
	}
	return m
}

// mustMarshal fails when v cannot be written as JSON (what happened to /metrics before).
func mustMarshal(t *testing.T, what string, v any) {
	t.Helper()
	if _, err := json.Marshal(v); err != nil {
		t.Errorf("%s: cannot be written as JSON: %v (%+v)", what, err, v)
	}
}

func TestFinite(t *testing.T) {
	for v, want := range map[float64]bool{0: true, -230.5: true, 95.5: true, MaxMagnitude: true, -MaxMagnitude: true,
		MaxMagnitude * 1.000001: false, -1e13: false, 1e308: false, math.MaxFloat64: false,
		math.Inf(1): false, math.Inf(-1): false} {
		if Finite(v) != want {
			t.Errorf("Finite(%v) = %v", v, !want)
		}
	}
	if Finite(math.NaN()) {
		t.Error("NaN is not a reading")
	}
	nan, big, ok := math.NaN(), 1e308, 42.0
	if Num(nil) != nil || Num(&nan) != nil || Num(&big) != nil || Num(&ok) != &ok {
		t.Error("Num")
	}
	if NumIn(&ok, 0, 100) != &ok || NumIn(&ok, 50, 100) != nil || NumIn(&ok, 0, 41.9) != nil ||
		NumIn(&nan, 0, 100) != nil || NumIn(&nan, math.Inf(-1), math.Inf(1)) != nil || NumIn(nil, 0, 1) != nil {
		t.Error("NumIn")
	}
}

func TestF64RejectsImpossibleNumbers(t *testing.T) {
	for _, v := range []any{1e308, -1e308, math.NaN(), math.Inf(1), math.Inf(-1), json.Number("1e308"),
		json.Number("1e999"), json.Number("NaN"), int64(math.MaxInt64), "95.5", nil, true} {
		if p := f64(v); p != nil {
			t.Errorf("f64(%v) = %v, want nil", v, *p)
		}
	}
	for v, want := range map[any]float64{95.5: 95.5, 7: 7, int64(-3): -3, json.Number("230.1"): 230.1, 1e12: 1e12} {
		if p := f64(v); p == nil || *p != want {
			t.Errorf("f64(%v) = %v, want %v", v, p, want)
		}
	}
	if div(f64(12000.0), 1000) == nil || *div(f64(12000.0), 1000) != 12 || div(f64(1.0), 0) != nil || div(nil, 5) != nil {
		t.Error("div")
	}
	if numRound(math.NaN(), 1) != nil || numRound(1e308, 3) != nil || numRound(math.Inf(1), 1) != nil || *numRound(93.54, 1) != 93.5 {
		t.Error("numRound")
	}
}

// The audit's plug input: each channel is a possible number for a float, the sum is not.
func TestTasmotaSumsAreChecked(t *testing.T) {
	cases := []struct {
		name, energy string
		watts        *float64
	}{
		{"audit: 1e308 twice", `{"Power":[1e308,1e308]}`, nil},
		{"one impossible channel poisons the total", `{"Power":[40,1e308]}`, nil},
		{"possible values, impossible sum", `{"Power":[6e11,6e11]}`, nil},
		{"single impossible value", `{"Power":1e308}`, nil},
		{"two channels", `{"Power":[40,55.5]}`, ptr(95.5)},
		{"a channel without a number is skipped, as before", `{"Power":[null,5]}`, ptr(5)},
		{"single value", `{"Power":61}`, ptr(61)},
	}
	for _, c := range cases {
		r, err := ParseTasmotaStatus8(decode(t, `{"StatusSNS":{"ENERGY":`+c.energy+`}}`))
		if err != nil {
			t.Fatal(c.name, err)
		}
		if (r.Watts == nil) != (c.watts == nil) || (r.Watts != nil && *r.Watts != *c.watts) {
			t.Errorf("%s: watts %v, want %v", c.name, show(r.Watts), show(c.watts))
		}
		mustMarshal(t, c.name, r)
	}
	r, _ := ParseTasmotaStatus8(decode(t, `{"StatusSNS":{"ENERGY":{"Power":[1e308,1e308],"Voltage":230,"Current":[1e308,-1e308],"Total":1e308}}}`))
	if r.Watts != nil || r.Voltage == nil || *r.Voltage != 230 || r.Current != nil || r.EnergyKWh != nil {
		t.Fatalf("the good value stays, the impossible ones are unknown: %+v", r)
	}
}

func ptr(v float64) *float64 { return &v }

func show(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestParsersDropImpossibleNumbers(t *testing.T) {
	g2 := ParseShellyGen2(decode(t, `{"apower":1e308,"voltage":229.8,"current":-1e308,"aenergy":{"total":1e308}}`))
	if g2.Watts != nil || g2.Current != nil || g2.EnergyKWh != nil || g2.Voltage == nil || *g2.Voltage != 229.8 {
		t.Errorf("shelly gen2: %+v", g2)
	}
	mustMarshal(t, "shelly gen2", g2)
	g1, err := ParseShellyGen1(decode(t, `{"emeters":[{"power":1e308,"voltage":230,"current":0.5,"total":1e308}]}`), 0)
	if err != nil || g1.Watts != nil || g1.EnergyKWh != nil || *g1.Voltage != 230 {
		t.Errorf("shelly gen1 emeter: %+v %v", g1, err)
	}
	mustMarshal(t, "shelly gen1 emeter", g1)
	g1, err = ParseShellyGen1(decode(t, `{"meters":[{"power":1e308,"total":1e308}]}`), 0)
	if err != nil || g1.Watts != nil || g1.EnergyKWh != nil {
		t.Errorf("shelly gen1 meter: %+v %v", g1, err)
	}
	if _, _, err := ParseRedfishPower(decode(t, `{"PowerControl":[{"PowerConsumedWatts":1e308}]}`)); err == nil {
		t.Error("redfish: an impossible PowerConsumedWatts is no reading")
	}
	w, v, err := ParseRedfishPower(decode(t, `{"PowerControl":[{"PowerConsumedWatts":180}],"PowerSupplies":[{"LineInputVoltage":1e308},{"LineInputVoltage":231}]}`))
	if err != nil || *w != 180 || v == nil || *v != 231 {
		t.Errorf("redfish: %v %v %v", show(w), show(v), err)
	}
	if w, _, err := ParseRedfishPower(decode(t, `{"PowerWatts":{"Reading":1e308}}`)); err != nil || w != nil {
		t.Errorf("redfish EnvironmentMetrics: %v %v", show(w), err)
	}
}

// Scaling: a possible raw value times the configured scale can leave the range; so can a scale that is not a
// number (yaml reads .nan and .inf as floats).
func TestTuyaScalingIsChecked(t *testing.T) {
	dps := map[string]any{"19": 9e11, "20": 2301.0, "18": 412.0}
	for name, scale := range map[string]float64{"huge product": 1e6, "NaN scale": math.NaN(), "+Inf scale": math.Inf(1), "-Inf scale": math.Inf(-1)} {
		r := ParseTuyaDPS(dps, map[string]DpsField{"power": {DP: "19", Scale: scale}, "voltage": {DP: "20", Scale: 0.1}})
		if r.Watts != nil || r.Voltage == nil || *r.Voltage != 230.1 {
			t.Errorf("%s: %+v", name, r)
		}
		mustMarshal(t, name, r)
	}
	if r := ParseTuyaDPS(map[string]any{"19": 1e308}, nil); r.Watts != nil {
		t.Errorf("impossible raw value: %v", *r.Watts)
	}
}

// The UPS power source (type nut): text from upsd. strconv reads "NaN" and "Inf" as numbers.
func TestNUTWattsRejectsImpossibleNumbers(t *testing.T) {
	for _, s := range []string{"NaN", "nan", "Inf", "+Inf", "-Inf", "Infinity", "1e999", "1e308", "-1e308", "0x1p1023", "", "abc"} {
		w, v, a := NUTWatts(map[string]string{"ups.realpower": s, "input.voltage": s, "output.current": s})
		if w != nil || v != nil || a != nil {
			t.Errorf("%q: %v %v %v", s, show(w), show(v), show(a))
		}
	}
	for name, vars := range map[string]map[string]string{
		"impossible product":  {"ups.load": "9e11", "ups.realpower.nominal": "9e11"},
		"negative load":       {"ups.load": "-5", "ups.realpower.nominal": "900"},
		"negative nominal":    {"ups.load": "25", "ups.realpower.nominal": "-900"},
		"NaN load":            {"ups.load": "NaN", "ups.realpower.nominal": "900"},
		"Inf nominal":         {"ups.load": "25", "ups.realpower.nominal": "Inf"},
		"zero nominal":        {"ups.load": "25", "ups.realpower.nominal": "0"},
		"NaN realpower, load": {"ups.realpower": "NaN", "ups.load": "NaN"},
	} {
		if w, _, _ := NUTWatts(vars); w != nil {
			t.Errorf("%s: %v", name, *w)
		}
	}
	if w, _, _ := NUTWatts(map[string]string{"ups.load": "25", "ups.realpower.nominal": "900"}); w == nil || *w != 225 {
		t.Error("estimate", show(w))
	}
	// an impossible ups.realpower falls back to the estimate, as a missing one does
	if w, _, _ := NUTWatts(map[string]string{"ups.realpower": "NaN", "ups.load": "50", "ups.realpower.nominal": "900"}); w == nil || *w != 450 {
		t.Error("estimate instead of NaN", show(w))
	}
}
