package devices

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// UPSFlags maps NUT ups.status words to the flags and states Fairy shows.
var UPSFlags = map[string]string{"OL": "online", "OB": "on_battery", "LB": "low_battery", "HB": "high_battery",
	"RB": "replace_battery", "CHRG": "charging", "DISCHRG": "discharging", "BYPASS": "bypass", "CAL": "calibrating",
	"OFF": "off", "OVER": "overload", "TRIM": "trim", "BOOST": "boost", "FSD": "forced_shutdown", "ALARM": "alarm",
	"TEST": "test"}

// ParseUPSStatus splits NUT ups.status ("OB DISCHRG LB") -> state (online|on_battery|low_battery|off|unknown), flags.
func ParseUPSStatus(raw string) (string, []string) {
	toks := strings.Fields(strings.ToUpper(raw))
	has := map[string]bool{}
	flags := []string{}
	for _, t := range toks {
		has[t] = true
		if f, ok := UPSFlags[t]; ok {
			flags = append(flags, f)
		}
	}
	switch {
	case has["OB"] && (has["LB"] || has["FSD"]):
		return "low_battery", flags
	case has["OB"]:
		return "on_battery", flags
	case has["OL"]:
		return "online", flags
	case has["OFF"]:
		return "off", flags
	}
	return "unknown", flags
}

// UPSRow is the normalised UPS shape (also the agent's /metrics `ups` rows).
type UPSRow struct {
	Name            string   `json:"name"`
	Description     *string  `json:"description"`
	StatusRaw       *string  `json:"status_raw"`
	State           string   `json:"state"`
	Flags           []string `json:"flags"`
	BatteryCharge   *float64 `json:"battery_charge"`
	BatteryRuntimeS *int     `json:"battery_runtime_s"`
	BatteryVoltage  *float64 `json:"battery_voltage"`
	LoadPercent     *float64 `json:"load_percent"`
	Watts           *float64 `json:"watts"`
	WattsEstimated  bool     `json:"watts_estimated"`
	NominalW        *float64 `json:"nominal_w"`
	InputVoltage    *float64 `json:"input_voltage"`
	OutputVoltage   *float64 `json:"output_voltage"`
	InputFrequency  *float64 `json:"input_frequency"`
	Model           *string  `json:"model"`
	Mfr             *string  `json:"mfr"`
	Serial          *string  `json:"serial"`
	BatteryDate     *string  `json:"battery_date"`
	TestResult      *string  `json:"test_result"`
	TransferReason  *string  `json:"transfer_reason"`
	OK              bool     `json:"ok"`
	Error           *string  `json:"error"`
}

// MaxUPSRuntimeS is the longest battery run time taken from a UPS (about 31 years, and it fits an int on every
// platform); anything longer is not a reading.
const MaxUPSRuntimeS = 1_000_000_000

// UPSFromVars normalises a NUT variable set. CyberPower/usbhid-ups often has no ups.realpower: watts are then
// estimated as ups.load % x ups.realpower.nominal (WattsEstimated).
//
// A value upsd reports that cannot be a reading is left out (nil, shown as unknown) and the rest of the row
// stays: "NaN", "Inf" or a number beyond devices.MaxMagnitude anywhere, a battery charge outside 0-100, a
// negative load or nominal power, a run time below 0 or above MaxUPSRuntimeS. The row can therefore always be
// written as JSON, and the UPS's state (on battery, low battery) still reaches the panel.
func UPSFromVars(name string, v map[string]string, description string) UPSRow {
	raw := v["ups.status"]
	state, flags := ParseUPSStatus(raw)
	load, nominal := notNegative(numVar(v, "ups.load")), notNegative(numVar(v, "ups.realpower.nominal"))
	watts, est := numVar(v, "ups.realpower"), false
	if watts == nil {
		watts = nutEstimate(load, nominal)
		est = watts != nil
	}
	var runtime *int
	if r := NumIn(numVar(v, "battery.runtime"), 0, MaxUPSRuntimeS); r != nil {
		x := int(*r)
		runtime = &x
	}
	row := UPSRow{Name: name, State: state, Flags: flags, BatteryCharge: NumIn(numVar(v, "battery.charge"), 0, 100),
		BatteryRuntimeS: runtime, BatteryVoltage: numVar(v, "battery.voltage"), LoadPercent: load, Watts: watts,
		WattsEstimated: est, NominalW: nominal, InputVoltage: numVar(v, "input.voltage"),
		OutputVoltage: numVar(v, "output.voltage"), InputFrequency: numVar(v, "input.frequency", "output.frequency"),
		Model: infoVar(v, "ups.model", "device.model"), Mfr: infoVar(v, "ups.mfr", "device.mfr"),
		Serial: infoVar(v, "ups.serial", "device.serial"), BatteryDate: infoVar(v, "battery.date", "battery.mfr.date"),
		TestResult: strVar(v, "ups.test.result"), TransferReason: strVar(v, "input.transfer.reason"), OK: true}
	if raw != "" {
		row.StatusRaw = &raw
	}
	if description != "" {
		row.Description = &description
	}
	return row
}

// PollUPS never fails: on error it returns error rows (named after `names`, or "upsd").
func PollUPS(ctx context.Context, host string, port int, user, pass string, names []string, timeout time.Duration) []UPSRow {
	upses, err := NUTReadAll(ctx, host, port, user, pass, timeout, names)
	if err != nil {
		msg := err.Error()
		if len(names) == 0 {
			names = []string{"upsd"}
		}
		out := make([]UPSRow, 0, len(names))
		for _, n := range names {
			out = append(out, UPSRow{Name: n, OK: false, Error: &msg, Flags: []string{}})
		}
		return out
	}
	out := make([]UPSRow, 0, len(upses))
	for _, u := range upses {
		out = append(out, UPSFromVars(u.Name, u.Vars, u.Description))
	}
	return out
}

// placeholder matches the filler some UPS firmwares report instead of a real model, maker, serial or date
// (CyberPower over usbhid: battery.date "1", ups.mfr "1"): one or two digits, or words that mean "unknown".
var placeholder = regexp.MustCompile(`(?i)^(\d{1,2}|0+|unknown|n/?a|none|not set|-+|\?+)$`)

// infoVar is strVar for descriptive values: placeholders count as missing, so the panel shows "–" instead.
func infoVar(v map[string]string, keys ...string) *string {
	for _, k := range keys {
		if s := strings.TrimSpace(v[k]); s != "" && !placeholder.MatchString(s) {
			return &s
		}
	}
	return nil
}
