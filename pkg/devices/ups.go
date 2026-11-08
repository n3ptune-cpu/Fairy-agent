package devices

import (
	"context"
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

// UPSFromVars normalises a NUT variable set. CyberPower/usbhid-ups often has no ups.realpower: watts are then
// estimated as ups.load % x ups.realpower.nominal (WattsEstimated).
func UPSFromVars(name string, v map[string]string, description string) UPSRow {
	raw := v["ups.status"]
	state, flags := ParseUPSStatus(raw)
	load, nominal := numVar(v, "ups.load"), numVar(v, "ups.realpower.nominal")
	watts, est := numVar(v, "ups.realpower"), false
	if watts == nil && load != nil && nominal != nil && *nominal != 0 {
		w := round(*load**nominal/100, 1)
		watts, est = &w, true
	}
	var runtime *int
	if r := numVar(v, "battery.runtime"); r != nil {
		x := int(*r)
		runtime = &x
	}
	row := UPSRow{Name: name, State: state, Flags: flags, BatteryCharge: numVar(v, "battery.charge"),
		BatteryRuntimeS: runtime, BatteryVoltage: numVar(v, "battery.voltage"), LoadPercent: load, Watts: watts,
		WattsEstimated: est, NominalW: nominal, InputVoltage: numVar(v, "input.voltage"),
		OutputVoltage: numVar(v, "output.voltage"), InputFrequency: numVar(v, "input.frequency", "output.frequency"),
		Model: strVar(v, "ups.model", "device.model"), Mfr: strVar(v, "ups.mfr", "device.mfr"),
		Serial: strVar(v, "ups.serial", "device.serial"), BatteryDate: strVar(v, "battery.date", "battery.mfr.date"),
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
