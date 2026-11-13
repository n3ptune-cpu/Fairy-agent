package devices

import (
	"strconv"
	"time"
)

// ParseShellyGen2 reads a Gen2+/Plus/Pro RPC Switch.GetStatus (or PM1.GetStatus). aenergy.total is Wh.
func ParseShellyGen2(d map[string]any) Reading {
	return Reading{f64(d["apower"]), f64(d["voltage"]), f64(d["current"]), div(f64(obj(d["aenergy"])["total"]), 1000)}
}

// ParseShellyGen1 reads /status `meters` (Plug S, 1PM; total in watt-minutes) or `emeters` (EM/3EM; total in Wh).
func ParseShellyGen1(d map[string]any, channel int) (Reading, error) {
	if em, ok := d["emeters"].([]any); ok && len(em) > 0 {
		if channel >= len(em) {
			return Reading{}, Errf("shelly: no meter on that channel")
		}
		m := obj(em[channel])
		return Reading{f64(m["power"]), f64(m["voltage"]), f64(m["current"]), div(f64(m["total"]), 1000)}, nil
	}
	meters, _ := d["meters"].([]any)
	if channel >= len(meters) {
		return Reading{}, Errf("shelly: no meter on that channel")
	}
	m := obj(meters[channel])
	return Reading{Watts: f64(m["power"]), EnergyKWh: div(f64(m["total"]), 60000)}, nil
}

// ParseTasmotaStatus8 reads `Status 8` (StatusSNS.ENERGY); multi-channel values are summed.
func ParseTasmotaStatus8(d map[string]any) (Reading, error) {
	e := obj(obj(d["StatusSNS"])["ENERGY"])
	if len(e) == 0 {
		return Reading{}, Errf("tasmota: no ENERGY block (not a metering device?)")
	}
	num := func(v any) *float64 { // multi-channel devices return lists
		l, ok := v.([]any)
		if !ok {
			return f64(v)
		}
		s := 0.0
		for _, x := range l {
			p := f64(x)
			if p == nil {
				if isNumber(x) { // an impossible number on one channel: the total is unknown, not "the rest"
					return nil
				}
				continue
			}
			s += *p
		}
		return Num(&s) // checked again: possible numbers can add up to an impossible one
	}
	return Reading{num(e["Power"]), num(e["Voltage"]), num(e["Current"]), num(e["Total"])}, nil
}

// ParseRedfishPower reads a Chassis Power (PowerControl / PowerSupplies) or EnvironmentMetrics document.
func ParseRedfishPower(d map[string]any) (watts, volts *float64, err error) {
	if pw, ok := d["PowerWatts"]; ok { // newer EnvironmentMetrics schema
		return f64(obj(pw)["Reading"]), nil, nil
	}
	if pc, ok := d["PowerControl"].([]any); ok && len(pc) > 0 {
		watts = f64(obj(pc[0])["PowerConsumedWatts"])
	}
	if ps, ok := d["PowerSupplies"].([]any); ok {
		for _, p := range ps {
			if v := f64(obj(p)["LineInputVoltage"]); v != nil && *v != 0 {
				volts = v
				break
			}
		}
	}
	if watts == nil {
		return nil, nil, Errf("redfish: no PowerConsumedWatts")
	}
	return watts, volts, nil
}

// MaxHAWatts is the most a Home Assistant power sensor may report for a plug and still be taken as a reading:
// 100 kW. A plug measures up to a few kW; a larger number is a wrong entity (a meter, a counter) or a fault.
const MaxHAWatts = 100000

// haWatts is how many watts one of Home Assistant's units of power is. Only these four are read: a sensor in
// another unit (kWh, V, a temperature) is the wrong entity and must not be shown as watts.
var haWatts = map[string]float64{"mW": 0.001, "W": 1, "kW": 1000, "MW": 1e6}

// ParseHAState reads the watts from a Home Assistant state object (GET /api/states/<entity id>) of a power
// sensor. Every reason it gives for "no reading" is a fixed text: nothing of the answer is repeated in it.
//
//   - `state` is text. "unavailable" (the device does not answer Home Assistant), "unknown" (no value yet), an
//     empty text and everything that is not a plain decimal number are no reading. So are "nan" and "inf",
//     which a number parser would take.
//   - The unit is attributes.unit_of_measurement: W, mW, kW or MW, converted to watts. Without a unit the
//     number counts as watts only when attributes.device_class is "power". Any other unit is no reading.
//   - A negative number and one over MaxHAWatts are no reading.
//   - maxAge > 0: the state must have been written at most that long before now. The time is last_reported,
//     which Home Assistant renews whenever the integration writes the state again, also with the same value;
//     an answer without it (an older Home Assistant) is judged by last_updated, which only moves when the
//     value changes. A state with neither is no reading, a time ahead of now is taken as fresh.
//
// Watts are passed on as they are, as a plug's own answer is; a converted number (mW, kW, MW) is rounded to
// three places, because the conversion alone makes 0.0234 kW into 23.400000000000002 W.
func ParseHAState(d map[string]any, maxAge time.Duration, now time.Time) (Reading, error) {
	state, isText := d["state"].(string)
	switch {
	case !isText || state == "":
		return Reading{}, Errf("home assistant: the sensor has no state")
	case state == "unavailable":
		return Reading{}, Errf("home assistant: the sensor is unavailable")
	case state == "unknown":
		return Reading{}, Errf("home assistant: the sensor's state is unknown")
	}
	v, ok := decimal(state)
	if !ok {
		return Reading{}, Errf("home assistant: the sensor's state is not a number")
	}
	attrs := obj(d["attributes"])
	factor := 1.0
	switch unit := attrs["unit_of_measurement"].(type) {
	case nil, string:
		name, _ := unit.(string)
		if name == "" { // no unit at all (not there, null or empty)
			if class, _ := attrs["device_class"].(string); class != "power" {
				return Reading{}, Errf("home assistant: the sensor has no unit and is not a power sensor")
			}
		} else if factor, ok = haWatts[name]; !ok {
			return Reading{}, Errf("home assistant: the sensor's unit is not a unit of power (W, mW, kW, MW)")
		}
	default:
		return Reading{}, Errf("home assistant: the sensor's unit is not a unit of power (W, mW, kW, MW)")
	}
	w := &v
	if factor != 1 {
		w = numRound(v*factor, 3)
	}
	if w == nil || !(*w >= 0 && *w <= MaxHAWatts) {
		return Reading{}, Errf("home assistant: the sensor's value is not a possible power (0 to 100000 W)")
	}
	if *w == 0 {
		*w = 0 // "-0" is zero
	}
	if maxAge > 0 {
		at, ok := haTime(d["last_reported"])
		if !ok {
			at, ok = haTime(d["last_updated"])
		}
		if !ok {
			return Reading{}, Errf("home assistant: the sensor's state has no time (max_age_s is set)")
		}
		if now.Sub(at) > maxAge {
			return Reading{}, Errf("home assistant: the sensor's value is older than max_age_s")
		}
	}
	return Reading{Watts: w}, nil
}

// decimal is the number in a text that is a plain decimal number ("12", "12.5", "-0.5", "1.2e3"); everything
// else is not one: "nan", "inf", hexadecimal, digits with "_", spaces, a number too large for a float.
func decimal(s string) (float64, bool) {
	if len(s) > 64 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c == '.' || c == '-' || c == '+' || c == 'e' || c == 'E') {
			return 0, false
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || !Finite(v) {
		return 0, false
	}
	return v, true
}

// haTime is one of Home Assistant's time stamps ("2026-01-01T12:00:00.123456+00:00").
func haTime(v any) (time.Time, bool) {
	s, _ := v.(string)
	if s == "" || len(s) > 64 {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, s)
	return at, err == nil
}
