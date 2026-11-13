package devices

import "time"

// HAKind is one of the values of a plug, other than its watts, that a Home Assistant has a sensor of its own
// for: ParseHAValue reads one of them from that sensor's state object.
type HAKind int

const (
	HAVoltage HAKind = iota + 1 // volts
	HACurrent                   // amperes
	HAEnergy                    // kWh: a total (a counter), not a power
)

// The most a Home Assistant sensor may report for these values and still be taken as one. A plug has 100 to
// 250 V and up to 16 A or so; a larger number is a wrong entity or a fault. The energy total is a counter that
// only grows: 1e9 kWh is far above every meter and far below where a number stops being exact.
const (
	MaxHAVolts     = 1000
	MaxHAAmps      = 1000
	MaxHAEnergyKWh = 1e9
)

// haValue is how one kind of value is read: its units (how many of the kind's own unit one of them is), the
// device_class of such a sensor, and the fixed reasons that name the kind. Every text is written out here: no
// reason is put together from anything an answer holds.
type haValue struct {
	units    map[string]float64
	class    string  // attributes.device_class of such a sensor
	unitless bool    // a number without a unit counts (as the kind's own unit) when the class is the kind's
	total    bool    // attributes.state_class, when there, must be total or total_increasing
	max      float64 // in the kind's own unit
	noUnit   string
	badUnit  string
	notKind  string
	outside  string
}

var haValues = map[HAKind]haValue{
	HAVoltage: {units: map[string]float64{"V": 1, "mV": 0.001}, class: "voltage", unitless: true, max: MaxHAVolts,
		noUnit:  "the sensor has no unit and is not a voltage sensor",
		badUnit: "the sensor's unit is not a unit of voltage (V, mV)",
		notKind: "the sensor is not a voltage sensor",
		outside: "the sensor's value is not a possible voltage (0 to 1000 V)"},
	HACurrent: {units: map[string]float64{"A": 1, "mA": 0.001}, class: "current", unitless: true, max: MaxHAAmps,
		noUnit:  "the sensor has no unit and is not a current sensor",
		badUnit: "the sensor's unit is not a unit of current (A, mA)",
		notKind: "the sensor is not a current sensor",
		outside: "the sensor's value is not a possible current (0 to 1000 A)"},
	HAEnergy: {units: map[string]float64{"kWh": 1, "Wh": 0.001, "MWh": 1000}, class: "energy", total: true, max: MaxHAEnergyKWh,
		noUnit:  "the sensor has no unit (an energy total needs kWh, Wh or MWh)",
		badUnit: "the sensor's unit is not a unit of energy (kWh, Wh, MWh)",
		notKind: "the sensor is not an energy sensor",
		outside: "the sensor's value is not a possible energy total (0 to 1e9 kWh)"},
}

// The reasons of ParseHAValue that do not name the kind.
const (
	haValueNoState   = "the sensor has no state"
	haValueUnavail   = "the sensor is unavailable"
	haValueUnknown   = "the sensor's state is unknown"
	haValueNotNumber = "the sensor's state is not a number"
	haValueNotTotal  = "the sensor is not a total (its state_class is not total or total_increasing)"
	haValueNoTime    = "the sensor's state has no time (max_age_s is set)"
	haValueOld       = "the sensor's value is older than max_age_s"
)

// ParseHAValue reads one value of a plug other than its watts (its volts, its amperes or its energy total in
// kWh) from the Home Assistant state object of the sensor for it. It is as strict as ParseHAState is for the
// watts, and every reason it gives for "no value" is a fixed text: nothing of the answer is repeated in it.
//
//   - `state` is text, as in ParseHAState: "unavailable", "unknown", an empty text and everything that is not a
//     plain decimal number are no value ("nan" and "inf" too).
//   - The unit is attributes.unit_of_measurement, converted to the kind's own: V or mV to volts, A or mA to
//     amperes, kWh, Wh or MWh to kWh. Any other unit is no value: a power (W, kW) is not an energy total, a
//     temperature is not a voltage. Without a unit the number counts as volts or as amperes only when
//     attributes.device_class is "voltage" or "current"; an energy total always needs its unit, because
//     nothing says whether such a number is Wh or kWh.
//   - A unit of the kind is not enough when the sensor says that it is something else: attributes.device_class,
//     when it is there, must be the kind's (kWh is also the unit of a battery's capacity, "energy_storage").
//   - The energy is a total: attributes.state_class, when it is there, must be "total" or "total_increasing". A
//     sensor without one is read; one that says "measurement" is not a counter.
//   - The number, converted, must be possible: 0 to MaxHAVolts, MaxHAAmps or MaxHAEnergyKWh. Every negative
//     number is no value (there is no noise below zero to allow for here, as there is for the watts); "-0" is
//     0. The range is checked on the converted number before it is rounded.
//   - maxAge > 0: the rule of ParseHAState, for this sensor's own times: last_reported, or last_updated when
//     the answer has no usable last_reported, at most maxAge before now; a state with neither is no value, a
//     time ahead of now is taken as fresh. Each sensor of a plug is judged by its own time: a voltage that has
//     not been written for an hour is old also when the watts are fresh.
//
// A number in the kind's own unit is passed on as it is; a converted one (mV, mA, Wh, MWh) is rounded to three
// places, as converted watts are.
func ParseHAValue(d map[string]any, kind HAKind, maxAge time.Duration, now time.Time) (float64, error) {
	k, known := haValues[kind]
	if !known {
		return 0, Errf("not a value that is read from a Home Assistant sensor")
	}
	state, isText := d["state"].(string)
	switch {
	case !isText || state == "":
		return 0, haNoValue(haValueNoState)
	case state == "unavailable":
		return 0, haNoValue(haValueUnavail)
	case state == "unknown":
		return 0, haNoValue(haValueUnknown)
	}
	v, ok := decimal(state)
	if !ok {
		return 0, haNoValue(haValueNotNumber)
	}
	attrs := obj(d["attributes"])
	unit, unitIsText := attrs["unit_of_measurement"].(string)
	if attrs["unit_of_measurement"] != nil && !unitIsText {
		return 0, haNoValue(k.badUnit)
	}
	class, isKind := haAttrText(attrs["device_class"], k.class)
	factor := 1.0
	switch {
	case unit == "": // no unit at all (not there, null or empty)
		if !k.unitless || class == "" || !isKind {
			return 0, haNoValue(k.noUnit)
		}
	default:
		if factor, ok = k.units[unit]; !ok {
			return 0, haNoValue(k.badUnit)
		}
		if !isKind {
			return 0, haNoValue(k.notKind)
		}
	}
	if k.total {
		if _, total := haAttrText(attrs["state_class"], "total", "total_increasing"); !total {
			return 0, haNoValue(haValueNotTotal)
		}
	}
	v *= factor
	if !(v >= 0 && v <= k.max) { // "not inside": an infinity from the conversion fails too
		return 0, haNoValue(k.outside)
	}
	switch {
	case v == 0:
		v = 0 // "-0" is zero
	case factor != 1:
		v = round(v, 3) // inside the range before, so inside it after
	}
	if maxAge > 0 {
		at, ok := haTime(d["last_reported"])
		if !ok {
			at, ok = haTime(d["last_updated"])
		}
		if !ok {
			return 0, haNoValue(haValueNoTime)
		}
		if now.Sub(at) > maxAge {
			return 0, haNoValue(haValueOld)
		}
	}
	return v, nil
}

// haNoValue is the error with one of the fixed reasons above, as it is written there.
func haNoValue(reason string) error { return &Error{Msg: reason} }

// haAttrText is an attribute that names a class (device_class, state_class): its text ("" when it is not
// there, null or empty), and whether it is acceptable: not there at all, or one of want. An attribute that is
// there and is not text (a number, a list) is never acceptable; its text is then "?".
func haAttrText(v any, want ...string) (text string, accepted bool) {
	s, isText := v.(string)
	switch {
	case v == nil || isText && s == "":
		return "", true
	case !isText:
		return "?", false
	}
	for _, w := range want {
		if s == w {
			return s, true
		}
	}
	return s, false
}
