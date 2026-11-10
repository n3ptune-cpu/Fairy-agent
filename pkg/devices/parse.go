package devices

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

// DpsField maps a reading to a Tuya data point and the scale that turns its raw integer into the unit.
type DpsField struct {
	DP    string  `json:"dp" yaml:"dp"`
	Scale float64 `json:"scale" yaml:"scale"`
}

// DefaultTuyaDPS is the data-point mapping of common metering plugs. DP 17 ("add_ele") is an increment, not a
// total, so it isn't mapped.
func DefaultTuyaDPS() map[string]DpsField {
	return map[string]DpsField{"power": {"19", 0.1}, "voltage": {"20", 0.1}, "current": {"18", 0.001}}
}

// ParseTuyaDPS turns a plug's data points into a Reading (default mapping when none is configured).
func ParseTuyaDPS(dps map[string]any, mapping map[string]DpsField) Reading {
	if len(mapping) == 0 {
		mapping = DefaultTuyaDPS()
	}
	get := func(field string) *float64 {
		m, ok := mapping[field]
		if !ok {
			return nil
		}
		raw := f64(dps[m.DP])
		if raw == nil {
			return nil
		}
		scale := m.Scale
		if scale == 0 {
			scale = 1
		}
		return numRound(*raw*scale, 3) // nil when the scaled value is impossible (or the scale is not a number)
	}
	return Reading{get("power"), get("voltage"), get("current"), get("energy_kwh_total")}
}
