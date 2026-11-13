package devices

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// The fixed reasons of ParseHAValue, as the agent's row shows them.
const (
	hvNoState   = "the sensor has no state"
	hvUnavail   = "the sensor is unavailable"
	hvUnknown   = "the sensor's state is unknown"
	hvNotNumber = "the sensor's state is not a number"
	hvNotTotal  = "the sensor is not a total (its state_class is not total or total_increasing)"
	hvNoTime    = "the sensor's state has no time (max_age_s is set)"
	hvOld       = "the sensor's value is older than max_age_s"

	hvVoltNoUnit  = "the sensor has no unit and is not a voltage sensor"
	hvVoltBadUnit = "the sensor's unit is not a unit of voltage (V, mV)"
	hvVoltKind    = "the sensor is not a voltage sensor"
	hvVoltRange   = "the sensor's value is not a possible voltage (0 to 1000 V)"

	hvAmpNoUnit  = "the sensor has no unit and is not a current sensor"
	hvAmpBadUnit = "the sensor's unit is not a unit of current (A, mA)"
	hvAmpKind    = "the sensor is not a current sensor"
	hvAmpRange   = "the sensor's value is not a possible current (0 to 1000 A)"

	hvEnergyNoUnit  = "the sensor has no unit (an energy total needs kWh, Wh or MWh)"
	hvEnergyBadUnit = "the sensor's unit is not a unit of energy (kWh, Wh, MWh)"
	hvEnergyKind    = "the sensor is not an energy sensor"
	hvEnergyRange   = "the sensor's value is not a possible energy total (0 to 1e9 kWh)"
)

// hvFixed are all of them: a reason that is not in this list is not a fixed one.
var hvFixed = map[string]bool{hvNoState: true, hvUnavail: true, hvUnknown: true, hvNotNumber: true, hvNotTotal: true, hvNoTime: true,
	hvOld: true, hvVoltNoUnit: true, hvVoltBadUnit: true, hvVoltKind: true, hvVoltRange: true, hvAmpNoUnit: true, hvAmpBadUnit: true,
	hvAmpKind: true, hvAmpRange: true, hvEnergyNoUnit: true, hvEnergyBadUnit: true, hvEnergyKind: true, hvEnergyRange: true}

// hvAttrs are a sensor's attributes as Home Assistant sends them for a plug's voltage, current or energy.
func hvAttrs(unit, class, stateClass string) string {
	return `{"state_class":"` + stateClass + `","unit_of_measurement":"` + unit + `","device_class":"` + class + `","friendly_name":"Lab plug"}`
}

func volts(unit string) string  { return hvAttrs(unit, "voltage", "measurement") }
func amps(unit string) string   { return hvAttrs(unit, "current", "measurement") }
func energy(unit string) string { return hvAttrs(unit, "energy", "total_increasing") }

type hvCase struct {
	state, attributes string
	want              float64
	reason            string // "" = a value
}

func runHAValueCases(t *testing.T, kind HAKind, cases map[string]hvCase) {
	t.Helper()
	for name, c := range cases {
		v, err := ParseHAValue(haState(t, c.state, c.attributes, ""), kind, 0, haNow)
		if c.reason != "" {
			if !hvFixed[c.reason] {
				t.Fatalf("%s: the test's own reason is not in the list: %q", name, c.reason)
			}
			if err == nil || Describe(err) != c.reason || err.Error() != c.reason || v != 0 {
				t.Errorf("%s: want %q, got %v %v", name, c.reason, v, err)
			}
			continue
		}
		if err != nil || v != c.want || math.Signbit(v) {
			t.Errorf("%s: want %v, got %v %v", name, c.want, v, err)
			continue
		}
		if _, err := json.Marshal(v); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Volts: V as it is, mV converted and rounded to three places. 0 to 1000 V, nothing negative.
func TestParseHAValueVoltage(t *testing.T) {
	runHAValueCases(t, HAVoltage, map[string]hvCase{
		// units
		"volts":                           {`"229.8"`, volts("V"), 229.8, ""},
		"volts, a whole number":           {`"230"`, volts("V"), 230, ""},
		"volts are passed on as they are": {`"229.87654321"`, volts("V"), 229.87654321, ""},
		"millivolts":                      {`"229800"`, volts("mV"), 229.8, ""},
		"millivolts, rounded":             {`"229876.5"`, volts("mV"), 229.877, ""}, // 229.87650000000002 without the rounding
		"millivolts below a millivolt":    {`"0.4"`, volts("mV"), 0, ""},
		"an exponent":                     {`"2.3e2"`, volts("V"), 230, ""},
		"zero":                            {`"0.0"`, volts("V"), 0, ""},
		"minus zero is zero":              {`"-0"`, volts("V"), 0, ""},
		"minus zero in millivolts":        {`"-0.0"`, volts("mV"), 0, ""},
		"only a unit":                     {`"230"`, `{"unit_of_measurement":"V"}`, 230, ""},
		"a unit, class null":              {`"230"`, `{"unit_of_measurement":"V","device_class":null}`, 230, ""},
		"a unit, class empty":             {`"230"`, `{"unit_of_measurement":"V","device_class":""}`, 230, ""},
		// a unit of voltage, but the sensor says it is something else
		"volts of another class":   {`"230"`, hvAttrs("V", "power", "measurement"), 0, hvVoltKind},
		"class in capitals":        {`"230"`, hvAttrs("V", "Voltage", "measurement"), 0, hvVoltKind},
		"class not text":           {`"230"`, `{"unit_of_measurement":"V","device_class":["voltage"]}`, 0, hvVoltKind},
		"class a number":           {`"230"`, `{"unit_of_measurement":"mV","device_class":7}`, 0, hvVoltKind},
		"the state class is free":  {`"230"`, hvAttrs("V", "voltage", "total"), 230, ""},
		"the state class is free2": {`"230"`, `{"unit_of_measurement":"V","state_class":7}`, 230, ""},
		// no unit
		"no unit, a voltage sensor":    {`"230"`, `{"device_class":"voltage"}`, 230, ""},
		"unit null, a voltage sensor":  {`"230"`, `{"unit_of_measurement":null,"device_class":"voltage"}`, 230, ""},
		"unit empty, a voltage sensor": {`"230"`, `{"unit_of_measurement":"","device_class":"voltage"}`, 230, ""},
		"no unit, no class":            {`"230"`, `{"friendly_name":"Lab plug"}`, 0, hvVoltNoUnit},
		"no unit, another class":       {`"230"`, `{"device_class":"current"}`, 0, hvVoltNoUnit},
		"no unit, class not text":      {`"230"`, `{"device_class":["voltage"]}`, 0, hvVoltNoUnit},
		"no unit, class empty":         {`"230"`, `{"device_class":""}`, 0, hvVoltNoUnit},
		"no attributes":                {`"230"`, `{}`, 0, hvVoltNoUnit},
		"attributes null":              {`"230"`, `null`, 0, hvVoltNoUnit},
		"attributes a list":            {`"230"`, `[{"unit_of_measurement":"V"}]`, 0, hvVoltNoUnit},
		// other units
		"watts":                   {`"230"`, volts("W"), 0, hvVoltBadUnit},
		"amperes":                 {`"230"`, volts("A"), 0, hvVoltBadUnit},
		"kilovolts":               {`"0.23"`, volts("kV"), 0, hvVoltBadUnit},
		"microvolts":              {`"230000000"`, volts("µV"), 0, hvVoltBadUnit},
		"lowercase v":             {`"230"`, volts("v"), 0, hvVoltBadUnit},
		"MV in capitals":          {`"230"`, volts("MV"), 0, hvVoltBadUnit},
		"a unit with a space":     {`"230"`, volts("V "), 0, hvVoltBadUnit},
		"a unit that is a number": {`"230"`, `{"unit_of_measurement":5,"device_class":"voltage"}`, 0, hvVoltBadUnit},
		"a unit that is a list":   {`"230"`, `{"unit_of_measurement":["V"],"device_class":"voltage"}`, 0, hvVoltBadUnit},
		// states that are no number
		"unavailable":             {`"unavailable"`, volts("V"), 0, hvUnavail},
		"unknown":                 {`"unknown"`, volts("V"), 0, hvUnknown},
		"empty":                   {`""`, volts("V"), 0, hvNoState},
		"null":                    {`null`, volts("V"), 0, hvNoState},
		"a JSON number, not text": {`229.8`, volts("V"), 0, hvNoState},
		"a word":                  {`"on"`, volts("V"), 0, hvNotNumber},
		"NaN":                     {`"NaN"`, volts("V"), 0, hvNotNumber},
		"inf":                     {`"inf"`, volts("V"), 0, hvNotNumber},
		"hexadecimal":             {`"0xE6"`, volts("V"), 0, hvNotNumber},
		"a number with its unit":  {`"230 V"`, volts("V"), 0, hvNotNumber},
		"a decimal comma":         {`"229,8"`, volts("V"), 0, hvNotNumber},
		"too large for a float":   {`"1e400"`, volts("V"), 0, hvNotNumber},
		// the range: 0 to 1000 V, checked before the rounding
		"exactly 1000 V":                  {`"1000"`, volts("V"), 1000, ""},
		"1000 V in millivolts":            {`"1000000"`, volts("mV"), 1000, ""},
		"just over 1000 V":                {`"1000.1"`, volts("V"), 0, hvVoltRange},
		"a hair over 1000 V":              {`"1000.0000001"`, volts("V"), 0, hvVoltRange},
		"a hair over, in millivolts":      {`"1000000.4"`, volts("mV"), 0, hvVoltRange}, // rounded to three places: 1000
		"a hair under, in millivolts":     {`"999999.6"`, volts("mV"), 1000, ""},        // inside the range, then rounded
		"negative":                        {`"-230"`, volts("V"), 0, hvVoltRange},
		"a little below zero":             {`"-0.001"`, volts("V"), 0, hvVoltRange}, // no noise is allowed for here
		"a little below zero, millivolts": {`"-0.4"`, volts("mV"), 0, hvVoltRange},  // -0 when rounded first
		"1e12":                            {`"1e12"`, volts("V"), 0, hvVoltRange},
		"a huge number, converted":        {`"1e308"`, volts("mV"), 0, hvNotNumber}, // not a number a device can have measured
	})
}

// Amperes: A as it is, mA converted and rounded to three places. 0 to 1000 A, nothing negative.
func TestParseHAValueCurrent(t *testing.T) {
	runHAValueCases(t, HACurrent, map[string]hvCase{
		"amperes":                      {`"0.41"`, amps("A"), 0.41, ""},
		"amperes, passed on as given":  {`"0.4123456"`, amps("A"), 0.4123456, ""},
		"milliamperes":                 {`"410"`, amps("mA"), 0.41, ""},
		"milliamperes, rounded":        {`"412.3456"`, amps("mA"), 0.412, ""},
		"milliamperes, rounded up":     {`"23.5"`, amps("mA"), 0.024, ""}, // 0.0235 A
		"zero":                         {`"0"`, amps("A"), 0, ""},
		"minus zero is zero":           {`"-0.0"`, amps("mA"), 0, ""},
		"only a unit":                  {`"3"`, `{"unit_of_measurement":"A"}`, 3, ""},
		"no unit, a current sensor":    {`"3"`, `{"device_class":"current"}`, 3, ""},
		"no unit, a voltage sensor":    {`"3"`, `{"device_class":"voltage"}`, 0, hvAmpNoUnit},
		"no unit, no class":            {`"3"`, `{}`, 0, hvAmpNoUnit},
		"amperes of another class":     {`"3"`, hvAttrs("A", "voltage", "measurement"), 0, hvAmpKind},
		"volts":                        {`"3"`, amps("V"), 0, hvAmpBadUnit},
		"watts":                        {`"3"`, amps("W"), 0, hvAmpBadUnit},
		"kiloamperes":                  {`"0.003"`, amps("kA"), 0, hvAmpBadUnit},
		"lowercase a":                  {`"3"`, amps("a"), 0, hvAmpBadUnit},
		"MA in capitals":               {`"3"`, amps("MA"), 0, hvAmpBadUnit},
		"a unit that is a number":      {`"3"`, `{"unit_of_measurement":1}`, 0, hvAmpBadUnit},
		"unavailable":                  {`"unavailable"`, amps("A"), 0, hvUnavail},
		"unknown":                      {`"unknown"`, amps("A"), 0, hvUnknown},
		"empty":                        {`""`, amps("A"), 0, hvNoState},
		"a word":                       {`"off"`, amps("A"), 0, hvNotNumber},
		"exactly 1000 A":               {`"1000"`, amps("A"), 1000, ""},
		"1000 A in milliamperes":       {`"1e6"`, amps("mA"), 1000, ""},
		"just over 1000 A":             {`"1000.01"`, amps("A"), 0, hvAmpRange},
		"a hair over, in milliamperes": {`"1000000.4"`, amps("mA"), 0, hvAmpRange},
		"negative (feeding in)":        {`"-2.5"`, amps("A"), 0, hvAmpRange},
		"negative milliamperes":        {`"-1"`, amps("mA"), 0, hvAmpRange},
	})
}

// The energy total in kWh: kWh as it is, Wh and MWh converted and rounded to three places. A unit of power is
// refused, a sensor that is not a total too. 0 to 1e9 kWh, nothing negative.
func TestParseHAValueEnergy(t *testing.T) {
	runHAValueCases(t, HAEnergy, map[string]hvCase{
		// units
		"kilowatt hours":                 {`"12.5"`, energy("kWh"), 12.5, ""},
		"kWh are passed on as they are":  {`"1234.56789"`, energy("kWh"), 1234.56789, ""},
		"watt hours":                     {`"12500"`, energy("Wh"), 12.5, ""},
		"watt hours, rounded":            {`"12345.6"`, energy("Wh"), 12.346, ""},
		"watt hours below a watt hour":   {`"0.4"`, energy("Wh"), 0, ""},
		"megawatt hours":                 {`"0.0125"`, energy("MWh"), 12.5, ""},
		"megawatt hours, rounded":        {`"1.2345678"`, energy("MWh"), 1234.568, ""},
		"zero, a new plug":               {`"0"`, energy("kWh"), 0, ""},
		"minus zero is zero":             {`"-0.0"`, energy("Wh"), 0, ""},
		"only a unit":                    {`"12.5"`, `{"unit_of_measurement":"kWh"}`, 12.5, ""},
		"a total":                        {`"12.5"`, hvAttrs("kWh", "energy", "total"), 12.5, ""},
		"a total that only grows":        {`"12.5"`, hvAttrs("kWh", "energy", "total_increasing"), 12.5, ""},
		"no state class":                 {`"12.5"`, `{"unit_of_measurement":"kWh","device_class":"energy"}`, 12.5, ""},
		"state class null":               {`"12.5"`, `{"unit_of_measurement":"kWh","device_class":"energy","state_class":null}`, 12.5, ""},
		"state class empty":              {`"12.5"`, `{"unit_of_measurement":"Wh","state_class":""}`, 0.013, ""},
		"a measurement is not a total":   {`"12.5"`, hvAttrs("kWh", "energy", "measurement"), 0, hvNotTotal},
		"state class in capitals":        {`"12.5"`, hvAttrs("kWh", "energy", "Total"), 0, hvNotTotal},
		"state class a number":           {`"12.5"`, `{"unit_of_measurement":"kWh","state_class":1}`, 0, hvNotTotal},
		"state class a list":             {`"12.5"`, `{"unit_of_measurement":"kWh","state_class":["total"]}`, 0, hvNotTotal},
		"a battery's capacity":           {`"12.5"`, hvAttrs("kWh", "energy_storage", "measurement"), 0, hvEnergyKind},
		"kWh of another class, a total":  {`"12.5"`, hvAttrs("kWh", "power", "total"), 0, hvEnergyKind},
		"class not text":                 {`"12.5"`, `{"unit_of_measurement":"kWh","device_class":{"a":1}}`, 0, hvEnergyKind},
		"the wrong class before a total": {`"12.5"`, hvAttrs("Wh", "gas", "measurement"), 0, hvEnergyKind},
		// no unit: never, whatever the class
		"no unit, an energy sensor": {`"12.5"`, `{"device_class":"energy","state_class":"total_increasing"}`, 0, hvEnergyNoUnit},
		"unit null":                 {`"12.5"`, `{"unit_of_measurement":null,"device_class":"energy"}`, 0, hvEnergyNoUnit},
		"unit empty":                {`"12.5"`, `{"unit_of_measurement":"","device_class":"energy"}`, 0, hvEnergyNoUnit},
		"no attributes":             {`"12.5"`, `{}`, 0, hvEnergyNoUnit},
		// units of power and other units
		"watts":                   {`"12.5"`, energy("W"), 0, hvEnergyBadUnit},
		"kilowatts":               {`"12.5"`, energy("kW"), 0, hvEnergyBadUnit},
		"milliwatts":              {`"12.5"`, energy("mW"), 0, hvEnergyBadUnit},
		"megawatts":               {`"12.5"`, energy("MW"), 0, hvEnergyBadUnit},
		"a power sensor":          {`"95.5"`, hvAttrs("W", "power", "measurement"), 0, hvEnergyBadUnit},
		"gigawatt hours":          {`"0.0000125"`, energy("GWh"), 0, hvEnergyBadUnit},
		"joules":                  {`"45000000"`, energy("J"), 0, hvEnergyBadUnit},
		"lowercase kwh":           {`"12.5"`, energy("kwh"), 0, hvEnergyBadUnit},
		"KWH in capitals":         {`"12.5"`, energy("KWH"), 0, hvEnergyBadUnit},
		"mWh, not MWh":            {`"12.5"`, energy("mWh"), 0, hvEnergyBadUnit},
		"a unit that is a number": {`"12.5"`, `{"unit_of_measurement":3,"device_class":"energy"}`, 0, hvEnergyBadUnit},
		// states that are no number
		"unavailable": {`"unavailable"`, energy("kWh"), 0, hvUnavail},
		"unknown":     {`"unknown"`, energy("kWh"), 0, hvUnknown},
		"empty":       {`""`, energy("kWh"), 0, hvNoState},
		"a word":      {`"none"`, energy("kWh"), 0, hvNotNumber},
		"nan":         {`"nan"`, energy("kWh"), 0, hvNotNumber},
		// the range: 0 to 1e9 kWh, checked before the rounding
		"exactly 1e9 kWh":               {`"1000000000"`, energy("kWh"), 1e9, ""},
		"1e9 kWh in megawatt hours":     {`"1000000"`, energy("MWh"), 1e9, ""},
		"1e9 kWh in watt hours":         {`"1e12"`, energy("Wh"), 1e9, ""},
		"just over 1e9 kWh":             {`"1000000000.5"`, energy("kWh"), 0, hvEnergyRange},
		"a hair over, in megawatt hrs":  {`"1000000.0000004"`, energy("MWh"), 0, hvEnergyRange}, // rounded to three places: 1e9
		"over, in megawatt hours":       {`"1000000.001"`, energy("MWh"), 0, hvEnergyRange},
		"a hair under, in megawatt hrs": {`"999999.9999996"`, energy("MWh"), 1e9, ""},        // inside the range, then rounded
		"over, in watt hours":           {`"1000000000000.4"`, energy("Wh"), 0, hvNotNumber}, // over what any device can have measured
		"negative":                      {`"-1"`, energy("kWh"), 0, hvEnergyRange},
		"a little below zero":           {`"-0.0004"`, energy("kWh"), 0, hvEnergyRange},
		"a little below zero, in Wh":    {`"-0.4"`, energy("Wh"), 0, hvEnergyRange}, // -0 when rounded first
		"a huge number of megawatt hrs": {`"9e11"`, energy("MWh"), 0, hvEnergyRange},
	})
}

// A kind that is not one of the three is no value, with a fixed word.
func TestParseHAValueUnknownKind(t *testing.T) {
	for _, kind := range []HAKind{0, -1, 4, 99} {
		v, err := ParseHAValue(haState(t, `"230"`, volts("V"), ""), kind, 0, haNow)
		if err == nil || v != 0 || Describe(err) != "not a value that is read from a Home Assistant sensor" {
			t.Errorf("kind %d: %v %v", kind, v, err)
		}
	}
}

// max_age_s is judged for every sensor by its own times, by the rule of the watts: the same state object's
// times give the same verdict from ParseHAState and from ParseHAValue, for each kind.
func TestParseHAValueAgeIsTheRuleOfTheWatts(t *testing.T) {
	const limit = 15 * time.Minute
	at := func(ago time.Duration) string { return haNow.Add(-ago).Format("2006-01-02T15:04:05.000000-07:00") }
	both := func(reported, updated string) string {
		return `"last_changed":"2025-12-31T08:00:00+00:00","last_reported":"` + reported + `","last_updated":"` + updated + `"`
	}
	onlyUpdated := func(updated string) string { return `"last_updated":"` + updated + `"` }
	kinds := map[string]struct {
		kind  HAKind
		state string
		attrs string
		want  float64
	}{"voltage": {HAVoltage, `"229.8"`, volts("V"), 229.8}, "current": {HACurrent, `"410"`, amps("mA"), 0.41},
		"energy": {HAEnergy, `"12500"`, energy("Wh"), 12.5}}
	for name, c := range map[string]struct {
		times  string
		maxAge time.Duration
		reason string
	}{
		"reported a moment ago":                          {both(at(2*time.Second), at(2*time.Second)), limit, ""},
		"reported exactly at the limit":                  {both(at(limit), at(limit)), limit, ""},
		"reported a second over the limit":               {both(at(limit+time.Second), at(time.Second)), limit, hvOld},
		"reported now, value unchanged for a day":        {both(at(5*time.Second), at(24*time.Hour)), limit, ""},
		"reported long ago, last_updated is not asked":   {both(at(time.Hour), at(time.Second)), limit, hvOld},
		"reported ahead of this machine's clock":         {both(at(-3*time.Minute), at(time.Hour)), limit, ""},
		"no last_reported, updated a minute ago":         {onlyUpdated(at(time.Minute)), limit, ""},
		"no last_reported, updated an hour ago":          {onlyUpdated(at(time.Hour)), limit, hvOld},
		"last_reported not a time, updated a minute ago": {both("yesterday", at(time.Minute)), limit, ""},
		"last_reported empty, updated an hour ago":       {both("", at(time.Hour)), limit, hvOld},
		"neither time":                                 {`"last_changed":"` + at(time.Second) + `"`, limit, hvNoTime},
		"neither is a time":                            {both("soon", "later"), limit, hvNoTime},
		"max_age_s off: a value from last year":        {both("2025-01-01T00:00:00+00:00", "2025-01-01T00:00:00+00:00"), 0, ""},
		"max_age_s off: no times at all":               {`"last_changed":null`, 0, ""},
		"a negative max age is off":                    {both(at(time.Hour), at(time.Hour)), -time.Second, ""},
		"one second allowed, reported two seconds ago": {both(at(2*time.Second), at(2*time.Second)), time.Second, hvOld},
	} {
		_, wattsErr := ParseHAState(haState(t, `"95.5"`, haAttrs("W"), c.times), c.maxAge, haNow)
		wattsSay := map[string]string{"": "", hvNoTime: haNoTime, hvOld: haOld}[c.reason]
		if Describe(wattsErr) != wattsSay {
			t.Errorf("%s: the watts of a state with these times: %v (the rule this test compares with has changed)", name, wattsErr)
		}
		for kindName, k := range kinds {
			v, err := ParseHAValue(haState(t, k.state, k.attrs, c.times), k.kind, c.maxAge, haNow)
			if c.reason != "" {
				if err == nil || Describe(err) != c.reason || v != 0 {
					t.Errorf("%s, %s: want %q, got %v %v", name, kindName, c.reason, v, err)
				}
				continue
			}
			if err != nil || v != k.want {
				t.Errorf("%s, %s: want %v, got %v %v", name, kindName, k.want, v, err)
			}
		}
	}
	// what is wrong with the value is said before its age
	old := both(at(time.Hour), at(time.Hour))
	for state, want := range map[string]string{`"unavailable"`: hvUnavail, `"unknown"`: hvUnknown, `"on"`: hvNotNumber, `"-5"`: hvVoltRange} {
		if _, err := ParseHAValue(haState(t, state, volts("V"), old), HAVoltage, limit, haNow); err == nil || Describe(err) != want {
			t.Errorf("state %s, an hour old: want %q, got %v", state, want, err)
		}
	}
	if _, err := ParseHAValue(haState(t, `"12"`, hvAttrs("kWh", "energy", "measurement"), old), HAEnergy, limit, haNow); err == nil || Describe(err) != hvNotTotal {
		t.Errorf("a measurement, an hour old: %v", err)
	}
}

// Nothing of the answer is in a reason, for any kind: a state object can hold any text, and the reasons are
// sent to the panel.
func TestParseHAValueReasonsAreFixedWords(t *testing.T) {
	const marker = "TEXT-FROM-THE-ANSWER"
	for kindName, kind := range map[string]HAKind{"voltage": HAVoltage, "current": HACurrent, "energy": HAEnergy, "no kind": 0} {
		for name, d := range map[string]map[string]any{
			"state":       haState(t, `"`+marker+`"`, volts("V"), ""),
			"unit":        haState(t, `"40"`, hvAttrs(marker, "", ""), ""),
			"class":       haState(t, `"40"`, `{"device_class":"`+marker+`"}`, ""),
			"class, unit": haState(t, `"40"`, `{"unit_of_measurement":"V","device_class":"`+marker+`"}`, ""),
			"A, class":    haState(t, `"40"`, `{"unit_of_measurement":"A","device_class":"`+marker+`"}`, ""),
			"kWh, class":  haState(t, `"40"`, `{"unit_of_measurement":"kWh","device_class":"`+marker+`"}`, ""),
			"state class": haState(t, `"40"`, `{"unit_of_measurement":"kWh","state_class":"`+marker+`"}`, ""),
			"time":        haState(t, `"40"`, `{"unit_of_measurement":"V","friendly_name":"`+marker+`"}`, `"last_reported":"`+marker+`","last_updated":"`+marker+`"`),
			"time, A":     haState(t, `"40"`, `{"unit_of_measurement":"A"}`, `"last_reported":"`+marker+`"`),
			"time, kWh":   haState(t, `"40"`, `{"unit_of_measurement":"kWh"}`, `"last_updated":"`+marker+`"`),
			"old":         haState(t, `"40"`, `{"unit_of_measurement":"V","friendly_name":"`+marker+`"}`, `"last_reported":"2020-01-01T00:00:00+00:00"`),
			"number":      haState(t, `"-40"`, `{"unit_of_measurement":"V","friendly_name":"`+marker+`"}`, ""),
			"a member":    {marker: marker, "state": marker},
			"nil":         nil,
			"empty":       {},
		} {
			v, err := ParseHAValue(d, kind, time.Minute, haNow)
			if kind == 0 {
				if err == nil || strings.Contains(err.Error(), marker) {
					t.Errorf("%s, %s: %v", kindName, name, err)
				}
				continue
			}
			if err == nil || v != 0 || !hvFixed[err.Error()] || !hvFixed[Describe(err)] || strings.Contains(err.Error(), marker) {
				t.Errorf("%s, %s: %v %v", kindName, name, v, err)
			}
		}
	}
	for reason := range hvFixed {
		if len(reason) > 80 || strings.ContainsAny(reason, "\"{}[]%\n") || strings.Contains(reason, "sensor.") {
			t.Errorf("not a short plain text: %q", reason)
		}
	}
}

// The watts are read as they were: ParseHAState gives no volts, amperes or energy, whatever the state object
// of a power sensor holds besides its state.
func TestParseHAStateStillReadsOnlyWatts(t *testing.T) {
	d := haState(t, `"95.5"`, `{"unit_of_measurement":"W","device_class":"power","voltage":229.8,"current":0.41,"energy":12.5}`, "")
	r, err := ParseHAState(d, 0, haNow)
	if err != nil || r.Watts == nil || *r.Watts != 95.5 || r.Voltage != nil || r.Current != nil || r.EnergyKWh != nil {
		t.Errorf("%+v %v", r, err)
	}
}
