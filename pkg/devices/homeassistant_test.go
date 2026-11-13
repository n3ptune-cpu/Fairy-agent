package devices

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// haNow is "now" for the state objects below.
var haNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// haState is a state object as Home Assistant's GET /api/states/<entity id> answers it (the REST API page's
// sample, as a plug's power sensor), decoded the way DecodeJSON hands it over. state and attributes are JSON
// text; times are the members after them, "" for the usual three (all a few seconds old).
func haState(t testing.TB, state, attributes, times string) map[string]any {
	t.Helper()
	if times == "" {
		times = `"last_changed":"2026-01-01T11:59:40.123456+00:00","last_reported":"2026-01-01T11:59:58.123456+00:00","last_updated":"2026-01-01T11:59:40.123456+00:00"`
	}
	text := `{"entity_id":"sensor.desk_plug_power","state":` + state + `,"attributes":` + attributes + `,` + times +
		`,"context":{"id":"ctx-1","parent_id":null,"user_id":null}}`
	var d map[string]any
	if err := json.Unmarshal([]byte(text), &d); err != nil {
		t.Fatalf("the test's own state object: %v\n%s", err, text)
	}
	return d
}

const (
	haNoState   = "home assistant: the sensor has no state"
	haUnavail   = "home assistant: the sensor is unavailable"
	haUnknown   = "home assistant: the sensor's state is unknown"
	haNotNumber = "home assistant: the sensor's state is not a number"
	haNoUnit    = "home assistant: the sensor has no unit and is not a power sensor"
	haBadUnit   = "home assistant: the sensor's unit is not a unit of power (W, mW, kW, MW)"
	haRange     = "home assistant: the sensor's value is not a possible power (0 to 100000 W)"
	haNoTime    = "home assistant: the sensor's state has no time (max_age_s is set)"
	haOld       = "home assistant: the sensor's value is older than max_age_s"
)

func haAttrs(unit string) string {
	return `{"state_class":"measurement","unit_of_measurement":"` + unit + `","device_class":"power","friendly_name":"Desk plug Power"}`
}

func TestParseHAStateUnitsAndNumbers(t *testing.T) {
	for name, c := range map[string]struct {
		state, attributes string
		watts             float64
		reason            string // "" = a reading
	}{
		// units
		"watts":                           {`"95.5"`, haAttrs("W"), 95.5, ""},
		"watts, a whole number":           {`"95"`, haAttrs("W"), 95, ""},
		"watts are passed on as they are": {`"12.3456789"`, haAttrs("W"), 12.3456789, ""},
		"zero":                            {`"0.0"`, haAttrs("W"), 0, ""},
		"minus zero is zero":              {`"-0"`, haAttrs("W"), 0, ""},
		"an exponent":                     {`"1.2e3"`, haAttrs("W"), 1200, ""},
		"kilowatts":                       {`"1.5"`, haAttrs("kW"), 1500, ""},
		"kilowatts, rounded":              {`"0.0234"`, haAttrs("kW"), 23.4, ""}, // 23.400000000000002 without the rounding
		"milliwatts":                      {`"23456"`, haAttrs("mW"), 23.456, ""},
		"milliwatts below a milliwatt":    {`"0.4"`, haAttrs("mW"), 0, ""},
		"megawatts":                       {`"0.001"`, haAttrs("MW"), 1000, ""},
		"the unit decides, not the class": {`"40"`, `{"unit_of_measurement":"W","device_class":"energy"}`, 40, ""},
		"only a unit":                     {`"40"`, `{"unit_of_measurement":"W"}`, 40, ""},
		// no unit
		"no unit, a power sensor":    {`"40"`, `{"device_class":"power"}`, 40, ""},
		"unit null, a power sensor":  {`"40"`, `{"unit_of_measurement":null,"device_class":"power"}`, 40, ""},
		"unit empty, a power sensor": {`"40"`, `{"unit_of_measurement":"","device_class":"power"}`, 40, ""},
		"no unit, no class":          {`"40"`, `{"friendly_name":"Desk plug"}`, 0, haNoUnit},
		"no unit, another class":     {`"40"`, `{"device_class":"energy"}`, 0, haNoUnit},
		"no unit, class in capitals": {`"40"`, `{"device_class":"Power"}`, 0, haNoUnit},
		"no unit, class not text":    {`"40"`, `{"device_class":["power"]}`, 0, haNoUnit},
		"no attributes":              {`"40"`, `{}`, 0, haNoUnit},
		"attributes null":            {`"40"`, `null`, 0, haNoUnit},
		"attributes not an object":   {`"40"`, `"W"`, 0, haNoUnit},
		"attributes a list":          {`"40"`, `[{"unit_of_measurement":"W"}]`, 0, haNoUnit},
		// other units
		"energy":                  {`"40"`, haAttrs("kWh"), 0, haBadUnit},
		"a temperature":           {`"40"`, haAttrs("°C"), 0, haBadUnit},
		"volts":                   {`"230"`, haAttrs("V"), 0, haBadUnit},
		"apparent power":          {`"40"`, haAttrs("VA"), 0, haBadUnit},
		"gigawatts":               {`"0.00004"`, haAttrs("GW"), 0, haBadUnit},
		"lowercase w":             {`"40"`, haAttrs("w"), 0, haBadUnit},
		"KW in capitals":          {`"40"`, haAttrs("KW"), 0, haBadUnit},
		"a unit with a space":     {`"40"`, haAttrs(" W"), 0, haBadUnit},
		"a unit that is a number": {`"40"`, `{"unit_of_measurement":5,"device_class":"power"}`, 0, haBadUnit},
		"a unit that is a list":   {`"40"`, `{"unit_of_measurement":["W"],"device_class":"power"}`, 0, haBadUnit},
		// states that are no number
		"unavailable":                {`"unavailable"`, haAttrs("W"), 0, haUnavail},
		"unknown":                    {`"unknown"`, haAttrs("W"), 0, haUnknown},
		"empty":                      {`""`, haAttrs("W"), 0, haNoState},
		"null":                       {`null`, haAttrs("W"), 0, haNoState},
		"a JSON number, not text":    {`95.5`, haAttrs("W"), 0, haNoState},
		"true":                       {`true`, haAttrs("W"), 0, haNoState},
		"an object":                  {`{"state":"95.5"}`, haAttrs("W"), 0, haNoState},
		"a word":                     {`"on"`, haAttrs("W"), 0, haNotNumber},
		"Unavailable in capitals":    {`"Unavailable"`, haAttrs("W"), 0, haNotNumber},
		"NaN":                        {`"NaN"`, haAttrs("W"), 0, haNotNumber},
		"nan":                        {`"nan"`, haAttrs("W"), 0, haNotNumber},
		"inf":                        {`"inf"`, haAttrs("W"), 0, haNotNumber},
		"+Inf":                       {`"+Inf"`, haAttrs("W"), 0, haNotNumber},
		"-Infinity":                  {`"-Infinity"`, haAttrs("W"), 0, haNotNumber},
		"too large for a float":      {`"1e400"`, haAttrs("W"), 0, haNotNumber},
		"hexadecimal":                {`"0x10"`, haAttrs("W"), 0, haNotNumber},
		"a hexadecimal float":        {`"0x1p4"`, haAttrs("W"), 0, haNotNumber},
		"digits with underscores":    {`"1_000"`, haAttrs("W"), 0, haNotNumber},
		"spaces around":              {`" 95.5 "`, haAttrs("W"), 0, haNotNumber},
		"a decimal comma":            {`"95,5"`, haAttrs("W"), 0, haNotNumber},
		"a number with its unit":     {`"95.5 W"`, haAttrs("W"), 0, haNotNumber},
		"two numbers":                {`"1.2.3"`, haAttrs("W"), 0, haNotNumber},
		"only a sign":                {`"-"`, haAttrs("W"), 0, haNotNumber},
		"a very long text of digits": {`"` + strings.Repeat("9", 65) + `"`, haAttrs("W"), 0, haNotNumber},
		// numbers that are no power of a plug
		"negative":                 {`"-5"`, haAttrs("W"), 0, haRange},
		"slightly negative":        {`"-0.001"`, haAttrs("W"), 0, haRange},
		"negative kilowatts":       {`"-0.2"`, haAttrs("kW"), 0, haRange},
		"exactly 100 kW":           {`"100000"`, haAttrs("W"), 100000, ""},
		"100 kW in megawatts":      {`"0.1"`, haAttrs("MW"), 100000, ""},
		"just over 100 kW":         {`"100000.1"`, haAttrs("W"), 0, haRange},
		"over 100 kW in kilowatts": {`"101"`, haAttrs("kW"), 0, haRange},
		"a meter's megawatts":      {`"3"`, haAttrs("MW"), 0, haRange},
		"1e12":                     {`"1e12"`, haAttrs("W"), 0, haRange},
		"1e308":                    {`"1e308"`, haAttrs("W"), 0, haNotNumber}, // not a number a device can have measured
		"1e308 megawatts":          {`"1e307"`, haAttrs("MW"), 0, haNotNumber},
		"a huge number, converted": {`"9e11"`, haAttrs("MW"), 0, haRange},
	} {
		r, err := ParseHAState(haState(t, c.state, c.attributes, ""), 0, haNow)
		if c.reason != "" {
			if err == nil || Describe(err) != c.reason || r != (Reading{}) {
				t.Errorf("%s: want %q, got %+v %v", name, c.reason, r, err)
			}
			continue
		}
		if err != nil || r.Watts == nil || *r.Watts != c.watts || math.Signbit(*r.Watts) {
			t.Errorf("%s: want %v W, got %s %v", name, c.watts, showWatts(r.Watts), err)
			continue
		}
		if r.Voltage != nil || r.Current != nil || r.EnergyKWh != nil {
			t.Errorf("%s: more than watts: %+v", name, r)
		}
		if _, err := json.Marshal(r); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func showWatts(p *float64) string {
	if p == nil {
		return "nothing"
	}
	b, _ := json.Marshal(*p)
	return string(b) + " W"
}

// max_age_s: the age is taken from last_reported, and from last_updated only when the answer has no usable
// last_reported. Without max_age_s the times are not looked at.
func TestParseHAStateAge(t *testing.T) {
	const limit = 15 * time.Minute
	at := func(ago time.Duration) string { return haNow.Add(-ago).Format("2006-01-02T15:04:05.000000-07:00") }
	both := func(reported, updated string) string {
		return `"last_changed":"2025-12-31T08:00:00+00:00","last_reported":"` + reported + `","last_updated":"` + updated + `"`
	}
	onlyUpdated := func(updated string) string {
		return `"last_changed":"2025-12-31T08:00:00+00:00","last_updated":"` + updated + `"`
	}
	for name, c := range map[string]struct {
		times  string
		maxAge time.Duration
		reason string
	}{
		"reported a moment ago":                             {both(at(2*time.Second), at(2*time.Second)), limit, ""},
		"reported ten minutes ago":                          {both(at(10*time.Minute), at(10*time.Minute)), limit, ""},
		"reported exactly at the limit":                     {both(at(limit), at(limit)), limit, ""},
		"reported a second over the limit":                  {both(at(limit+time.Second), at(time.Second)), limit, haOld},
		"reported sixteen minutes ago":                      {both(at(16*time.Minute), at(16*time.Minute)), limit, haOld},
		"reported now, value unchanged for a day":           {both(at(5*time.Second), at(24*time.Hour)), limit, ""},
		"reported long ago, last_updated is not asked":      {both(at(time.Hour), at(time.Second)), limit, haOld},
		"reported in another time zone":                     {both("2026-01-01T13:55:00+02:00", at(time.Hour)), limit, ""},
		"reported with a Z":                                 {both("2026-01-01T11:55:00Z", at(time.Hour)), limit, ""},
		"reported ahead of this machine's clock":            {both(at(-3*time.Minute), at(time.Hour)), limit, ""},
		"no last_reported, updated a minute ago":            {onlyUpdated(at(time.Minute)), limit, ""},
		"no last_reported, updated an hour ago":             {onlyUpdated(at(time.Hour)), limit, haOld},
		"last_reported null, updated a minute ago":          {`"last_reported":null,"last_updated":"` + at(time.Minute) + `"`, limit, ""},
		"last_reported empty, updated an hour ago":          {both("", at(time.Hour)), limit, haOld},
		"last_reported not a time, updated a minute ago":    {both("yesterday", at(time.Minute)), limit, ""},
		"last_reported without a zone, updated an hour ago": {both("2026-01-01T11:59:58", at(time.Hour)), limit, haOld},
		"last_reported a number, updated a minute ago":      {`"last_reported":1767268798,"last_updated":"` + at(time.Minute) + `"`, limit, ""},
		"neither time":                                 {`"last_changed":"` + at(time.Second) + `"`, limit, haNoTime},
		"neither is a time":                            {both("soon", "later"), limit, haNoTime},
		"max_age_s off: a value from last year":        {both("2025-01-01T00:00:00+00:00", "2025-01-01T00:00:00+00:00"), 0, ""},
		"max_age_s off: no times at all":               {`"last_changed":null`, 0, ""},
		"max_age_s off: times that are none":           {both("soon", "later"), 0, ""},
		"a negative max age is off":                    {both(at(time.Hour), at(time.Hour)), -time.Second, ""},
		"one second allowed, reported two seconds ago": {both(at(2*time.Second), at(2*time.Second)), time.Second, haOld},
		"a week allowed, reported six days ago":        {both(at(6*24*time.Hour), at(6*24*time.Hour)), 7 * 24 * time.Hour, ""},
	} {
		r, err := ParseHAState(haState(t, `"95.5"`, haAttrs("W"), c.times), c.maxAge, haNow)
		if c.reason != "" {
			if err == nil || Describe(err) != c.reason || r != (Reading{}) {
				t.Errorf("%s: want %q, got %+v %v", name, c.reason, r, err)
			}
			continue
		}
		if err != nil || r.Watts == nil || *r.Watts != 95.5 {
			t.Errorf("%s: want 95.5 W, got %s %v", name, showWatts(r.Watts), err)
		}
	}
	// what is wrong with the value is said before its age: an unavailable plug is "unavailable", not "old"
	old := both(at(time.Hour), at(time.Hour))
	for state, want := range map[string]string{`"unavailable"`: haUnavail, `"unknown"`: haUnknown, `"on"`: haNotNumber, `"-5"`: haRange} {
		if _, err := ParseHAState(haState(t, state, haAttrs("W"), old), limit, haNow); err == nil || Describe(err) != want {
			t.Errorf("state %s, an hour old: want %q, got %v", state, want, err)
		}
	}
}

// Nothing of the answer is in a reason: a state object can hold any text (a friendly name, a state somebody
// set by hand), and the reasons are shown in the panel.
func TestParseHAStateReasonsAreFixedWords(t *testing.T) {
	const marker = "TEXT-FROM-THE-ANSWER"
	fixed := map[string]bool{haNoState: true, haUnavail: true, haUnknown: true, haNotNumber: true, haNoUnit: true, haBadUnit: true,
		haRange: true, haNoTime: true, haOld: true}
	for name, d := range map[string]map[string]any{
		"state":  haState(t, `"`+marker+`"`, haAttrs("W"), ""),
		"unit":   haState(t, `"40"`, haAttrs(marker), ""),
		"class":  haState(t, `"40"`, `{"device_class":"`+marker+`"}`, ""),
		"time":   haState(t, `"40"`, haAttrs("W"), `"last_reported":"`+marker+`","last_updated":"`+marker+`"`),
		"old":    haState(t, `"40"`, `{"unit_of_measurement":"W","friendly_name":"`+marker+`"}`, `"last_reported":"2020-01-01T00:00:00+00:00"`),
		"number": haState(t, `"-40"`, `{"unit_of_measurement":"W","friendly_name":"`+marker+`"}`, ""),
		"nil":    nil,
		"empty":  {},
	} {
		_, err := ParseHAState(d, time.Minute, haNow)
		if err == nil || !fixed[err.Error()] || !fixed[Describe(err)] || strings.Contains(err.Error(), marker) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
