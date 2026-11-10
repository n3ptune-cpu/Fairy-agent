// Package devices is the power-device and UPS protocol code shared by the panel and the agent (agent-side devices on
// a friend's LAN use the same code). Errors are safe to show: they never contain credentials or URLs.
package devices

import (
	"encoding/json"
	"fmt"
	"math"
)

// Error is a failure whose message is safe to show in the API.
type Error struct{ Msg string }

// Error returns the message.
func (e *Error) Error() string { return e.Msg }

// Errf returns an *Error with a formatted message. Never put credentials, URLs or headers into it.
func Errf(f string, a ...any) error { return &Error{Msg: fmt.Sprintf(f, a...)} }

// Safe marks err's message as safe to show in the API, for errors whose text is known to hold no secrets
// (configutil.EnvSecret, tuya). Without it, Describe reduces unknown errors to a generic word.
func Safe(err error) error { return &Error{Msg: err.Error()} }

// Reading is one power measurement: watts, volts, amps, kWh total (nil = unknown).
type Reading struct {
	Watts, Voltage, Current, EnergyKWh *float64
}

// MaxMagnitude is the largest absolute value Fairy accepts from a device, whatever the unit (watts, volts, amps,
// kWh, percent, seconds). Nothing a plug, a UPS or a BMC measures comes near it, and numbers of this size can
// still be added, scaled and rounded without leaving what a JSON number can hold.
const MaxMagnitude = 1e12

// Finite reports whether v is a number a device can have measured: not NaN, not an infinity and at most
// MaxMagnitude either way. Everything read from a device passes this check where it enters, and again after
// every sum, scaling and rounding: two possible numbers can add up to an impossible one, and one impossible
// number is enough to make a whole JSON answer fail (encoding/json refuses NaN and Inf).
func Finite(v float64) bool { return v >= -MaxMagnitude && v <= MaxMagnitude } // false for NaN: it compares false

// Num returns p when it points at a Finite number, nil ("unknown") otherwise.
func Num(p *float64) *float64 {
	if p == nil || !Finite(*p) {
		return nil
	}
	return p
}

// NumIn returns p when it points at a number from lo to hi (inclusive), nil ("unknown") otherwise.
func NumIn(p *float64, lo, hi float64) *float64 {
	if p == nil || !Finite(*p) || !(*p >= lo && *p <= hi) {
		return nil
	}
	return p
}

// isNumber reports whether a decoded JSON value is a number at all (possible or not).
func isNumber(v any) bool {
	switch v.(type) {
	case float64, int, int64, json.Number:
		return true
	}
	return false
}

// f64 is the number in a decoded JSON value: nil when it is not a number or not a Finite one.
func f64(v any) *float64 {
	switch x := v.(type) {
	case float64:
		return Num(&x)
	case int:
		f := float64(x)
		return Num(&f)
	case int64:
		f := float64(x)
		return Num(&f)
	case json.Number:
		if f, err := x.Float64(); err == nil {
			return Num(&f)
		}
	}
	return nil
}

func div(p *float64, d float64) *float64 {
	if p == nil {
		return nil
	}
	v := *p / d
	return Num(&v)
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

// numRound rounds v, nil when v or the rounded value is not Finite.
func numRound(v float64, places int) *float64 {
	if !Finite(v) {
		return nil
	}
	r := round(v, places)
	return Num(&r)
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
