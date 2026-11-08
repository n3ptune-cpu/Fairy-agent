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

func f64(v any) *float64 {
	switch x := v.(type) {
	case float64:
		return &x
	case int:
		f := float64(x)
		return &f
	case int64:
		f := float64(x)
		return &f
	case json.Number:
		if f, err := x.Float64(); err == nil {
			return &f
		}
	}
	return nil
}

func div(p *float64, d float64) *float64 {
	if p == nil {
		return nil
	}
	v := *p / d
	return &v
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
