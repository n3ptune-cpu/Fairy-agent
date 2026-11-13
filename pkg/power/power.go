// Package power reads wall power from plugs, UPSes and BMCs (plus component power reported by agents): one
// Source per device type, built from a `power_sources:` config entry by Build. fairy-agent uses it to relay the
// devices on its own network; the Fairy panel (github.com/n3ptune-cpu/Fairy-dashboard) uses the same sources
// and adds the Runner (backoff) and the Manager (overview, watts per system, history, devices relayed by agents).
//
// Adding a device type = one Source implementation in its own file plus a case in Build.
package power

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/configutil"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// Base holds the fields every source type has.
type Base struct {
	ID             string   `yaml:"id"`
	Type           string   `yaml:"type"`
	Name           string   `yaml:"name"`
	System         string   `yaml:"system"`           // link to a system -> System.power_w
	IncludeInTotal *bool    `yaml:"include_in_total"` // false for downstream plugs already counted by a UPS
	Interval       *float64 `yaml:"interval"`         // default per type
}

// DisplayName is the source's name, or its id.
func (b Base) DisplayName() string {
	if b.Name != "" {
		return b.Name
	}
	return b.ID
}

func (b Base) validate() error {
	if !configutil.ValidID(b.ID) {
		return fmt.Errorf("power source %q: id must be lowercase letters, digits and dashes", b.ID)
	}
	if b.System != "" && !configutil.ValidID(b.System) {
		return fmt.Errorf("power source %s: invalid system id", b.ID)
	}
	if b.Interval != nil && !(*b.Interval >= 1 && *b.Interval <= 300) { // "not inside": .nan fails too
		return fmt.Errorf("power source %s: interval must be 1-300 s", b.ID)
	}
	return nil
}

// Source reads one device.
type Source interface {
	Info() Base
	Read(ctx context.Context, timeout time.Duration) ([]Reading, error)
	DefaultInterval() float64
	FloorInterval() float64
	MaxBackoff() float64
	Close()
}

// Check is what a config check may show of a source that reads with a secret: where it reads, what, and
// whether the secret is there. It never holds the secret, only the name of the variable it is kept in.
type Check struct {
	ID, Type  string
	Scheme    string // http or https
	Host      string // host[:port]
	Reads     string // what is read there (homeassistant: the sensor's entity id)
	SecretEnv string // the environment variable the source takes its secret from
	SecretSet bool   // that variable is set (in the environment of whoever asks)
}

// Checker is a Source that has a Check (today: homeassistant).
type Checker interface{ Check() Check }

// Refused reports whether err says that the device refused the secret it was sent (a token, a password): an
// error that has, itself or in what it wraps, a method `Refused() bool` that returns true.
//
// After such an answer, asking again at once does not help and can do harm: a Home Assistant counts every
// request with a token it does not know as a failed login and can ban the sender's address. So whoever polls
// a source waits much longer after a refusal than after any other failure (the agent's relay: RefusedWait). A
// source type opts in by returning such an error from Read (refusedf); today only homeassistant does, and the
// timing of every other type is as it was.
func Refused(err error) bool {
	var r interface{ Refused() bool }
	return errors.As(err, &r) && r.Refused()
}

// RefusedWait is how long to wait before a source is asked again after its n-th refusal in a row (n >= 1): 5
// minutes after the first, 15 minutes after the second, an hour after the third and after every further one.
// A token that was revoked and forgotten so makes 3 wrong logins in the first hour, 5 in the first three hours
// and one an hour after that (26 in the first day), where the normal interval of a Home Assistant source made
// 360 an hour: a Home Assistant that bans an address after a number of failed logins (ip_ban_enabled) is
// given as few as a source that still notices a repaired token can give it.
func RefusedWait(n int) time.Duration {
	switch {
	case n <= 1:
		return 5 * time.Minute
	case n == 2:
		return 15 * time.Minute
	}
	return time.Hour
}

// refusal is an error for which Refused is true. Its text is a fixed one that is safe to show: devices.Describe
// finds the *devices.Error inside.
type refusal struct{ err *devices.Error }

func (e *refusal) Error() string { return e.err.Msg }
func (e *refusal) Unwrap() error { return e.err }
func (e *refusal) Refused() bool { return true }

// refusedf is devices.Errf for a refusal of the secret. Never put credentials, URLs or headers into it.
func refusedf(f string, a ...any) error {
	return &refusal{err: &devices.Error{Msg: fmt.Sprintf(f, a...)}}
}

type defaults struct{}

func (defaults) DefaultInterval() float64 { return 2 }
func (defaults) FloorInterval() float64   { return 1 }
func (defaults) MaxBackoff() float64      { return 60 }
func (defaults) Close()                   {}

// Reading is one measurement of a power source (the panel's API shows it as model.PowerReading).
type Reading struct {
	SourceID       string    `json:"source_id"`
	Name           string    `json:"name"`
	Watts          *float64  `json:"watts"`
	Voltage        *float64  `json:"voltage"`
	Current        *float64  `json:"current"`
	EnergyKWhTotal *float64  `json:"energy_kwh_total"`
	SystemID       *string   `json:"system_id"`
	Timestamp      time.Time `json:"timestamp"`
}

// NewReading builds a Reading for a source. Values that are not possible numbers (devices.Finite) are left out
// (nil), whatever source they come from, so a Reading can always be written as JSON.
func NewReading(b Base, r devices.Reading) Reading {
	pr := Reading{SourceID: b.ID, Name: b.DisplayName(), Watts: devices.Num(r.Watts), Voltage: devices.Num(r.Voltage),
		Current: devices.Num(r.Current), EnergyKWhTotal: devices.Num(r.EnergyKWh), Timestamp: time.Now().UTC()}
	if b.System != "" {
		system := b.System
		pr.SystemID = &system
	}
	return pr
}
