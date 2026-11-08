// Package power reads wall power from plugs, UPSes and BMCs (plus component power reported by agents): one
// Source per device type, built from a `power_sources:` config entry by Build. fairy-agent uses it to relay the
// devices on its own network; the Fairy panel (github.com/n3ptune-cpu/Fairy-dashboard) uses the same sources
// and adds the Runner (backoff) and the Manager (overview, watts per system, history, devices relayed by agents).
//
// Adding a device type = one Source implementation in its own file plus a case in Build.
package power

import (
	"context"
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
	if b.Interval != nil && (*b.Interval < 1 || *b.Interval > 300) {
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

// NewReading builds a Reading for a source.
func NewReading(b Base, r devices.Reading) Reading {
	pr := Reading{SourceID: b.ID, Name: b.DisplayName(), Watts: r.Watts, Voltage: r.Voltage,
		Current: r.Current, EnergyKWhTotal: r.EnergyKWh, Timestamp: time.Now().UTC()}
	if b.System != "" {
		system := b.System
		pr.SystemID = &system
	}
	return pr
}
