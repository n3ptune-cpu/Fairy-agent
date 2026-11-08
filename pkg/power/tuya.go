package power

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/configutil"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/tuya"
)

// TuyaConfig is a `type: tuya` power source: a metering plug on the LAN (protocol 3.1-3.5).
type TuyaConfig struct {
	Base        `yaml:",inline"`
	DeviceID    string                      `yaml:"device_id"`
	IP          string                      `yaml:"ip"`
	LocalKeyEnv string                      `yaml:"local_key_env"`
	Version     string                      `yaml:"version"`
	DPS         map[string]devices.DpsField `yaml:"dps"`
	RefreshDPS  *[]int                      `yaml:"refresh_dps"` // some plugs only update power DPS on request
}

// tuyaSource: Tuya devices accept ONE TCP connection and can drop/reset under aggressive polling, so this keeps a
// single persistent connection and defaults to 5 s (floor 3 s).
type tuyaSource struct {
	defaults
	c   TuyaConfig
	mu  sync.Mutex
	dev *tuya.Device
}

func (s *tuyaSource) Info() Base { return s.c.Base }

func (s *tuyaSource) DefaultInterval() float64 { return 5 }

func (s *tuyaSource) FloorInterval() float64 { return 3 }

func (s *tuyaSource) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dev != nil {
		s.dev.Close()
		s.dev = nil
	}
}

func (s *tuyaSource) Read(_ context.Context, timeout time.Duration) ([]Reading, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.c
	if s.dev == nil {
		key, err := configutil.EnvSecret(c.LocalKeyEnv, "power source "+c.ID, 16)
		if err != nil {
			return nil, devices.Safe(err)
		}
		d, err := tuya.NewDevice(c.DeviceID, c.IP, key, c.Version, timeout)
		if err != nil {
			return nil, devices.Safe(err)
		}
		s.dev = d
	}
	s.dev.Timeout = timeout
	refresh := []int{18, 19, 20}
	if c.RefreshDPS != nil {
		refresh = *c.RefreshDPS
	}
	dps, err := s.dev.Status(refresh)
	if err != nil {
		return nil, devices.Safe(err) // tuya errors never contain the key
	}
	return []Reading{NewReading(c.Base, devices.ParseTuyaDPS(dps, c.DPS))}, nil
}

// buildTuya validates a `type: tuya` entry (default protocol 3.3, default metering DPS).
func buildTuya(decode configDecoder) (Source, error) {
	c := TuyaConfig{Version: "3.3"}
	if err := decode(&c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if c.DeviceID == "" || c.IP == "" || c.LocalKeyEnv == "" {
		return nil, fmt.Errorf("power source %s: device_id, ip and local_key_env are required", c.ID)
	}
	switch c.Version {
	case "3.1", "3.2", "3.3", "3.4", "3.5":
	default:
		return nil, fmt.Errorf("power source %s: version must be 3.1-3.5", c.ID)
	}
	if len(c.DPS) == 0 {
		c.DPS = devices.DefaultTuyaDPS()
	}
	for k, f := range c.DPS {
		if f.Scale == 0 {
			f.Scale = 1
			c.DPS[k] = f
		}
	}
	return &tuyaSource{c: c}, nil
}
