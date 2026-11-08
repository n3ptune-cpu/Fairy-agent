package power

import (
	"context"
	"fmt"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/configutil"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// NutConfig is a `type: nut` power source: wall power of a UPS read from upsd.
type NutConfig struct {
	Base        `yaml:",inline"`
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	UPS         string `yaml:"ups"`
	Username    string `yaml:"username"`
	PasswordEnv string `yaml:"password_env"`
}

type nut struct {
	defaults
	c NutConfig
}

func (s *nut) Info() Base { return s.c.Base }

func (s *nut) Read(ctx context.Context, timeout time.Duration) ([]Reading, error) {
	c := s.c
	pw, err := configutil.EnvSecret(c.PasswordEnv, "power source "+c.ID, 1)
	if err != nil {
		return nil, devices.Safe(err)
	}
	all, err := devices.NUTReadAll(ctx, c.Host, c.Port, c.Username, pw, timeout, []string{c.UPS})
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, devices.Errf("nut: no such UPS")
	}
	w, v, a := devices.NUTWatts(all[0].Vars)
	if w == nil {
		return nil, devices.Errf("nut: UPS reports neither ups.realpower nor ups.load + ups.realpower.nominal")
	}
	return []Reading{NewReading(c.Base, devices.Reading{Watts: w, Voltage: v, Current: a})}, nil
}

// buildNut validates a `type: nut` entry (defaults: port 3493, UPS name "ups").
func buildNut(decode configDecoder) (Source, error) {
	c := NutConfig{Port: 3493, UPS: "ups"}
	if err := decode(&c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if c.Host == "" {
		return nil, fmt.Errorf("power source %s: host is required", c.ID)
	}
	return &nut{c: c}, nil
}
