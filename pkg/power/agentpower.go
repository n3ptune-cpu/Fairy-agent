package power

import (
	"context"
	"fmt"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/configutil"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// AgentPowerConfig is a `type: agent` power source: one metric of an agent's component power.
type AgentPowerConfig struct {
	Base   `yaml:",inline"`
	Agent  string `yaml:"agent"`
	Metric string `yaml:"metric"` // cpu_package_w | gpu_w | battery_w | bmc_w
}

// AgentPowerFn returns an agent's latest reading of one component power metric (cpu_package_w, gpu_w,
// battery_w or bmc_w), nil if unknown. The panel provides it; fairy-agent itself has no `type: agent` sources.
type AgentPowerFn func(agentID, metric string) *float64

type agentPowerSrc struct {
	defaults
	c  AgentPowerConfig
	fn AgentPowerFn
}

func (s *agentPowerSrc) Info() Base { return s.c.Base }

func (s *agentPowerSrc) DefaultInterval() float64 { return 1 }

func (s *agentPowerSrc) Read(context.Context, time.Duration) ([]Reading, error) {
	v := s.fn(s.c.Agent, s.c.Metric)
	if v == nil {
		return nil, devices.Errf("agent %s reports no %s", s.c.Agent, s.c.Metric)
	}
	return []Reading{NewReading(s.c.Base, devices.Reading{Watts: v})}, nil
}

// buildAgentPower validates a `type: agent` entry. It is not counted in the wall-power total unless the
// entry opts in (component power is not wall power; bmc_w is PSU input).
func buildAgentPower(decode configDecoder, agentPower AgentPowerFn) (Source, error) {
	c := AgentPowerConfig{Metric: "bmc_w"}
	f := false
	c.IncludeInTotal = &f // component power is not wall power (bmc_w is PSU input; opt in)
	if err := decode(&c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if !configutil.ValidID(c.Agent) {
		return nil, fmt.Errorf("power source %s: agent must be an agent id", c.ID)
	}
	switch c.Metric {
	case "cpu_package_w", "gpu_w", "battery_w", "bmc_w":
	default:
		return nil, fmt.Errorf("power source %s: metric must be cpu_package_w, gpu_w, battery_w or bmc_w", c.ID)
	}
	if agentPower == nil {
		agentPower = func(string, string) *float64 { return nil }
	}
	return &agentPowerSrc{c: c, fn: agentPower}, nil
}
