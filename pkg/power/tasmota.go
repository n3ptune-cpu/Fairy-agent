package power

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/configutil"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// TasmotaConfig is a `type: tasmota` power source.
type TasmotaConfig struct {
	Base        `yaml:",inline"`
	URL         string `yaml:"url"`
	Username    string `yaml:"username"`
	PasswordEnv string `yaml:"password_env"`
}

type tasmota struct {
	defaults
	c TasmotaConfig
}

func (s *tasmota) Info() Base { return s.c.Base }

func (s *tasmota) Read(ctx context.Context, timeout time.Duration) ([]Reading, error) {
	c := s.c
	q := url.Values{"cmnd": {"Status 8"}}
	pw, err := configutil.EnvSecret(c.PasswordEnv, "power source "+c.ID, 1)
	if err != nil {
		return nil, devices.Safe(err)
	}
	if pw != "" { // Tasmota's own scheme; the URL is never logged
		q.Set("user", c.Username)
		q.Set("password", pw)
	}
	d, err := devices.GetJSON(ctx, devices.LANClient(timeout), strings.TrimRight(c.URL, "/")+"/cm?"+q.Encode(), "", "", "")
	if err != nil {
		return nil, err
	}
	r, err := devices.ParseTasmotaStatus8(d)
	if err != nil {
		return nil, err
	}
	return []Reading{NewReading(c.Base, r)}, nil
}

// buildTasmota validates a `type: tasmota` entry (default user admin).
func buildTasmota(decode configDecoder) (Source, error) {
	c := TasmotaConfig{Username: "admin"}
	if err := decode(&c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if err := httpURL(c.ID, "url", c.URL); err != nil {
		return nil, err
	}
	return &tasmota{c: c}, nil
}
