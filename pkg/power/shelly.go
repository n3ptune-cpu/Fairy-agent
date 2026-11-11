package power

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/configutil"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// ShellyConfig is a `type: shelly` power source (Gen1 /status or Gen2+ RPC).
type ShellyConfig struct {
	Base        `yaml:",inline"`
	URL         string `yaml:"url"` // http://192.168.1.50
	Gen         string `yaml:"gen"` // auto | 1 | 2
	Channel     int    `yaml:"channel"`
	RPCMethod   string `yaml:"rpc_method"` // e.g. PM1.GetStatus for Shelly PM Mini
	Username    string `yaml:"username"`
	PasswordEnv string `yaml:"password_env"`
}

type shelly struct {
	defaults
	c ShellyConfig
}

func (s *shelly) Info() Base { return s.c.Base }

func (s *shelly) Read(ctx context.Context, timeout time.Duration) ([]Reading, error) {
	c := s.c
	pw, err := configutil.EnvSecret(c.PasswordEnv, "power source "+c.ID, 1)
	if err != nil {
		return nil, devices.Safe(err)
	}
	base := strings.TrimRight(c.URL, "/")
	hc := devices.LANClient(timeout)
	if c.Gen == "auto" || c.Gen == "2" {
		auth := ""
		if pw != "" {
			auth = "digest" // Gen2 auth is digest
		}
		var r devices.Reading
		err := devices.ReadJSON(ctx, hc, fmt.Sprintf("%s/rpc/%s?id=%d", base, url.PathEscape(c.RPCMethod), c.Channel), auth, c.Username, pw,
			func(d map[string]any) error { r = devices.ParseShellyGen2(d); return nil })
		var he *devices.HTTPStatusError
		if err == nil {
			return []Reading{NewReading(c.Base, r)}, nil
		}
		if !errors.As(err, &he) || he.Code != 404 || c.Gen == "2" {
			return nil, err
		}
	}
	auth := ""
	if pw != "" {
		auth = "basic"
	}
	var r devices.Reading
	err = devices.ReadJSON(ctx, hc, base+"/status", auth, c.Username, pw, func(d map[string]any) (err error) {
		r, err = devices.ParseShellyGen1(d, c.Channel)
		return err
	})
	if err != nil {
		return nil, err
	}
	return []Reading{NewReading(c.Base, r)}, nil
}

// buildShelly validates a `type: shelly` entry (defaults: gen auto, Switch.GetStatus, user admin).
func buildShelly(decode configDecoder) (Source, error) {
	c := ShellyConfig{Gen: "auto", RPCMethod: "Switch.GetStatus", Username: "admin"}
	if err := decode(&c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if err := httpURL(c.ID, "url", c.URL); err != nil {
		return nil, err
	}
	if c.Gen != "auto" && c.Gen != "1" && c.Gen != "2" {
		return nil, fmt.Errorf("power source %s: gen must be auto, 1 or 2", c.ID)
	}
	if c.Channel < 0 {
		return nil, fmt.Errorf("power source %s: channel must be >= 0", c.ID)
	}
	return &shelly{c: c}, nil
}
