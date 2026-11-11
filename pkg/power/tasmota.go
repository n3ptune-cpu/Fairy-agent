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

// Read asks the plug for "Status 8" (its measurements).
//
// A plug with a web password wants it with every command, and Tasmota documents one way to give it: in the
// address, /cm?user=<name>&password=<password>&cmnd=... ("this must be included (in plaintext) in the URL of
// the HTTP request", Tasmota's Commands page, "with Web Requests"). That is the only form used here, one
// request for every reading, as in every release before. Firmware from 9.3.0 on also takes an HTTP header
// (Authorization: Basic) for /cm, but that is in its source only, not in its documentation, older firmware
// refuses it, and it protects nothing: Tasmota speaks plain HTTP, so the password crosses the local network
// in clear in either form.
//
// What this code does guarantee is that the address with the password is never logged and never part of an
// error: devices.ReadJSON returns only fixed words for a failed request, and safeError checks that again here.
func (s *tasmota) Read(ctx context.Context, timeout time.Duration) ([]Reading, error) {
	c := s.c
	q := url.Values{"cmnd": {"Status 8"}}
	pw, err := configutil.EnvSecret(c.PasswordEnv, "power source "+c.ID, 1)
	if err != nil {
		return nil, devices.Safe(err)
	}
	if pw != "" { // Tasmota's own scheme; the address is never logged
		q.Set("user", c.Username)
		q.Set("password", pw)
	}
	var r devices.Reading
	err = devices.ReadJSON(ctx, devices.LANClient(timeout), strings.TrimRight(c.URL, "/")+"/cm?"+q.Encode(), "", "", "",
		func(d map[string]any) (err error) {
			r, err = devices.ParseTasmotaStatus8(d)
			return err
		})
	if err != nil {
		return nil, safeError(err, pw)
	}
	return []Reading{NewReading(c.Base, r)}, nil
}

// safeError returns err as it is when its text cannot give the password away, and a fixed word otherwise. The
// errors of this package's requests are fixed words already (devices.ReadJSON); this is the second lock on the
// one request whose address can carry a password.
func safeError(err error, pw string) error {
	msg := err.Error()
	if (pw != "" && (strings.Contains(msg, pw) || strings.Contains(msg, url.QueryEscape(pw)))) ||
		strings.Contains(msg, "password=") || strings.Contains(msg, "/cm?") {
		return devices.Errf("request failed")
	}
	return err
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
