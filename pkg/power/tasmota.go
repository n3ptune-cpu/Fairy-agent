package power

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
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
	// inURL: this plug refused the password in a header and took it in the address (older firmware). Later
	// reads go straight to that form; a restart asks the header way again.
	inURL atomic.Bool
}

func (s *tasmota) Info() Base { return s.c.Base }

// Read asks the plug for "Status 8" (its measurements).
//
// A plug with a web password wants it with every command. Tasmota's own, documented way is in the address:
// /cm?user=<name>&password=<password>&cmnd=... . Newer firmware also takes it in an HTTP header
// (Authorization: Basic), which keeps the password out of every address. So the header is tried first, and
// the address form is used only for a plug that refuses the header (HTTP 401, or the "WARNING" answer older
// firmware gives with HTTP 200). Either way the password crosses the local network in clear: Tasmota's HTTP
// API has nothing else.
//
// The address with the password is never logged and never part of an error: devices.GetJSON returns only
// fixed words for a failed request, and safeError checks that again here.
func (s *tasmota) Read(ctx context.Context, timeout time.Duration) ([]Reading, error) {
	c := s.c
	pw, err := configutil.EnvSecret(c.PasswordEnv, "power source "+c.ID, 1)
	if err != nil {
		return nil, devices.Safe(err)
	}
	client := devices.LANClient(timeout)
	plain := strings.TrimRight(c.URL, "/") + "/cm?" + url.Values{"cmnd": {"Status 8"}}.Encode()
	var d map[string]any
	switch {
	case pw == "":
		d, err = devices.GetJSON(ctx, client, plain, "", "", "")
	case s.inURL.Load():
		d, err = s.readWithPasswordInURL(ctx, client, pw)
	default:
		d, err = devices.GetJSON(ctx, client, plain, "basic", c.Username, pw)
		if tasmotaWantsPasswordInURL(d, err) {
			if d, err = s.readWithPasswordInURL(ctx, client, pw); err == nil && !tasmotaWantsPasswordInURL(d, nil) {
				s.inURL.Store(true)
			}
		}
	}
	if err != nil {
		return nil, safeError(err, pw)
	}
	r, err := devices.ParseTasmotaStatus8(d)
	if err != nil {
		return nil, safeError(err, pw)
	}
	return []Reading{NewReading(c.Base, r)}, nil
}

// readWithPasswordInURL is Tasmota's older way: the password in the address.
func (s *tasmota) readWithPasswordInURL(ctx context.Context, client *http.Client, pw string) (map[string]any, error) {
	q := url.Values{"cmnd": {"Status 8"}, "user": {s.c.Username}, "password": {pw}}
	return devices.GetJSON(ctx, client, strings.TrimRight(s.c.URL, "/")+"/cm?"+q.Encode(), "", "", "")
}

// tasmotaWantsPasswordInURL reports whether a plug's answer to a command says "no password seen": HTTP 401, or
// (older firmware) HTTP 200 with {"WARNING":"Need user=<username>&password=<password>"}.
func tasmotaWantsPasswordInURL(d map[string]any, err error) bool {
	var he *devices.HTTPStatusError
	if errors.As(err, &he) {
		return he.Code == http.StatusUnauthorized
	}
	if err != nil {
		return false
	}
	_, warned := d["WARNING"]
	return warned
}

// safeError returns err as it is when its text cannot give the password away, and a fixed word otherwise. The
// errors of this package's requests are fixed words already (devices.GetJSON); this is the second lock on the
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
