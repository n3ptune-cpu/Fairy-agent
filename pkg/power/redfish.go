package power

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/configutil"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// RedfishConfig is a `type: redfish` (or `ipmi`) power source: a BMC's Redfish power reading.
type RedfishConfig struct {
	Base        `yaml:",inline"`
	URL         string `yaml:"url"`        // https://idrac.lan
	ChassisID   string `yaml:"chassis_id"` // iDRAC default System.Embedded.1; HPE iLO uses "1"
	PowerPath   string `yaml:"power_path"` // override, e.g. /redfish/v1/Chassis/1/EnvironmentMetrics
	Username    string `yaml:"username"`
	PasswordEnv string `yaml:"password_env"`
	VerifyTLS   *bool  `yaml:"verify_tls"`
	CAFile      string `yaml:"ca_file"`
}

type redfish struct {
	c  RedfishConfig
	tr *http.Transport // one per BMC: connections are reused across polls
}

func (s *redfish) Info() Base { return s.c.Base }

func (s *redfish) DefaultInterval() float64 { return 10 }

// BMC sensors update slowly; don't hammer them
func (s *redfish) FloorInterval() float64 { return 10 }

func (s *redfish) MaxBackoff() float64 { return 300 }

// BMCs are often not cabled: back off up to 5 min
func (s *redfish) Close() { s.tr.CloseIdleConnections() }

func (s *redfish) Read(ctx context.Context, timeout time.Duration) ([]Reading, error) {
	c := s.c
	path := c.PowerPath
	if path == "" {
		path = "/redfish/v1/Chassis/" + url.PathEscape(c.ChassisID) + "/Power"
	}
	pw, err := configutil.EnvSecret(c.PasswordEnv, c.ID, 1)
	if err != nil {
		return nil, devices.Safe(err)
	}
	d, err := devices.GetJSON(ctx, devices.ClientWith(timeout, s.tr), strings.TrimRight(c.URL, "/")+path, "basic", c.Username, pw)
	if err != nil {
		return nil, err
	}
	w, v, err := devices.ParseRedfishPower(d)
	if err != nil {
		return nil, err
	}
	return []Reading{NewReading(c.Base, devices.Reading{Watts: w, Voltage: v})}, nil
}

// TLSConfig builds the client TLS settings (custom CA or verification off).
func TLSConfig(verify bool, caFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if !verify {
		cfg.InsecureSkipVerify = true //nolint:gosec // owner's explicit choice for self-signed BMCs
		return cfg, nil
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("no certificates in " + caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// buildRedfish validates a `type: redfish` (or `ipmi`) entry (defaults: chassis System.Embedded.1, user root).
func buildRedfish(decode configDecoder) (Source, error) {
	c := RedfishConfig{ChassisID: "System.Embedded.1", Username: "root"}
	if err := decode(&c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if err := httpURL(c.ID, "url", c.URL); err != nil {
		return nil, err
	}
	if c.PasswordEnv == "" {
		return nil, fmt.Errorf("power source %s: password_env is required", c.ID)
	}
	tc, err := TLSConfig(c.VerifyTLS == nil || *c.VerifyTLS, c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("power source %s: %w", c.ID, err)
	}
	return &redfish{c: c, tr: devices.TLSTransport(tc)}, nil
}
