package agent

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// Audit 3, L35: the range checks asked "below the minimum or above the maximum", which is never true for NaN,
// so `.nan` passed. With fan_control.max_temp_c: .nan the agent started and the fan watchdog never acted.
func TestConfigRejectsNotANumber(t *testing.T) {
	settings := map[string]string{
		"fan_control: {max_temp_c: %s}":    "fan_control.max_temp_c",
		"gpu: {interval_s: %s}":            "gpu.interval_s",
		"ipmi: {sensor_interval_s: %s}":    "ipmi.sensor_interval_s",
		"fan_control:\n  max_temp_c: %s\n": "fan_control.max_temp_c",
	}
	for tmpl, want := range settings {
		for _, v := range []string{".nan", ".NaN", ".NAN", ".inf", "-.inf", ".Inf", "+.inf"} {
			y := strings.Replace(tmpl, "%s", v, 1)
			c, err := Parse([]byte(y), "config.yaml")
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%q: got %v, want an error naming %s (max_temp_c %v)", y, err, want, c)
			}
		}
	}
	// the limits themselves and the defaults still load
	for _, y := range []string{"", "fan_control: {max_temp_c: 50}", "fan_control: {max_temp_c: 95}", "gpu: {interval_s: 1}",
		"gpu: {interval_s: 60}", "ipmi: {sensor_interval_s: 2}", "ipmi: {sensor_interval_s: 300}",
		"fan_control: {min_duty: 30}", "fan_control: {min_duty: 100}", "power_control: {min_delay_s: 3600}", "control_rate_per_min: 60"} {
		c, err := Parse([]byte(y), "config.yaml")
		if err != nil {
			t.Errorf("%q: %v", y, err)
			continue
		}
		if m := c.FanControl.MaxTempC; math.IsNaN(m) || m < 50 || m > 95 {
			t.Errorf("%q: max_temp_c %v", y, m)
		}
	}
	for y, want := range map[string]string{"fan_control: {max_temp_c: 49.9}": "max_temp_c", "fan_control: {max_temp_c: 95.1}": "max_temp_c",
		"gpu: {interval_s: 60.5}": "interval_s", "ipmi: {sensor_interval_s: 1.9}": "sensor_interval_s",
		"fan_control: {min_duty: 101}": "min_duty", "power_control: {min_delay_s: 3601}": "min_delay_s", "control_rate_per_min: -1": "control_rate_per_min"} {
		if _, err := Parse([]byte(y), "config.yaml"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v", y, err)
		}
	}
}

// `fairy-agent check-config` also builds the relayed devices (NewRelay): `.nan` there fails as well.
func TestRelayConfigRejectsNotANumber(t *testing.T) {
	for y, want := range map[string]string{
		"power_sources: [{id: plug, type: tasmota, url: 'http://192.0.2.1', interval: .nan}]":                                        "interval",
		"power_sources: [{id: plug, type: shelly, url: 'http://192.0.2.1', interval: .inf}]":                                         "interval",
		"power_sources: [{id: plug, type: shelly, url: 'http://192.0.2.1', interval: -.inf}]":                                        "interval",
		"power_sources: [{id: bmc, type: redfish, url: 'https://192.0.2.1', password_env: X, interval: .nan}]":                       "interval",
		"power_sources: [{id: t, type: tuya, device_id: d, ip: 192.0.2.1, local_key_env: K, dps: {power: {dp: '19', scale: .nan}}}]": "scale",
		"power_sources: [{id: t, type: tuya, device_id: d, ip: 192.0.2.1, local_key_env: K, dps: {power: {dp: '19', scale: .inf}}}]": "scale",
	} {
		c, err := Parse([]byte(y), "config.yaml")
		if err != nil {
			t.Fatalf("%q: %v", y, err)
		}
		if _, err := NewRelay(c.PowerSources, c.UPS); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error naming %s", y, err, want)
		}
	}
	c, err := Parse([]byte("power_sources: [{id: plug, type: tasmota, url: 'http://192.0.2.1', interval: 300},"+
		" {id: t, type: tuya, device_id: d, ip: 192.0.2.1, local_key_env: K, dps: {power: {dp: '19', scale: 0.1}}}]"), "config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRelay(c.PowerSources, c.UPS); err != nil {
		t.Fatal(err)
	}
}

// The pause between two polls of a device is never NaN, zero or negative, whatever a source reports.
func TestRelayPollIntervalIsSane(t *testing.T) {
	nan, half, long := math.NaN(), 0.5, 1e9
	for name, tc := range map[string]struct {
		iv   *float64
		want time.Duration
	}{
		"default":             {nil, 2 * time.Second},
		"NaN":                 {&nan, 2 * time.Second},
		"below the floor":     {&half, time.Second},
		"far above the limit": {&long, 2 * time.Second},
	} {
		got := interval(&multiSource{base: power.Base{ID: "x", Interval: tc.iv}})
		if got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
