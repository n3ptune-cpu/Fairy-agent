package agent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"math"
	"net/http"
	"runtime"
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
		"power_sources: [{id: plug, type: tasmota, url: 'http://192.0.2.1', interval: .nan}]":                  "interval",
		"power_sources: [{id: plug, type: shelly, url: 'http://192.0.2.1', interval: .inf}]":                   "interval",
		"power_sources: [{id: plug, type: shelly, url: 'http://192.0.2.1', interval: -.inf}]":                  "interval",
		"power_sources: [{id: bmc, type: redfish, url: 'https://192.0.2.1', password_env: X, interval: .nan}]": "interval",
	} {
		c, err := Parse([]byte(y), "config.yaml")
		if err != nil {
			t.Fatalf("%q: %v", y, err)
		}
		if _, err := NewRelay(c.PowerSources, c.UPS); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error naming %s", y, err, want)
		}
	}
	c, err := Parse([]byte("power_sources: [{id: plug, type: tasmota, url: 'http://192.0.2.1', interval: 300}]"), "config.yaml")
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

// TestFewDifferentChars: the hint for a token typed by hand. The length check takes 24 times one letter, and
// nothing slows guessing down, so the agent says so in its log when it starts (second review of
// ae9384f..5a6658c, F2 (d)). A token the agent or the panel makes (32 random bytes, base64url) never has that few.
func TestFewDifferentChars(t *testing.T) {
	for tok, want := range map[string]bool{
		strings.Repeat("a", 24):         true,
		strings.Repeat("a", 23) + "b":   true,
		strings.Repeat("abc123XYZ", 5):  true,  // 9 different characters
		strings.Repeat("abc123XYZ_", 3): false, // 10
		"correct-horse-battery-staple":  false, // 12 different characters: the hint is not a measure of strength
		"2026-11-12-2026-11-12-20":      true,
	} {
		if got := FewDifferentChars(tok); got != want {
			t.Errorf("FewDifferentChars(%q) = %v, want %v", tok, got, want)
		}
	}
	for i := 0; i < 2000; i++ {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		if tok := base64.RawURLEncoding.EncodeToString(b); FewDifferentChars(tok) {
			t.Fatalf("a token made of 32 random bytes is called typed by hand: %d characters", len(tok))
		}
	}
}

// TestRunWarnsOnceAboutATokenTypedByHand: the real Run with a read token of 24 times "a" and a control token of
// 23 times "a" and a "b" starts and serves (the tokens are valid: only the length is checked), and its log has
// one warning for each, by name, without the token.
func TestRunWarnsOnceAboutATokenTypedByHand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Run looks for the helper service on Windows")
	}
	const weakRead, weakCtl = "aaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaab"
	random := func() string {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	goodRead, goodCtl := random(), random() // as `fairy-agent gen-token` makes them
	for _, c := range []struct {
		read, ctl string
		lines     int
	}{{weakRead, weakCtl, 2}, {goodRead, goodCtl, 0}} {
		logs := captureLog(t)
		t.Setenv("FAIRY_AGENT_TOKEN", c.read)
		t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", c.ctl)
		addr := freeAddr(t)
		cfg := mustParse(t, "listen: "+addr+"\nwol: {enabled: true, allowed_macs: [\"3c:ec:ef:00:11:22\"]}\n")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, cfg, Build{Version: "test"}) }()
		status := 0
		for deadline := time.Now().Add(15 * time.Second); status != 200 && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/metrics", nil)
			req.Header.Set("Authorization", "Bearer "+c.read)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				status = resp.StatusCode
				resp.Body.Close()
			}
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("Run:", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("Run did not stop")
		}
		log := logs.String()
		if status != 200 {
			t.Fatalf("the agent did not answer its read token: %d\n%s", status, log)
		}
		const line = "a token has fewer than 10 different characters"
		if n := strings.Count(log, line); n != c.lines {
			t.Errorf("%d warnings, want %d:\n%s", n, c.lines, log)
		}
		if c.lines == 2 && (!strings.Contains(log, "token=read") || !strings.Contains(log, "token=control")) {
			t.Errorf("the warnings do not name the two tokens:\n%s", log)
		}
		if strings.Contains(log, weakRead) || strings.Contains(log, weakCtl[:23]) || strings.Contains(log, goodRead) || strings.Contains(log, goodCtl) {
			t.Errorf("a token is in the log:\n%s", log)
		}
	}
}
