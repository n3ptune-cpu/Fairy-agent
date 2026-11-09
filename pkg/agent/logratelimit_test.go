package agent

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestRateLimitLog(t *testing.T) {
	var buf bytes.Buffer
	h := RateLimitLog(slog.NewTextHandler(&buf, nil), 3).(*rateHandler)
	now := time.Unix(1_700_000_000, 0)
	h.st.now = func() time.Time { return now }
	log := slog.New(h)
	for i := 0; i < 1000; i++ { // a UPS flapping, a BMC failing over and over
		log.Warn("UPS event", "ups", "cyberpower", "i", i)
	}
	log.Info("something else")
	if got := strings.Count(buf.String(), "UPS event"); got != 3 {
		t.Fatalf("%d lines:\n%s", got, buf.String())
	}
	if !strings.Contains(buf.String(), "something else") {
		t.Fatal("other messages must pass")
	}
	now = now.Add(61 * time.Second)
	log.With("relay", "x").Warn("UPS event", "ups", "cyberpower")
	if !strings.Contains(buf.String(), "suppressed=997") || !strings.Contains(buf.String(), "relay=x") {
		t.Fatal(buf.String())
	}
}
