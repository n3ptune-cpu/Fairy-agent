package winpipe

import (
	"testing"
	"time"
)

func TestRetryDelay(t *testing.T) {
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
		30 * time.Second, 30 * time.Second}
	for i, w := range want {
		if got := RetryDelay(i); got != w {
			t.Errorf("attempt %d: %s, want %s", i, got, w)
		}
	}
	// never zero, never negative, never more than 30 s, however long the name is held
	for _, i := range []int{-5, -1, 62, 63, 64, 1000, 1 << 30} {
		if got := RetryDelay(i); got < time.Second || got > 30*time.Second {
			t.Errorf("attempt %d: %s", i, got)
		}
	}
	var total time.Duration
	for i := 0; i < 20; i++ {
		total += RetryDelay(i)
	}
	if total > 9*time.Minute { // 20 attempts stay inside ten minutes: the helper is back soon after the name is free
		t.Errorf("20 attempts take %s", total)
	}
}
