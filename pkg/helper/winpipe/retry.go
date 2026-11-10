package winpipe

import "time"

// RetryDelay is how long Serve waits before it tries again to create the pipe when another process holds its
// name: 1 s, 2 s, 4 s ... up to 30 s, then every 30 s for as long as it takes. The helper keeps running
// meanwhile (the BMC reader and the fan watchdog do not need the pipe), so a program that takes the name
// while the helper is down cannot keep the helper from starting, only from being reached while it holds the name.
func RetryDelay(attempt int) time.Duration {
	const maxDelay = 30 * time.Second
	if attempt < 0 {
		attempt = 0
	}
	if attempt >= 5 { // 1 s << 5 is already past the cap
		return maxDelay
	}
	return time.Second << attempt
}
