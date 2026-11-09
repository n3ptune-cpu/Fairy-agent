package agent

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// RateLimitLog wraps a log handler so that one message text is written at most perMinute times a minute; the
// records dropped in between are counted and the count ("suppressed") is added to the next one written. Whatever
// repeats (a flapping UPS, a BMC that keeps failing, a client hammering the agent) cannot fill the disk or the
// journal; the log file itself is also rotated (LogFile).
func RateLimitLog(h slog.Handler, perMinute int) slog.Handler {
	if perMinute <= 0 {
		perMinute = 30
	}
	return &rateHandler{h: h, st: &rateState{per: perMinute, win: time.Minute, now: time.Now, keys: map[string]*rateKey{}}}
}

type rateKey struct {
	start      time.Time
	n          int
	suppressed int
}

type rateState struct {
	mu   sync.Mutex
	per  int
	win  time.Duration
	now  func() time.Time
	keys map[string]*rateKey
}

type rateHandler struct {
	h  slog.Handler
	st *rateState
}

func (r *rateHandler) Enabled(ctx context.Context, l slog.Level) bool { return r.h.Enabled(ctx, l) }

func (r *rateHandler) Handle(ctx context.Context, rec slog.Record) error {
	s := r.st
	s.mu.Lock()
	now := s.now()
	key := rec.Level.String() + "\x00" + rec.Message
	k := s.keys[key]
	if k == nil {
		if len(s.keys) >= 1000 { // many different messages: start over rather than grow
			clear(s.keys)
		}
		k = &rateKey{start: now}
		s.keys[key] = k
	}
	if now.Sub(k.start) >= s.win {
		k.start, k.n = now, 0
	}
	if k.n >= s.per {
		k.suppressed++
		s.mu.Unlock()
		return nil
	}
	k.n++
	dropped := k.suppressed
	k.suppressed = 0
	s.mu.Unlock()
	if dropped > 0 {
		rec = rec.Clone()
		rec.AddAttrs(slog.Int("suppressed", dropped))
	}
	return r.h.Handle(ctx, rec)
}

func (r *rateHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return &rateHandler{h: r.h.WithAttrs(a), st: r.st}
}

func (r *rateHandler) WithGroup(name string) slog.Handler {
	return &rateHandler{h: r.h.WithGroup(name), st: r.st}
}
