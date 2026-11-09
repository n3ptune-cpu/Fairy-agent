package ups

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EventLimiter caps how many events one UPS may cause, for whoever keeps UPS events (the Fairy panel): at most
// Burst per Window per UPS. A UPS whose status flaps, or a hostile upsd or agent that makes it look so, then
// costs a few events and a count instead of filling the event list, the notifications and the disk.
type EventLimiter struct {
	Burst  int           // default 10
	Window time.Duration // default 10 minutes

	mu   sync.Mutex
	seen map[string]*eventWindow
}

type eventWindow struct {
	start      time.Time
	n          int
	suppressed int
}

// Allow reports whether an event of the UPS id may be recorded at now. suppressed is how many were refused since
// the last allowed one (to mention in it, e.g. "and 37 more changes").
func (l *EventLimiter) Allow(id string, now time.Time) (ok bool, suppressed int) {
	burst, win := l.Burst, l.Window
	if burst <= 0 {
		burst = 10
	}
	if win <= 0 {
		win = 10 * time.Minute
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string]*eventWindow{}
	}
	w := l.seen[id]
	if w == nil {
		if len(l.seen) >= 1024 {
			clear(l.seen)
		}
		w = &eventWindow{start: now}
		l.seen[id] = w
	}
	if now.Sub(w.start) >= win {
		w.start, w.n = now, 0
	}
	if w.n >= burst {
		w.suppressed++
		return false, 0
	}
	w.n++
	s := w.suppressed
	w.suppressed = 0
	return true, s
}

// AppendLine appends one line (a newline is added) to a log file kept below maxBytes: when the line would not
// fit, the file becomes path.1 (replacing the previous one) and a new file is started. At most about 2 x maxBytes
// stay on disk. The folder is created 0700, the file 0600.
func AppendLine(path string, line []byte, maxBytes int64) error {
	if maxBytes <= 0 {
		return errors.New("ups: AppendLine needs a size limit")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if st, err := os.Stat(path); err == nil && st.Size()+int64(len(line))+1 > maxBytes {
		_ = os.Remove(path + ".1")
		if err := os.Rename(path, path+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line[:len(line):len(line)], '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
