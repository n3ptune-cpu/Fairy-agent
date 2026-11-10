package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// LogFile is an append-only log that rotates at MaxBytes (agent.log -> agent.log.1, one old file kept).
type LogFile struct {
	Path     string
	MaxBytes int64

	mu   sync.Mutex
	f    *os.File
	size int64
}

// OpenLog opens (creating the folder) the log file. On Windows the file is opened itself, never through a
// link: a symbolic link, a junction or a file with a second name (hard link) under the log's name is refused
// (openLogFile). The updater and the helper are LocalSystem and write their logs with this; a link there must
// not make them write into a file somewhere else.
func OpenLog(path string, maxBytes int64) (*LogFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	l := &LogFile{Path: path, MaxBytes: maxBytes}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *LogFile) open() error {
	f, err := openLogFile(l.Path)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

// Write appends p, rotating first when the file is full.
func (l *LogFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return 0, fmt.Errorf("log closed")
	}
	if l.MaxBytes > 0 && l.size+int64(len(p)) > l.MaxBytes {
		l.f.Close()
		_ = os.Remove(l.Path + ".1")
		_ = os.Rename(l.Path, l.Path+".1")
		if err := l.open(); err != nil {
			l.f = nil
			return 0, err
		}
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

// Close closes the file.
func (l *LogFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
