package ups

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEventLimiter(t *testing.T) {
	l := &EventLimiter{Burst: 3, Window: time.Minute}
	now := time.Unix(1_700_000_000, 0)
	allowed := 0
	for i := 0; i < 500; i++ { // a status flapping every few milliseconds
		if ok, _ := l.Allow("cyberpower", now.Add(time.Duration(i)*time.Millisecond)); ok {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatal(allowed)
	}
	if ok, _ := l.Allow("other-ups", now); !ok {
		t.Fatal("another UPS has its own budget")
	}
	if ok, n := l.Allow("cyberpower", now.Add(2*time.Minute)); !ok || n != 497 {
		t.Fatal(ok, n)
	}
}

func TestAppendLineStaysBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ups-events.jsonl")
	line := bytes.Repeat([]byte("x"), 99)
	for i := 0; i < 10000; i++ {
		if err := AppendLine(path, line, 10_000); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := os.Stat(path)
	b, _ := os.Stat(path + ".1")
	if a.Size() > 10_000 || b.Size() > 10_000 || a.Size()%100 != 0 {
		t.Fatal(a.Size(), b.Size())
	}
	if AppendLine(path, line, 0) == nil {
		t.Fatal("no limit")
	}
}
