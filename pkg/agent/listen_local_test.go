package agent

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// idleConn opens a connection from src, sends one complete request without a token and reads the answer: the
// connection is then kept open by the agent for a next request (for IdleTimeout, 90 s).
func idleConn(t *testing.T, src, addr string) net.Conn {
	t.Helper()
	c, err := dialFrom(src, addr)
	if err != nil {
		t.Skip("cannot connect from", src, err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "GET /metrics HTTP/1.1\r\nHost: agent\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 401 {
		t.Fatal("setup: a request without a token over keep-alive:", resp, err)
	}
	resp.Body.Close()
	return c
}

// waitIdle waits until the server has marked n of the listener's connections idle. The server does that a
// moment after the answer was sent, in its own time: a test that has read the answer cannot take the mark for
// set, and one that depends on which connection became idle FIRST must wait for each mark before it opens the
// next connection.
func waitIdle(t *testing.T, ln *LimitListener, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ln.mu.Lock()
		idle := 0
		for c := range ln.conns {
			if !c.idleSince.IsZero() {
				idle++
			}
		}
		ln.mu.Unlock()
		if idle >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %d of the listener's connections are marked idle, want %d", idle, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// Review N2. This machine has eight slots. A local user without any right took them with eight idle
// connections (one complete request each, then nothing; they stay for 90 s and can be renewed). The update's
// health check, which also comes from this machine, was then reset every time: every update was rolled back.
// Now the oldest idle connection of this machine makes room.
func TestLocalIdleConnsDoNotLockTheHealthCheckOut(t *testing.T) {
	ln, addr := serveLimited(t, ConnLimits{})
	var held []net.Conn
	for i := 0; i < MaxConnsPerSender; i++ {
		held = append(held, idleConn(t, floodLocal, addr))
		// The next one is opened only when the server has marked this one idle: the end of this test says which
		// connection must have been closed, "the oldest idle one", and that is the one MARKED first, not the
		// one opened first. Without this wait a later connection was now and then marked before held[0] (its
		// answer is read here before the server gets to the mark), that one was closed, and the test failed
		// with "the oldest idle connection is still open" (about 1 run in 20 on a busy machine).
		waitIdle(t, ln, i+1)
	}
	waitStats(t, ln, func(s ConnStats) bool { return s.Trusted == MaxConnsPerSender })
	time.Sleep(2500 * time.Millisecond) // longer than ReadHeaderTimeout: idle connections are not dropped after 2 s
	if s := ln.Stats(); s.Trusted != MaxConnsPerSender {
		t.Fatalf("the idle connections are gone: %+v", s)
	}
	// a request from this machine: answered at once
	start := time.Now()
	if st, err := metricsFrom(floodLocal, addr); err != nil || st != 200 {
		t.Fatalf("with 8 idle connections of a local user open, a request from this machine: HTTP %d, %v", st, err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatal("it had to wait", took)
	}
	// the update's real check, twelve times in a row (the installer asks once a second)
	cfg := healthCfg(t, "http://"+addr)
	for i := 0; i < 12; i++ {
		if err := CheckRunning(context.Background(), cfg, "test"); err != nil {
			t.Fatalf("health check %d with a local user's idle connections open: %v", i, err)
		}
	}
	s := ln.Stats()
	if s.Refused != 0 || s.Evicted == 0 || s.Evicted > 13 || s.Open > MaxConnsPerSender {
		t.Fatalf("%+v", s)
	}
	// the oldest idle connection was closed, not a newer one
	_ = held[0].SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := held[0].Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatal("the oldest idle connection is still open:", err)
	}
	// Only idle connections make room. One with a request in flight or an unfinished header is never closed
	// for another: a ninth connection then waits for a slot (TestRunLimitsConnections).
	// And only this machine's own: a stranger's ninth connection is refused as before, idle ones or not.
	for i := 0; i < MaxConnsPerSender; i++ {
		idleConn(t, "127.0.1.1", addr)
	}
	if st, err := metricsFrom("127.0.1.1", addr); err == nil {
		t.Fatal("a stranger's ninth connection was answered: HTTP", st)
	}
}

// Four of the 64 slots are for this machine alone: with every other slot taken by the panel and by strangers,
// the update's health check still gets in.
func TestConnLocalReserve(t *testing.T) {
	l := LimitConns(nil, ConnLimits{})
	if l.o.LocalReserved != 4 {
		t.Fatalf("%+v", l.o)
	}
	for _, c := range []struct {
		key     string
		trusted bool
	}{{"100.64.9.9", false}, {"panel", true}} {
		l = LimitConns(nil, ConnLimits{})
		for i := 0; i < 30; i++ {
			l.admit("panel", true)
			l.admit(fmt.Sprint("100.64.1.", i/8), false)
		}
		if st := l.Stats(); st.Open != 60 {
			t.Fatalf("%+v", st)
		}
		if why := l.admit(c.key, c.trusted); !strings.Contains(why, "kept for this machine") {
			t.Fatalf("61st connection that is not this machine's (%s): %q", c.key, why)
		}
		for i := 0; i < 4; i++ {
			if why := l.admit("local", true); why != "" {
				t.Fatal("this machine", i, why)
			}
		}
		if why := l.admit("local", true); why != "too many open connections" {
			t.Fatal("65th connection:", why)
		}
	}
	// this machine's own connections do not count against the others' 60
	l = LimitConns(nil, ConnLimits{})
	for i := 0; i < 8; i++ {
		l.admit("local", true)
	}
	for i := 0; i < 28; i++ {
		l.admit("panel", true)
		l.admit(fmt.Sprint("100.64.1.", i/8), false)
	}
	if st := l.Stats(); st.Open != 64 || st.Refused != 0 {
		t.Fatalf("%+v", st)
	}
}
