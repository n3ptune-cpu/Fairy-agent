package agent

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// tokenConn opens a connection from src, sends one request with the read token and reads the answer; the
// connection stays open, idle.
func tokenConn(t *testing.T, src, addr string) net.Conn {
	t.Helper()
	c, err := dialFrom(src, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "GET /metrics HTTP/1.1\r\nHost: agent\r\nAuthorization: Bearer %s\r\n\r\n", readTok)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("setup: a request with the token:", resp, err)
	}
	resp.Body.Close()
	return c
}

// fillStrangers opens 8 connections from each of 6 addresses (127.0.<net>.1 to .6): every slot strangers may
// have. idle: each sent one complete request (no token) and is kept open by the agent; otherwise each holds an
// unfinished request.
func fillStrangers(t *testing.T, addr string, net int, idle bool) {
	t.Helper()
	for s := 0; s < 6; s++ {
		src := fmt.Sprintf("127.0.%d.%d", net, s+1)
		for i := 0; i < MaxConnsPerSender; i++ {
			if idle {
				idleConn(t, src, addr)
				continue
			}
			c, err := dialFrom(src, addr)
			if err != nil {
				t.Fatal(src, i, err)
			}
			t.Cleanup(func() { c.Close() })
			_, _ = c.Write([]byte("GET /metrics HTTP/1.1\r\nHost: agent\r\nX-Fill: aaaa"))
		}
	}
}

// Review N3. An agent whose tokens were set up by hand has no panel address on record, so the panel is a
// stranger there. Six senders with eight idle connections each (no token needed) took all 48 slots strangers
// may have; the 16 reserved ones were for an address nobody knew, and the panel was locked out for as long as
// the connections were held. (The reviewer's proof, and what follows from the fix.)
func TestHandConfiguredAgentKeepsAShareForTheTokenHolder(t *testing.T) {
	ln, addr := serveLimited(t, ConnLimits{Panel: func() string { return "" }})
	fillStrangers(t, addr, 3, true)
	waitStats(t, ln, func(s ConnStats) bool { return s.Open == 48 && s.Trusted == 0 })

	// the panel's first request ever: the oldest idle connection of a stranger makes room for it
	if st, err := metricsFrom(floodPanel, addr); err != nil || st != 200 {
		t.Fatalf("48 idle connections from 6 senders: the panel's /metrics with the right token: HTTP %d, %v (stats %+v)", st, err, ln.Stats())
	}
	if s := ln.Stats(); s.Evicted != 1 || s.Refused != 0 {
		t.Fatalf("%+v", s)
	}
	// From now on its address has the panel's share. Strangers take every slot they may have again, this time
	// with unfinished requests, which nothing closes for a newcomer ...
	// (each of them at the cost of one of the idle connections)
	fillStrangers(t, addr, 5, false)
	waitStats(t, ln, func(s ConnStats) bool { return s.Open-s.Trusted == MaxConns-ReservedConns && s.Evicted == 48 })
	if c, held, _ := halfOpen("127.0.4.1", addr, 16); held {
		c.Close()
		t.Fatal("a new stranger got in while strangers held every slot they may have")
	}
	// ... and the token holder is served all the same, with more connections than a stranger may have
	var mine []net.Conn
	for i := 0; i < 12; i++ {
		mine = append(mine, tokenConn(t, floodPanel, addr))
	}
	s := ln.Stats()
	if s.Trusted != 12 || s.Open != 60 {
		t.Fatalf("the token holder's connections are not counted as the panel's: %+v", s)
	}
	// a stranger with a wrong token gets none of this
	c, err := dialFrom("127.0.4.2", addr)
	if err == nil {
		defer c.Close()
		fmt.Fprintf(c, "GET /metrics HTTP/1.1\r\nHost: agent\r\nAuthorization: Bearer %s\r\n\r\n", "wrong-token-xxxxxxxxxxxxxxxxxxxxx")
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err == nil {
			t.Fatal("a stranger was answered while strangers held every slot they may have: HTTP", resp.StatusCode)
		}
	}
	for _, c := range mine {
		c.Close()
	}
}

// Who counts as known, and for how long.
func TestKnownSenders(t *testing.T) {
	panel := ""
	l := LimitConns(nil, ConnLimits{Panel: func() string { return panel }})
	conn := func(remote string) *limitedConn {
		c := fakeConn{remote: remote, local: "100.70.0.1:9101"}
		key, trusted := l.sender(c)
		lc := &limitedConn{Conn: c, l: l, sender: key, trusted: trusted, remote: addrOf(c.RemoteAddr())}
		l.mu.Lock()
		l.countConn(lc)
		l.mu.Unlock()
		return lc
	}
	a := conn("100.88.0.8:40000")
	if a.trusted || a.sender != "100.88.0.8" {
		t.Fatal(a.sender, a.trusted)
	}
	a.Vouch()
	// the connection itself moves to the panel's share, and so does the next one from that address
	if s := l.Stats(); !a.trusted || a.sender != "token 100.88.0.8" || s.Trusted != 1 || s.Open != 1 {
		t.Fatalf("%q %v %+v", a.sender, a.trusted, s)
	}
	if b := conn("100.88.0.8:40001"); !b.trusted || b.sender != "token 100.88.0.8" || l.capOf(b.sender, true) != MaxConnsPanel {
		t.Fatal(b.sender, b.trusted)
	}
	if c := conn("100.88.0.9:40000"); c.trusted {
		t.Fatal("another address is known too")
	}
	// closing gives the slot back under the key it is counted under now
	l.connClosed(a)
	if s := l.Stats(); s.Open != 2 || s.Trusted != 1 || l.open["100.88.0.8"] != 0 || l.open["token 100.88.0.8"] != 1 {
		t.Fatalf("%+v %v", s, l.open)
	}
	// not for ever: an hour after its last request with a token the address is a stranger again
	l.mu.Lock()
	l.known[netip.MustParseAddr("100.88.0.8")] = time.Now().Add(-knownSenderFor - time.Second)
	l.mu.Unlock()
	if c := conn("100.88.0.8:40002"); c.trusted {
		t.Fatal("still known after an hour")
	}
	// at most eight addresses are remembered: the one that asked longest ago goes
	for i := 0; i < maxKnownSenders+3; i++ {
		c := conn(fmt.Sprintf("100.90.0.%d:40000", i+1))
		c.Vouch()
		l.mu.Lock()
		l.known[c.remote] = time.Now().Add(time.Duration(i-20) * time.Minute)
		l.mu.Unlock()
	}
	l.mu.Lock()
	n := len(l.known)
	_, first := l.known[netip.MustParseAddr("100.90.0.1")]
	_, last := l.known[netip.MustParseAddr("100.90.0.11")]
	l.mu.Unlock()
	if n != maxKnownSenders || first || !last {
		t.Fatal(n, first, last)
	}

	// With a panel address on record nobody else gets the panel's share for showing a token (the owner's own
	// script on another machine stays one sender among others) ...
	panel = "100.88.0.7"
	l = LimitConns(nil, ConnLimits{Panel: func() string { return panel }})
	x := conn("100.88.0.8:40000")
	x.Vouch()
	if x.trusted || len(l.known) != 0 || !x.vouched {
		t.Fatal(x.sender, x.trusted, l.known)
	}
	if y := conn("100.88.0.8:40001"); y.trusted {
		t.Fatal(y.sender)
	}
	// ... and with only_from_panel nobody but the panel and this machine is let in at all
	panel = ""
	l = LimitConns(nil, ConnLimits{Panel: func() string { return panel }, PanelOnly: true})
	l.known[netip.MustParseAddr("100.88.0.8")] = time.Now()
	if key, trusted := l.sender(fakeConn{remote: "100.88.0.8:40000", local: "100.70.0.1:9101"}); trusted || l.admit(key, trusted) != NoPanelRefusal {
		t.Fatal(key, trusted)
	}
}

// A connection that showed a valid token is never closed to make room for a stranger, and a stranger's own
// idle connections do not get it a ninth one.
func TestIdleConnOfATokenHolderIsNotClosedForAStranger(t *testing.T) {
	ln, addr := serveLimited(t, ConnLimits{}) // a paired agent: floodPanel is the panel
	// the owner's script on another machine: one idle connection that showed the token
	mine := tokenConn(t, "127.0.2.50", addr)
	// strangers fill the rest of their 48 with idle connections
	for s := 0; s < 6; s++ {
		for i := 0; i < MaxConnsPerSender; i++ {
			if s == 5 && i == MaxConnsPerSender-1 {
				break
			}
			idleConn(t, fmt.Sprintf("127.0.3.%d", s+1), addr)
		}
	}
	waitStats(t, ln, func(s ConnStats) bool { return s.Open == 48 })
	// ten more strangers, one after the other: each gets in at the cost of another stranger's idle connection
	for i := 0; i < 10; i++ {
		idleConn(t, fmt.Sprintf("127.0.4.%d", i+1), addr)
	}
	if s := ln.Stats(); s.Evicted != 10 || s.Open != 48 {
		t.Fatalf("%+v", s)
	}
	// the token holder's connection is still there and still works
	fmt.Fprintf(mine, "GET /metrics HTTP/1.1\r\nHost: agent\r\nAuthorization: Bearer %s\r\n\r\n", readTok)
	_ = mine.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp, err := http.ReadResponse(bufio.NewReader(mine), nil); err != nil || resp.StatusCode != 200 {
		t.Fatal("the token holder's idle connection was closed for a stranger:", err)
	}
}
