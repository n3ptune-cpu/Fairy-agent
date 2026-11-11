package agent

// Audit 4, T-03: connections from this machine share 8 slots and 32 places to wait. A local program without a
// token and without any right filled both with connections that say nothing (16 sockets and 4 new connections
// a second were enough). The update's health check, which also comes from this machine, was reset or waited
// too long, so every update was rolled back, and root's own `fairy-agent update` too.
//
// Now connections from this machine that come from a source port only root can use have four slots of their
// own (ConnLimits.RootPort), and the health check of a root installer comes from such a port. In these tests
// the ports that count as "only root" are chosen by the test, so they run without root and on every system.
// (On Linux the real ports and the real check are tested in rootports_linux_test.go.)

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// In these tests the source ports 20000 to 29999 stand for the ports only root can use. They are below the
// ports a system gives out by itself (Linux from 32768, Windows from 49152), so the flood's connections never
// come from one of them.
const testRootLo, testRootHi = 20000, 30000

func testRootPort(p int) bool { return p >= testRootLo && p < testRootHi }

// rootLimits are ConnLimits with the test's root ports. The test is skipped on a system that gives such ports
// out by itself.
func rootLimits(t *testing.T, o ConnLimits) ConnLimits {
	t.Helper()
	for i := 0; i < 8; i++ {
		l, err := net.Listen("tcp", floodLocal+":0")
		if err != nil {
			t.Fatal(err)
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if testRootPort(p) {
			t.Skipf("this system gives out port %d by itself: the test cannot tell its root ports from others", p)
		}
	}
	o.RootPort = testRootPort
	return o
}

// dialAsRoot connects from src and one of the test's root ports (a free one, picked at random).
func dialAsRoot(src, addr string) (c net.Conn, err error) {
	for i := 0; i < 20; i++ {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src), Port: testRootLo + rand.IntN(testRootHi-testRootLo)}, Timeout: 5 * time.Second}
		if c, err = d.Dial("tcp", addr); err == nil {
			return c, nil
		}
	}
	return nil, err
}

// healthFrom is the update's health check (GET /health with the ask of the read token), sent from one of the
// test's root ports or from an ordinary one. It reports whether the agent answered with the right proof.
//
// The key is made before the connection is opened (it takes a moment, and the server gives a connection two
// seconds for its request), and the time limit is only there so that a test that hangs ends: how long an
// answer takes on a busy test machine says nothing about the agent.
func healthFrom(src string, asRoot bool, addr, nonce string) error {
	key := healthKey(sha256.Sum256([]byte(readTok)))
	dial := dialFrom
	if asRoot {
		dial = dialAsRoot
	}
	c, err := dial(src, addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := fmt.Fprintf(c, "GET %s?c=%s&p=%s HTTP/1.1\r\nHost: agent\r\nConnection: close\r\n\r\n", HealthPath, nonce, healthAsk(key, nonce)); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var m struct {
		Proof string `json:"proof"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&m) != nil || m.Proof != healthProof(key, nonce, "test") {
		return fmt.Errorf("HTTP %d, proof %q", resp.StatusCode, m.Proof)
	}
	return nil
}

// silentFlood is the local program of the finding: n workers, each opens a connection from this machine, says
// nothing (or, every third worker, half a request), waits until the agent closes it and opens the next.
func silentFlood(t *testing.T, addr string, n int) (opened *atomic.Int64, stop func()) {
	t.Helper()
	opened = new(atomic.Int64)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			buf := make([]byte, 1)
			for {
				select {
				case <-done:
					return
				default:
				}
				c, err := dialFrom(floodLocal, addr)
				if err != nil {
					time.Sleep(20 * time.Millisecond)
					continue
				}
				opened.Add(1)
				if i%3 == 0 {
					_, _ = c.Write([]byte("GET /health?c=aaaaaaaaaaaaaaaa&p=")) // looks like the start of a check
				}
				start := time.Now()
				_ = c.SetReadDeadline(start.Add(6 * time.Second))
				_, _ = c.Read(buf) // returns when the agent closes or resets the connection
				c.Close()
				if time.Since(start) < 100*time.Millisecond { // reset at once: no slot and no place to wait
					time.Sleep(floodPause(5 * time.Millisecond))
				}
			}
		}(i)
	}
	return opened, func() { close(done); wg.Wait() }
}

func TestLocalFloodDoesNotStarveRootsHealthCheck(t *testing.T) {
	ln, addr := serveLimited(t, rootLimits(t, ConnLimits{}))
	_ = healthKey(sha256.Sum256([]byte(readTok))) // the slow key, before the clock runs
	if err := healthFrom(floodLocal, false, addr, "0000000000000000"); err != nil {
		t.Fatal("setup: the health check without a flood:", err)
	}
	opened, stop := silentFlood(t, addr, 48)
	defer stop()
	waitStats(t, ln, func(s ConnStats) bool { return s.Trusted >= MaxConnsPerSender && s.Waiting >= MaxWaitingConns/4 })

	// The same check from an ordinary port of this machine: the flood keeps it out, as the finding says. (This
	// is what a check that is not root's still meets. If it starts to pass, the flood above tests nothing.)
	ordinary := 0
	for i := 0; i < 5; i++ {
		if healthFrom(floodLocal, false, addr, fmt.Sprintf("%016d", i)) == nil {
			ordinary++
		}
	}
	// Root's check: every one is answered. (How fast is logged, not judged: that depends on the test machine.)
	i := 0
	var slowest time.Duration
	for ; i < 16; i++ {
		start := time.Now()
		if err := healthFrom(floodLocal, true, addr, fmt.Sprintf("%016d", 100+i)); err != nil {
			t.Errorf("health check %d from a port only root can use, during the flood: %v (stats %+v)", i, err, ln.Stats())
		}
		slowest = max(slowest, time.Since(start))
		time.Sleep(100 * time.Millisecond)
	}
	s := ln.Stats()
	t.Logf("the flood opened %d connections; checks from an ordinary port answered: %d of 5; from root's ports: %d asked, the slowest took %s; stats %+v",
		opened.Load(), ordinary, i, slowest.Round(time.Millisecond), s)
	if ordinary == 5 {
		t.Errorf("the flood did not keep an ordinary local connection out: this test no longer shows the finding")
	}
	if s.Trusted < MaxConnsPerSender || s.Waiting == 0 {
		t.Errorf("the flood was not running to the end: %+v", s)
	}
}

// Root's lane has four slots of its own, outside every other cap, and gives them back.
func TestRootLaneHasItsOwnSlots(t *testing.T) {
	ln, addr := serveLimited(t, rootLimits(t, ConnLimits{Wait: 300 * time.Millisecond}))
	var held []net.Conn
	for i := 0; i < RootConns; i++ { // four silent connections from root's ports
		c, err := dialAsRoot(floodLocal, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		held = append(held, c)
	}
	s := waitStats(t, ln, func(s ConnStats) bool { return s.Root == RootConns })
	if s.Open != 0 || s.Trusted != 0 {
		t.Fatalf("root's connections are counted in the other caps: %+v", s)
	}
	// this machine's ordinary slots are all still there
	for i := 0; i < MaxConnsPerSender; i++ {
		idleConn(t, floodLocal, addr)
	}
	if s := ln.Stats(); s.Trusted != MaxConnsPerSender || s.Root != RootConns || s.Refused != 0 {
		t.Fatalf("%+v", s)
	}
	// a fifth from a root port finds the lane full of connections that are not idle: it is closed at once
	c5, err := dialAsRoot(floodLocal, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c5.Close()
	_ = c5.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c5.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatal("a fifth connection in root's lane was not closed:", err)
	}
	// closing them gives the slots back
	for _, c := range held {
		c.Close()
	}
	waitStats(t, ln, func(s ConnStats) bool { return s.Root == 0 })
	if err := healthFrom(floodLocal, true, addr, "1111111111111111"); err != nil {
		t.Fatal(err)
	}
	waitStats(t, ln, func(s ConnStats) bool { return s.Root == 0 })
}

// Only this machine has the lane: the same source port from another address is a stranger like any other.
func TestRootLaneIsForThisMachineOnly(t *testing.T) {
	ln, addr := serveLimited(t, ConnLimits{RootPort: func(int) bool { return true }})
	for i := 0; i < MaxConnsPerSender; i++ {
		idleConn(t, "127.0.1.1", addr)
	}
	s := ln.Stats()
	if s.Root != 0 || s.Open != MaxConnsPerSender || s.Trusted != 0 {
		t.Fatalf("%+v", s)
	}
	c, err := dialFrom("127.0.1.1", addr) // all idle: a stranger's ninth is refused, as before
	if err == nil {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
			t.Fatal("a stranger's ninth connection was not closed:", err)
		}
	}
	// and from this machine every connection is in the lane now (RootPort says yes to every port)
	if err := healthFrom(floodLocal, false, addr, "2222222222222222"); err != nil {
		t.Fatal(err)
	}
}

// Review of the fix (R5): four idle connections in root's lane (one answered request each, then nothing) kept
// root's check out for as long as they were held, which the same connections in the ordinary local lane cannot
// do any more (review N2 of audit 3). An idle connection in root's lane makes room in the same way now.
func TestRootLaneIdleConnectionsMakeRoom(t *testing.T) {
	ln, addr := serveLimited(t, rootLimits(t, ConnLimits{}))
	var held []net.Conn
	for i := 0; i < RootConns; i++ {
		c, err := dialAsRoot(floodLocal, addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "GET /metrics HTTP/1.1\r\nHost: agent\r\n\r\n") // a complete request without a token, kept alive
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil || resp.StatusCode != 401 {
			t.Fatal("setup:", resp, err)
		}
		resp.Body.Close()
		held = append(held, c)
	}
	waitStats(t, ln, func(s ConnStats) bool { return s.Root == RootConns })
	// The server marks a connection idle a moment after its answer was read here, so the first check is asked
	// until it passes. Before the change it never did: the four were held for the 90 s an idle connection may stay.
	deadline := time.Now().Add(20 * time.Second)
	for n := 0; ; n++ {
		err := healthFrom(floodLocal, true, addr, fmt.Sprintf("%016d", 5000+n))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("root's check with %d idle connections in root's lane: %v (stats %+v)", RootConns, err, ln.Stats())
		}
		time.Sleep(20 * time.Millisecond)
	}
	for i := 0; i < 6; i++ { // and every one after it, more often than there are idle connections
		if err := healthFrom(floodLocal, true, addr, fmt.Sprintf("%016d", 6000+i)); err != nil {
			t.Fatalf("root's check %d with idle connections in root's lane: %v (stats %+v)", i, err, ln.Stats())
		}
	}
	s := ln.Stats()
	if s.Evicted == 0 || s.Root > RootConns || s.Open != 0 {
		t.Fatalf("%+v", s)
	}
	// As many of the held connections were closed as the listener says, and no more. (Which one is the oldest
	// idle one is the server's business: it marks them idle in its own time. A closed connection says so at
	// once; an open one says nothing, so the read gives up after a moment.)
	closed := 0
	for _, c := range held {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err != nil && !isTimeout(err) {
			closed++
		}
	}
	if closed == 0 || closed > int(s.Evicted) {
		t.Fatalf("%d of the %d idle connections in root's lane were closed; the listener closed %d to make room", closed, len(held), s.Evicted)
	}
}

// Review of the fix (R6): a connection over the cap of root's lane waited in the PANEL's waiting room, so a
// dozen connections from low ports filled it and the panel's next connection over its own cap was reset
// instead of waiting. The lane gives four slots and nothing else: a fifth connection is closed at once.
// (The listener alone, without the HTTP server, so that nothing in this test depends on a time limit.)
func TestRootLaneTakesNoPlaceInThePanelsWaitingRoom(t *testing.T) {
	if probe, err := net.Listen("tcp", floodPanel+":0"); err != nil {
		t.Skip("this system has no other 127.0.0.0/8 addresses to connect from:", err)
	} else {
		probe.Close()
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	const panelSlots, room = 8, 8
	o := rootLimits(t, ConnLimits{PerPanel: panelSlots, Waiting: room, Wait: 10 * time.Minute,
		Panel: func() string { return floodPanel },
		Local: func(remote, _ netip.Addr) bool { return remote.String() == floodLocal }})
	ln := LimitConns(tcp, o)
	var mu sync.Mutex
	var open, served []net.Conn // every connection of the test; those the limiter let through (the server's side)
	keep := func(c net.Conn) {
		mu.Lock()
		open = append(open, c)
		mu.Unlock()
	}
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range open {
			c.Close()
		}
	})
	go func() { // the "server": takes every connection the limiter lets through and holds it
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			keep(c)
			mu.Lock()
			served = append(served, c)
			mu.Unlock()
		}
	}()
	addr := ln.Addr().String()
	dial := func(from func(src, addr string) (net.Conn, error), src string) net.Conn {
		t.Helper()
		c, err := from(src, addr)
		if err != nil {
			t.Fatal(err)
		}
		keep(c)
		return c
	}
	for i := 0; i < panelSlots; i++ { // the panel has all of its slots in use
		dial(dialFrom, floodPanel)
	}
	for i := 0; i < RootConns; i++ { // root's lane is full
		dial(dialAsRoot, floodLocal)
	}
	waitStats(t, ln, func(s ConnStats) bool { return s.Open == panelSlots && s.Root == RootConns })
	// As many more from root's ports as the panel's waiting room has places. Each must be closed at once. (A
	// reset can reach the dialer before its connect has returned; then dialAsRoot tries again, so more than
	// room connections may be refused here.)
	var extra []net.Conn
	for i := 0; i < room; i++ {
		if c, err := dialAsRoot(floodLocal, addr); err == nil {
			keep(c)
			extra = append(extra, c)
		}
	}
	s := waitStats(t, ln, func(s ConnStats) bool { return s.Waiting > 0 || int(s.Refused) >= room })
	if s.Waiting != 0 || s.Root != RootConns {
		t.Fatalf("connections over the cap of root's lane wait for a slot (they wait in the panel's room): %+v", s)
	}
	for _, c := range extra { // every one of them was closed by the listener
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
			t.Fatalf("a connection over the cap of root's lane was not closed: %v (stats %+v)", err, ln.Stats())
		}
	}
	refused := ln.Stats().Refused
	// the panel's next connection finds its room empty and waits
	dial(dialFrom, floodPanel)
	s = waitStats(t, ln, func(s ConnStats) bool { return s.Waiting > 0 || s.Refused > refused })
	if s.Waiting != 1 || s.Refused != refused {
		t.Fatalf("the panel's connection over its cap was refused instead of waiting: %+v", s)
	}
	// and it gets the slot one of the panel's connections gives back
	mu.Lock()
	first := served[0] // the panel's first connection: the "server" is done with it
	mu.Unlock()
	if addrOf(first.RemoteAddr()).String() != floodPanel {
		t.Fatal("setup: the first connection served is not the panel's:", first.RemoteAddr())
	}
	first.Close()
	waitStats(t, ln, func(s ConnStats) bool { return s.Waiting == 0 && s.Waited == 1 && s.Open == panelSlots })
}
