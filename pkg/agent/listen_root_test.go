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
	// a fifth from a root port finds the lane full: it waits (300 ms here) and is then closed
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
