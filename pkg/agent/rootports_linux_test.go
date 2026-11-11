//go:build linux

package agent

import (
	"context"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Audit 4, T-03, the real thing on Linux: as root the health check connects from a port below 1024, and a
// listener with the default limits counts it in root's own slots. Not as root it connects as before.
func TestHealthCheckComesFromARootPort(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := LimitConns(tcp, ConnLimits{})
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialHealth(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var srv net.Conn
	select {
	case srv = <-accepted:
		defer srv.Close()
	case <-ctx.Done():
		t.Fatal("the connection was not accepted")
	}
	port := c.LocalAddr().(*net.TCPAddr).Port
	s := ln.Stats()
	switch {
	case os.Geteuid() != 0 || rootPorts() == 0:
		if port < 1024 || s.Root != 0 || s.Trusted != 1 {
			t.Fatalf("not root (or no reserved ports here): port %d, stats %+v", port, s)
		}
		t.Skipf("not root, or this system does not reserve ports below 1024 (rootPorts %d): the check came from port %d as before", rootPorts(), port)
	case port >= 1024 && port != 0:
		// root without the right to use the ports (a container): the fall-back is the ordinary port
		t.Skipf("root here cannot use a port below 1024: the check came from port %d", port)
	}
	if port < healthPortLo || servicePorts[port] || s.Root != 1 || s.Trusted != 0 || s.Open != 0 {
		t.Fatalf("as root: port %d, stats %+v", port, s)
	}
}

// The installer's real check (CheckRunning) during the local flood of the finding: as root, every one passes.
func TestRootsRealHealthCheckDuringALocalFlood(t *testing.T) {
	if os.Geteuid() != 0 || rootPorts() == 0 {
		t.Skip("needs root and a system that reserves the ports below 1024 (the same with test ports: TestLocalFloodDoesNotStarveRootsHealthCheck)")
	}
	ln, addr := serveLimited(t, ConnLimits{})
	cfg := healthCfg(t, "http://"+addr)
	if err := CheckRunning(context.Background(), cfg, "test"); err != nil {
		t.Fatal("setup: the check without a flood:", err)
	}
	opened, stop := silentFlood(t, addr, 48)
	defer stop()
	waitStats(t, ln, func(s ConnStats) bool { return s.Trusted >= MaxConnsPerSender && s.Waiting >= MaxWaitingConns/4 })
	if st, err := metricsFrom(floodLocal, addr); err == nil && st == 200 {
		t.Log("note: an ordinary local request got through the flood this time")
	}
	var slowest time.Duration
	for i := 0; i < 12; i++ {
		start := time.Now()
		if err := CheckRunning(context.Background(), cfg, "test"); err != nil { // it has its own limit of 3 s
			t.Errorf("health check %d during the flood: %v (stats %+v)", i, err, ln.Stats())
		}
		slowest = max(slowest, time.Since(start))
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("the flood opened %d connections; the slowest check took %s; stats %+v", opened.Load(), slowest.Round(time.Millisecond), ln.Stats())
}

// When the check falls back to an ordinary port, and when it does not (the dial itself is played by the test).
func TestHealthDialFallsBackToAnOrdinaryPort(t *testing.T) {
	old := dialTCP
	t.Cleanup(func() { dialTCP = old })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	inUse := &net.OpError{Op: "dial", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	denied := &net.OpError{Op: "dial", Err: os.NewSyscallError("bind", syscall.EACCES)}
	refused := &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	for name, c := range map[string]struct {
		low       func(ctx context.Context) error // what a dial from one of root's ports does
		wantLow   int                             // how many of root's ports are tried
		wantPlain bool                            // whether an ordinary port is used then
		wantErr   bool
		atLeast   time.Duration
	}{
		"every port is taken":             {func(context.Context) error { return inUse }, 8, true, false, 0},
		"root may not use the ports":      {func(context.Context) error { return denied }, 1, true, false, 0},
		"the agent is not listening":      {func(context.Context) error { return refused }, 1, false, true, 0},
		"packets from low ports are lost": {func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, 1, true, false, rootDialWait},
	} {
		low, plain := 0, 0
		dialTCP = func(ctx context.Context, network, addr string, port int) (net.Conn, error) {
			if port == 0 {
				plain++
				return old(ctx, network, addr, 0)
			}
			if port < healthPortLo || port > healthPortHi || servicePorts[port] {
				t.Errorf("%s: port %d is not one the check may use", name, port)
			}
			low++
			return nil, c.low(ctx)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // far more than rootDialWait
		start := time.Now()
		conn, err := dialHealthAs(ctx, "tcp", ln.Addr().String(), true)
		took := time.Since(start)
		cancel()
		if conn != nil {
			conn.Close()
		}
		if low != c.wantLow || (plain == 1) != c.wantPlain || (err != nil) != c.wantErr || took < c.atLeast {
			t.Errorf("%s: %d tries from root's ports (want %d), ordinary port used %d times (want %v), err %v, took %s",
				name, low, c.wantLow, plain, c.wantPlain, err, took)
		}
	}
	// not root, or no reserved ports on this system: an ordinary port at once
	low := 0
	dialTCP = func(ctx context.Context, network, addr string, port int) (net.Conn, error) {
		if port != 0 {
			low++
		}
		return old(ctx, network, addr, 0)
	}
	if conn, err := dialHealthAs(context.Background(), "tcp", ln.Addr().String(), false); err != nil || low != 0 {
		t.Fatal(err, low)
	} else {
		conn.Close()
	}
}

// Review of the fix (R7): the port the check connects from must not get in the way of a real service. It is one
// of 512 to 1023 (the range the old r-commands and bindresvport use for clients), never one that a well-known
// service listens on.
func TestHealthSourcePortSelection(t *testing.T) {
	for _, p := range []int{514, 515, 543, 544, 548, 554, 563, 587, 593, 631, 636, 853, 873, 902, 989, 990, 992, 993, 995} {
		if !servicePorts[p] {
			t.Errorf("port %d (a common service) is not in the list of ports the check leaves alone", p)
		}
	}
	for p := range servicePorts {
		if p < healthPortLo || p > healthPortHi {
			t.Errorf("port %d in the list is outside %d to %d", p, healthPortLo, healthPortHi)
		}
	}
	// every number the random source can return, in turn: every result is allowed, and every allowed port comes
	got := map[int]bool{}
	n := healthPortHi - healthPortLo + 1
	for i := 0; i < n; i++ {
		k := -1
		p := healthSourcePort(func(m int) int {
			if m != n {
				t.Fatalf("the port is drawn from %d numbers, want %d", m, n)
			}
			k++ // after the first draw: a service port was drawn, so the next number
			return (i + k) % n
		})
		if p < healthPortLo || p > healthPortHi || servicePorts[p] {
			t.Fatalf("draw %d gave port %d", i, p)
		}
		got[p] = true
	}
	if want := n - len(servicePorts); len(got) != want {
		t.Fatalf("%d different ports were chosen, want all %d that are allowed", len(got), want)
	}
}

// freePort is a port nothing is bound to at this moment.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// holdConns accepts connections and holds them until the test ends; it reports each one.
func holdConns(t *testing.T) (addr string, accepted chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted = make(chan net.Conn, 16)
	t.Cleanup(func() {
		ln.Close()
		for {
			select {
			case c := <-accepted:
				c.Close()
			default:
				return
			}
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	return ln.Addr().String(), accepted
}

// A port that something on this machine listens on is never used: the check goes on to the next one. (With
// ordinary ports in place of root's, so that the test needs no root.)
func TestHealthDialSkipsAPortWithAListener(t *testing.T) {
	addr, _ := holdConns(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0") // "a service"
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	taken, free := busy.Addr().(*net.TCPAddr).Port, freePort(t)
	old := pickHealthPort
	t.Cleanup(func() { pickHealthPort = old })
	var picks []int
	pickHealthPort = func() int {
		p := free
		if len(picks) < 2 {
			p = taken
		}
		picks = append(picks, p)
		return p
	}
	c, err := dialHealthAs(context.Background(), "tcp", addr, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.LocalAddr().(*net.TCPAddr).Port; got != free || len(picks) != 3 {
		t.Fatalf("the check came from port %d after %d tries; want %d after 3 (port %d has a listener)", got, len(picks), free, taken)
	}
	// and the service was not disturbed: it still accepts
	probe, err := net.Dial("tcp", busy.Addr().String())
	if err != nil {
		t.Fatal("the listener on the port the check tried:", err)
	}
	probe.Close()
}

// After a check that gave up first (it timed out), its port can be listened on at once: the check's socket
// allows it (SO_REUSEADDR). Without that the port was refused to a service for a minute.
func TestHealthDialLeavesItsPortFreeForAListener(t *testing.T) {
	addr, accepted := holdConns(t)
	port := freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := dialTCP(ctx, "tcp", addr, port)
	if err != nil {
		t.Fatal(err)
	}
	srv := <-accepted
	c.Close() // the check gives up: its side closes first
	buf := make([]byte, 1)
	_ = srv.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := srv.Read(buf); err == nil || isTimeout(err) {
		t.Fatal("the other side did not see the check close:", err)
	}
	srv.Close() // now the check's old socket waits out its minute in the kernel
	for i := 0; i < 20; i++ {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))) // Go sets SO_REUSEADDR, as servers do
		if err != nil {
			t.Fatalf("try %d: a service cannot listen on port %d right after the check used it: %v", i, port, err)
		}
		l.Close()
		time.Sleep(10 * time.Millisecond)
	}
}
