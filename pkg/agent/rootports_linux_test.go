//go:build linux

package agent

import (
	"context"
	"net"
	"os"
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
	if port < 600 || s.Root != 1 || s.Trusted != 0 || s.Open != 0 {
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
	for i := 0; i < 12; i++ {
		start := time.Now()
		if err := CheckRunning(context.Background(), cfg, "test"); err != nil {
			t.Errorf("health check %d during the flood: %v (stats %+v)", i, err, ln.Stats())
		} else if took := time.Since(start); took > time.Second {
			t.Errorf("health check %d waited %s", i, took)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("the flood opened %d connections; stats %+v", opened.Load(), ln.Stats())
}
