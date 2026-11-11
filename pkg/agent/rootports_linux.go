//go:build linux

package agent

import (
	"context"
	"errors"
	"io/fs"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// rootPorts returns the number below which a source port can only be used by root (or a program that was
// given CAP_NET_BIND_SERVICE) on this machine: 1024, or 0 when the system does not reserve them. Linux keeps
// the limit in net.ipv4.ip_unprivileged_port_start (also for IPv6); some machines lower it, for containers
// that run without root. Then no port proves anything and there is no lane for root (LimitConns).
func rootPorts() int {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	if errors.Is(err, fs.ErrNotExist) { // a kernel before 4.11: the limit is always 1024
		return 1024
	}
	if err != nil {
		return 0
	}
	if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err != nil || n < 1024 {
		return 0
	}
	return 1024
}

// rootDialWait is how long a connection from one of root's ports may take to open before the check uses an
// ordinary port instead. A connection to this machine's own address opens or is refused at once; one that
// just hangs means that something on the machine drops packets from low source ports.
const rootDialWait = time.Second

// dialTCP connects to addr, from the given source port when it is not 0. (A variable for the tests.)
var dialTCP = func(ctx context.Context, network, addr string, port int) (net.Conn, error) {
	var d net.Dialer
	if port > 0 {
		d.LocalAddr = &net.TCPAddr{Port: port}
	}
	return d.DialContext(ctx, network, addr)
}

// dialHealth opens the health check's connection. Root connects from a port only root can use, so that the
// agent counts the connection in root's own slots (RootConns) and no local program can keep it waiting
// (audit 4, T-03). The ports are the ones bindresvport uses, 600 to 1023.
func dialHealth(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialHealthAs(ctx, network, addr, os.Geteuid() == 0 && rootPorts() > 0)
}

// dialHealthAs is dialHealth; fromRootPort says whether a port only root can use is tried first. The check
// connects from an ordinary port, as it always did, when it is not root, when the system has no such ports,
// when none of eight random ones can be bound (in use, or root may not use them, as in some containers), and
// when the connection from such a port does not open within rootDialWait. If the agent refuses the connection
// (it is not listening yet) that is the answer: an ordinary port would be refused too.
func dialHealthAs(ctx context.Context, network, addr string, fromRootPort bool) (net.Conn, error) {
	if fromRootPort {
		rctx, cancel := context.WithTimeout(ctx, rootDialWait)
		defer cancel()
		for range 8 {
			c, err := dialTCP(rctx, network, addr, 600+rand.IntN(424))
			if err == nil {
				return c, nil
			}
			if errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EADDRNOTAVAIL) {
				continue // that port is taken: another one
			}
			if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || rctx.Err() != nil {
				break // root may not use these ports here, or the connection did not open in time
			}
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return dialTCP(ctx, network, addr, 0)
}
