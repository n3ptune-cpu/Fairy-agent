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

// The check's source port is one of healthPortLo to healthPortHi: the range that programs which prove "I am
// root" by their port have always taken theirs from (rlogin, rsh, bindresvport).
const healthPortLo, healthPortHi = 512, 1023

// servicePorts are the ports in that range that a well-known service listens on. The check never connects
// from one of them, so it cannot be in the way when such a service starts (see dialTCP for the rest).
var servicePorts = map[int]bool{
	512: true, 513: true, 514: true, // exec, login, shell (and syslog over TCP)
	515: true,            // printer (lpd)
	530: true,            // courier RPC
	540: true,            // uucp
	543: true, 544: true, // klogin, kshell
	548: true,                       // AFP
	554: true,                       // RTSP
	563: true,                       // NNTP over TLS
	587: true,                       // mail submission
	593: true,                       // RPC over HTTP
	631: true,                       // IPP (CUPS)
	636: true,                       // LDAP over TLS
	646: true,                       // LDP
	655: true,                       // tinc
	749: true, 750: true, 754: true, // Kerberos administration
	783: true,            // spamd
	808: true,            // an HTTP alternative
	853: true,            // DNS over TLS
	860: true,            // iSCSI
	873: true,            // rsync
	902: true,            // VMware
	953: true,            // rndc
	989: true, 990: true, // FTP over TLS
	992: true, 993: true, 994: true, 995: true, // telnet, IMAP, IRC and POP3 over TLS
}

// healthSourcePort draws the check's source port: one of healthPortLo to healthPortHi that is not in
// servicePorts. intn(n) returns a random number from 0 to n-1.
func healthSourcePort(intn func(n int) int) int {
	for {
		if p := healthPortLo + intn(healthPortHi-healthPortLo+1); !servicePorts[p] {
			return p
		}
	}
}

// pickHealthPort is the port the next try connects from. (A variable for the tests.)
var pickHealthPort = func() int { return healthSourcePort(rand.IntN) }

// dialTCP connects to addr, from the given source port when it is not 0. (A variable for the tests.)
//
// With a source port the socket gets SO_REUSEADDR. Two things follow, both wanted. A port that anything on
// this machine listens on is still refused to the check (the kernel says "address in use" and the check takes
// another port). And a service that sets SO_REUSEADDR itself, as servers do, can start to listen on the port
// while, or right after, the check used it: without the option the port was refused to it for a minute after
// a check that gave up first. (A service that does not set it is still refused for that time, as before.)
var dialTCP = func(ctx context.Context, network, addr string, port int) (net.Conn, error) {
	var d net.Dialer
	if port > 0 {
		d.LocalAddr = &net.TCPAddr{Port: port}
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	return d.DialContext(ctx, network, addr)
}

// dialHealth opens the health check's connection. Root connects from a port only root (or a program with
// CAP_NET_BIND_SERVICE) can use, so that the agent counts the connection in root's own slots (RootConns) and
// the agent's connection limiter cannot be used by another local program to keep the check waiting (audit 4,
// T-03).
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
			c, err := dialTCP(rctx, network, addr, pickHealthPort())
			if err == nil {
				return c, nil
			}
			if errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EADDRNOTAVAIL) {
				continue // that port is taken (something listens on it, or uses it for the same address): another one
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
