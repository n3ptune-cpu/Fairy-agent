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

// dialHealth opens the health check's connection. Root connects from a port only root can use, so that the
// agent counts the connection in root's own slots (RootConns) and no local program can keep it waiting
// (audit 4, T-03). The ports are the ones bindresvport uses, 600 to 1023. Without root, without reserved
// ports, or when none of eight random ports is free, it connects from an ordinary port as before.
func dialHealth(ctx context.Context, network, addr string) (net.Conn, error) {
	if os.Geteuid() == 0 && rootPorts() > 0 {
		for range 8 {
			d := net.Dialer{LocalAddr: &net.TCPAddr{Port: 600 + rand.IntN(424)}}
			c, err := d.DialContext(ctx, network, addr)
			if err == nil {
				return c, nil
			}
			if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
				break // root without the right to use these ports (a container)
			}
			if !errors.Is(err, syscall.EADDRINUSE) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
				return nil, err // the agent does not answer: another port would not change that
			}
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
