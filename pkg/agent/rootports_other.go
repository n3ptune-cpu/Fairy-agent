//go:build !linux

package agent

import (
	"context"
	"net"
)

// rootPorts: only Linux is known to keep source ports for root in a way this program can check (see
// rootports_linux.go). Windows has no such ports at all.
func rootPorts() int { return 0 }

// dialHealth opens the health check's connection.
func dialHealth(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
