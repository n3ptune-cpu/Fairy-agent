//go:build !windows

package agent

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// listenTCP opens the agent's port.
func listenTCP(ctx context.Context, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", addr)
}

// addrInUse reports whether a listen error means that another program holds the port.
func addrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
