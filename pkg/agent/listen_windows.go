//go:build windows

package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// soExclusiveAddrUse is SO_EXCLUSIVEADDRUSE (winsock2.h: ((int)(~SO_REUSEADDR))).
const soExclusiveAddrUse = ^windows.SO_REUSEADDR

// listenTCP opens the agent's port for exclusive use: without the option another program on the PC can, in
// some cases, open the same port next to the agent (with SO_REUSEADDR, or on a more specific address) and
// receive what was meant for it. If Windows refuses the option the port is opened as before and the log says
// so: an agent that listens is worth more than one that does not start.
func listenTCP(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
		}); err != nil {
			serr = err
		}
		if serr != nil {
			slog.Warn("could not open the agent's port for exclusive use (SO_EXCLUSIVEADDRUSE); opening it as before", "error", serr.Error())
		}
		return nil
	}}
	return lc.Listen(ctx, "tcp", addr)
}

// addrInUse reports whether a listen error means that another program holds the port: WSAEADDRINUSE, or
// WSAEACCES, which is what Windows answers when the other program opened it for exclusive use.
func addrInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEACCES)
}
