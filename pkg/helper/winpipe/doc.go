// Package winpipe is the Windows named pipe between fairy-agent and fairy-agent-helper, with
// golang.org/x/sys/windows only (no other dependency): overlapped I/O with deadlines, a server that checks every
// client's identity, and a client that checks the server is the helper service's own process. Windows only;
// the protocol on top of it (pkg/helper/proto) is platform-independent.
package winpipe

// ErrNoPipe and ErrNotHelper are the client's errors.
var (
	ErrNoPipe    = errorString("the helper's pipe does not exist (helper not running)")
	ErrNotHelper = errorString("the pipe is not served by the fairy-agent-helper service")
)

type errorString string

func (e errorString) Error() string { return string(e) }
