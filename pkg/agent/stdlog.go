package agent

import (
	"bytes"
	"io"
	"log"
	"log/slog"
)

// Go's own packages do not write through slog: they use the log package's standard logger, and slog.SetDefault
// sends what that logger gets into the agent's log, line by line as it is. One of those lines repeats what a
// host sent. net/http's client writes it when a host it keeps a connection to sends bytes that no request is
// waiting for (a second answer, or more body than the answer's Content-Length said):
//
//	Unsolicited response received on idle HTTP channel starting with "<up to 4 KiB of those bytes>"; err=...
//
// A host that sends a request's own header lines back there (a broken proxy, a hostile device) so puts the
// Authorization header, with a Home Assistant token, a BMC's or a plug's password, into the agent's log. No
// setting of an http.Client or an http.Transport switches the line off or sends it elsewhere.
//
// stdLogUnasked is how that line begins in every Go release so far (net/http's transport.go,
// readLoopPeekFailLocked). In Go 1.27 it is the only line the client side of net/http writes to the standard
// logger with a host's bytes in it; the others are fixed words, a Go type's name or what this program itself
// set (the list is with TestStdLogGuard).
const stdLogUnasked = "Unsolicited response received on idle HTTP channel"

// StdLogUnasked is the line the agent's log has instead of net/http's "Unsolicited response ..." line: fixed
// words, nothing of what the host sent.
const StdLogUnasked = "http: a host sent data nobody asked for on a kept connection (text not shown)"

// SetLog makes l the logger of this process (slog.Default) and guards the log package's standard logger behind
// it (GuardStdLog). Every program of the agent sets its logger with this, never with slog.SetDefault: that
// alone sends the standard logger's lines to l unguarded.
func SetLog(l *slog.Logger) {
	slog.SetDefault(l)
	GuardStdLog()
}

// GuardStdLog puts a guard in front of wherever the log package's standard logger writes now (standard error
// in a program that set no logger, the handler of slog.Default after slog.SetDefault). A line of net/http that
// repeats a host's bytes (stdLogUnasked) is written as StdLogUnasked, after whatever the logger put in front
// of the line (its date and time); every other line passes as it is. The agent's own lines go through slog,
// not through this logger, and are not looked at; in a program that set no logger slog writes through the
// standard logger, and there too a line passes unless it holds net/http's words.
//
// The words come with the level and the rate limit of the logger behind: in the agent's log that is INFO and,
// like every repeated message there (RateLimitLog), at most 30 lines a minute with the rest counted.
//
// slog.SetDefault takes the guard away again (it sets the standard logger's output anew): SetLog is its
// replacement. Calling GuardStdLog twice puts one guard there.
func GuardStdLog() {
	if _, guarded := log.Writer().(*stdLogGuard); !guarded {
		log.SetOutput(&stdLogGuard{to: log.Writer()})
	}
}

// stdLogGuard is the standard logger's output: the log package hands it one whole line with each Write.
type stdLogGuard struct{ to io.Writer }

func (g *stdLogGuard) Write(line []byte) (int, error) {
	at := bytes.Index(line, []byte(stdLogUnasked))
	if at < 0 {
		return g.to.Write(line)
	}
	safe := make([]byte, 0, at+len(StdLogUnasked)+1)
	safe = append(append(append(safe, line[:at]...), StdLogUnasked...), '\n')
	if _, err := g.to.Write(safe); err != nil {
		return 0, err
	}
	return len(line), nil
}
