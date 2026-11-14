package agent

import (
	"bytes"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// keepStdLog puts the log package's standard logger and slog's default back when the test ends.
func keepStdLog(t *testing.T) {
	t.Helper()
	oldSlog, oldOut, oldFlags, oldPrefix := slog.Default(), log.Writer(), log.Flags(), log.Prefix()
	t.Cleanup(func() {
		slog.SetDefault(oldSlog)
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	})
}

// lockedBuffer is a log's destination that two goroutines may write.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// What a host sent in net/http's line, as net/http formats it (transport.go, readLoopPeekFailLocked).
func unaskedLine(sent string) (format string, args []any) {
	return "Unsolicited response received on idle HTTP channel starting with %q; err=%v", []any{[]byte(sent), nil}
}

// The lines the client side of net/http (Go 1.27.4) writes through the log package's standard logger, and what
// the guard makes of each. Only the first holds bytes of a host.
//
//	transport.go, readLoopPeekFailLocked   "Unsolicited response received on idle HTTP channel starting with %q; err=%v"
//	    up to 4 KiB of what the host sent: rewritten (StdLogUnasked)
//	client.go, send                        "RoundTripper returned a response & error; ignoring response"
//	    fixed words: passes
//	transport.go, tryPutIdleConn           "dup idle pconn %p in freelist" (log.Fatalf)
//	    fixed words and an address in this process's memory: passes
//	cookie.go, sanitizeOrWarn              "net/http: invalid byte %q in %s; dropping invalid bytes"
//	    one byte of a cookie this program would set on a request; the agent sets none and has no cookie jar: passes
//	cookie.go, (*Cookie).String            "net/http: invalid Cookie.Domain %q; dropping domain attribute"
//	    a cookie this program would set in an answer; the agent sets none: passes
//	transport.go, (*transportRequest).logf  goes to a function in the request's context (net/http's own tests),
//	    never to the standard logger
//	internal/http2/transport.go, without GODEBUG=http2debug:
//	    "protocol error: received %T before a SETTINGS frame", "Transport: unhandled response frame type %T",
//	    "http2: Transport received unsolicited DATA frame; closing connection",
//	    "protocol error: received DATA after END_STREAM", "... before a HEADERS frame", "... on a HEAD request"
//	    fixed words and a Go type's name: pass
//	internal/http2 with GODEBUG=http2debug=1 or 2 (vlogf, the Framer's debug lines, "http2: Transport encoding
//	    header %q = %q"): Go's own debugging switch prints headers and frames of HTTP/2 connections. Only the
//	    client for releases (pkg/release) and `helper-trust set` can speak HTTP/2, and neither sends a secret;
//	    every client that sends one speaks HTTP/1.1 only: those for a device, a BMC's readings or a Home
//	    Assistant (pkg/devices, TestDeviceClientsSpeakHTTP1Only) and the BMC relay's
//	    (TestBMCRelayClientSpeaksHTTP1Only). These lines pass.
//
// The agent's own HTTP server does not write to the standard logger at all: it has an ErrorLog of its own
// (Agent.Server), at a level the agent's log does not show.
func TestStdLogGuard(t *testing.T) {
	marker := strings.Join([]string{"made", "up", "marker", "token"}, "-")
	sent := "GET /api/states/sensor.lab_plug_power HTTP/1.1\r\nAuthorization: Bearer " + marker + "\r\n\r\n"
	shows := func(text string) bool {
		return strings.Contains(text, marker) || strings.Contains(text, "Bearer") || strings.Contains(text, "Authorization") ||
			strings.Contains(text, "sensor.") || strings.Contains(text, "Unsolicited")
	}
	passing := []string{
		"RoundTripper returned a response & error; ignoring response",
		"net/http: invalid byte '\\x00' in Cookie.Value; dropping invalid bytes",
		"protocol error: received *http2.DataFrame before a SETTINGS frame",
		"Transport: unhandled response frame type *http2.PriorityFrame",
		"http2: Transport received unsolicited DATA frame; closing connection",
		"protocol error: received DATA after END_STREAM",
		"a line of some other package, with \"quotes\" and a = sign",
	}

	// the agent's log as cmd/fairy-agent sets it up: text lines, one message at most 30 times a minute
	t.Run("the agent's log", func(t *testing.T) {
		keepStdLog(t)
		var out lockedBuffer
		h := RateLimitLog(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo}), 30).(*rateHandler)
		now := time.Unix(1_800_000_000, 0)
		h.st.now = func() time.Time { return now }
		SetLog(slog.New(h))

		format, args := unaskedLine(sent)
		log.Printf(format, args...)
		got := out.String()
		if shows(got) {
			t.Fatalf("the log shows what the host sent: %s", got)
		}
		if strings.Count(got, "\n") != 1 || !strings.Contains(got, `level=INFO msg="`+StdLogUnasked+`"`) {
			t.Fatalf("the log has %q, want one INFO line with %q", got, StdLogUnasked)
		}
		// the same again and again: the rate limit of every repeated message
		for range 500 {
			log.Printf(format, args...)
		}
		if n := strings.Count(out.String(), StdLogUnasked); n != 30 {
			t.Errorf("%d lines for 501 such answers in one minute, want 30", n)
		}
		now = now.Add(61 * time.Second)
		log.Printf(format, args...)
		if got := out.String(); !strings.Contains(got, "suppressed=471") || shows(got) {
			t.Errorf("after a minute: %s", got)
		}

		// every other line of the standard logger is in the log as slog.SetDefault alone would put it there
		for _, line := range passing {
			var guarded, plain lockedBuffer
			SetLog(slog.New(slog.NewTextHandler(&guarded, &slog.HandlerOptions{ReplaceAttr: noTime})))
			log.Print(line)
			slog.SetDefault(slog.New(slog.NewTextHandler(&plain, &slog.HandlerOptions{ReplaceAttr: noTime})))
			log.Print(line)
			if guarded.String() != plain.String() || !strings.Contains(plain.String(), "level=INFO msg=") {
				t.Errorf("a line of the standard logger was changed:\n%s%s", guarded.String(), plain.String())
			}
		}

		// the agent's own lines do not go through the guard: one that quotes net/http's words stays as it is
		var own lockedBuffer
		SetLog(slog.New(slog.NewTextHandler(&own, &slog.HandlerOptions{ReplaceAttr: noTime})))
		slog.Info("fairy-agent listening", "version", "dev", "listen", "127.0.0.1:18200")
		slog.Warn("power source failed", "id", "lab-plug", "error", "Unsolicited response received on idle HTTP channel")
		want := "level=INFO msg=\"fairy-agent listening\" version=dev listen=127.0.0.1:18200\n" +
			"level=WARN msg=\"power source failed\" id=lab-plug error=\"Unsolicited response received on idle HTTP channel\"\n"
		if own.String() != want {
			t.Errorf("the agent's own lines:\n%swant:\n%s", own.String(), want)
		}
	})

	// a command that set no logger: the standard logger writes to standard error, with its date and time, and
	// slog writes through it
	t.Run("a command without a logger", func(t *testing.T) {
		keepStdLog(t)
		var out lockedBuffer
		log.SetOutput(&out)
		log.SetFlags(log.LstdFlags)
		GuardStdLog()
		GuardStdLog() // one guard, however often
		if g, ok := log.Writer().(*stdLogGuard); !ok || g.to != &out {
			t.Fatalf("the standard logger writes to %T", log.Writer())
		}
		format, args := unaskedLine(sent)
		log.Printf(format, args...)
		got := out.String()
		stamp, text, _ := strings.Cut(got, " http: ")
		if _, err := time.Parse("2006/01/02 15:04:05", stamp); err != nil || "http: "+text != StdLogUnasked+"\n" || shows(got) {
			t.Fatalf("the line is %q, want the date, the time and %q", got, StdLogUnasked)
		}
		for _, line := range passing {
			var guarded, plain lockedBuffer
			log.SetFlags(0)
			log.SetOutput(&guarded)
			GuardStdLog()
			log.Print(line)
			log.SetOutput(&plain)
			log.Print(line)
			if guarded.String() != plain.String() || plain.String() != line+"\n" {
				t.Errorf("a line of the standard logger was changed: %q, without the guard %q", guarded.String(), plain.String())
			}
		}
	})
}

// The BMC relay's client sends a BMC's password. It has TLS settings of its own and no ForceAttemptHTTP2, so
// it speaks HTTP/1.1 only (what GODEBUG=http2debug prints is never its header), and it keeps no connection (no
// host can send bytes on one after its answer).
func TestBMCRelayClientSpeaksHTTP1Only(t *testing.T) {
	c, _ := (&BMCRelay{}).client("")
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.ForceAttemptHTTP2 || tr.Protocols != nil || tr.TLSClientConfig == nil || len(tr.TLSNextProto) != 0 || !tr.DisableKeepAlives {
		t.Fatalf("the BMC relay's transport: %+v", c.Transport)
	}
}

func noTime(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

// No program of the agent sets its logger past the guard: slog.SetDefault and log.SetOutput are called in
// stdlog.go and nowhere else (the tests set what they like). The Windows-only files are read too.
func TestEveryProgramSetsItsLogThroughSetLog(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && path != root && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir // .git, .github
		}
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		files++
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if filepath.ToSlash(path) == "../../pkg/agent/stdlog.go" {
			if !bytes.Contains(src, []byte("slog.SetDefault(")) || !bytes.Contains(src, []byte("log.SetOutput(")) {
				t.Errorf("stdlog.go no longer sets the loggers")
			}
			return nil
		}
		for _, call := range []string{"slog.SetDefault(", "log.SetOutput("} {
			if bytes.Contains(src, []byte(call)) {
				t.Errorf("%s calls %s...): the standard logger's lines would reach the log unguarded. Use agent.SetLog", filepath.ToSlash(path), call)
			}
		}
		return nil
	})
	if err != nil || files < 100 {
		t.Fatalf("read %d files: %v", files, err)
	}
}
