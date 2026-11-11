package agent

// Audit 4, T-25: /health answers a caller on this machine whose proof is made from the right read token, and
// nobody else. So a local program can test guesses of the token there: nothing was counted and nothing logged
// (300 wrong asks in 0.14 s in the verifier's run). Now a wrong ask is logged.
//
// Wrong asks are NOT limited. The first fix refused every ask from an ordinary port after ten wrong ones in a
// minute, and let only root's check through, which comes from a port below 1024 on Linux. The review showed
// that root's check comes from an ordinary port in three cases (root may not use low ports, packets from them
// are dropped, the installer is older than the lane), and there ten wrong asks of any local program made the
// update fail. No limit that sits on this route can spare a check it cannot tell from the guesses, so the
// limit is gone (review R8). The wrong-token limiter must not count these asks either: it is keyed by the
// address, and the update's check comes from the same address as every local program.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// healthAskText is the text of GET /health with the proof of token for nonce. It is made before a connection
// is opened: deriving the key from a token takes a moment (much longer with the race detector on a busy
// machine), and the server gives a connection two seconds to send its request. The first version of these
// tests derived the key after connecting, with another token for every wrong ask, and failed on a busy machine.
func healthAskText(token, nonce string) string {
	key := healthKey(sha256.Sum256([]byte(token)))
	return fmt.Sprintf("GET %s?c=%s&p=%s HTTP/1.1\r\nHost: agent\r\nConnection: close\r\n\r\n", HealthPath, nonce, healthAsk(key, nonce))
}

// wrongHealthRequests are n asks made from guesses of the read token (three guesses in turn: the agent counts
// wrong asks, not different guesses), and then the server's own key is made ready, so that no request of the
// test waits for it.
func wrongHealthRequests(n int) []string {
	reqs := make([]string, n)
	for i := range reqs {
		reqs[i] = healthAskText(fmt.Sprintf("a-guess-of-the-read-token-%d", i%3), fmt.Sprintf("bbbbbbbbbbbbbb%02d", i))
	}
	healthKey(sha256.Sum256([]byte(readTok)))
	return reqs
}

// sendHealth sends a prepared request from one of the test's root ports or from an ordinary one, and returns
// the status.
func sendHealth(t *testing.T, addr, request string, asRoot bool) int {
	t.Helper()
	dial := dialFrom
	if asRoot {
		dial = dialAsRoot
	}
	c, err := dial(floodLocal, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Minute)) // only so that a test that hangs ends
	if _, err := c.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// askHealth sends GET /health with the proof of token for nonce and returns the status.
func askHealth(t *testing.T, addr, token, nonce string, asRoot bool) int {
	t.Helper()
	return sendHealth(t, addr, healthAskText(token, nonce), asRoot)
}

// logBuffer collects the log; it may be read while the server still writes.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func captureLog(t *testing.T) *logBuffer {
	t.Helper()
	logs := &logBuffer{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return logs
}

// healthRig is an agent behind the real connection limiter, with the test's root ports.
func healthRig(t *testing.T) (a *Agent, addr string) {
	t.Helper()
	r := newRig(t, "")
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := LimitConns(tcp, rootLimits(t, ConnLimits{Local: isThisMachine}))
	srv := r.a.Server()
	srv.ErrorLog = nil
	srv.ReadHeaderTimeout, srv.ReadTimeout = time.Minute, time.Minute // not what these tests are about; a busy machine may be slow
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return r.a, ln.Addr().String()
}

// Wrong asks from this machine are written to the log, at most one line a minute, without the token or the
// guess. They never make a right ask fail, whichever port it comes from: the update's check must pass after
// any number of wrong asks of another local program, or that program could make every update roll back.
func TestHealthWrongAsksAreLoggedAndNeverRefuseTheCheck(t *testing.T) {
	logs := captureLog(t)
	_, addr := healthRig(t)
	const n = 25
	wrong := wrongHealthRequests(n)
	if st := askHealth(t, addr, readTok, "aaaaaaaaaaaaaaa0", false); st != 200 {
		t.Fatal("the right ask from an ordinary port, before any wrong one:", st)
	}
	start := time.Now()
	for i, req := range wrong {
		if st := sendHealth(t, addr, req, i%5 == 4); st != 404 { // most from an ordinary port, some from root's
			t.Fatalf("wrong ask %d: HTTP %d", i, st)
		}
	}
	// the update's check from an ordinary port: Windows, a root that may not use low ports, an older installer
	if st := askHealth(t, addr, readTok, "cccccccccccccccc", false); st != 200 {
		t.Fatalf("the update's check from an ordinary port after %d wrong asks of a local program: HTTP %d (a local program could make every update roll back)", n, st)
	}
	// and from one of root's ports
	if st := askHealth(t, addr, readTok, "dddddddddddddddd", true); st != 200 {
		t.Fatalf("root's check after %d wrong asks: HTTP %d", n, st)
	}
	// the wrong-token limiter knows nothing of all this: a request with the right token is answered
	if st, err := metricsFrom(floodLocal, addr); err != nil || st != 200 {
		t.Fatalf("/metrics with the right token after the wrong health asks: %d %v (they were counted as wrong tokens)", st, err)
	}
	lines := strings.Count(logs.String(), "health check: a request from this machine")
	if most := 1 + int(time.Since(start)/time.Minute); lines < 1 || lines > most {
		t.Fatalf("want one log line a minute about the wrong asks (1 to %d here), got %d:\n%s", most, lines, logs.String())
	}
	if strings.Contains(logs.String(), readTok) || strings.Contains(logs.String(), "a-guess-of") {
		t.Fatal("a token or a guess is in the log:\n" + logs.String())
	}
}
