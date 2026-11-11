package agent

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

// The update's health check, without the token on the wire.
//
// After the installer has swapped the program and restarted the service it must know that the agent it just
// started is the one answering on the agent's port, and which version it is. It used to ask GET /metrics with
// the read token. Whatever held the port at that moment received the token: a local program that took the
// port while the agent was restarting could read the machine's status and process list from then on.
//
// GET /health?c=<nonce>&p=<ask> sends no token. Both sides hold the same key K, made from the read token by a
// deliberately slow function (healthKey). The checker runs as root / LocalSystem on this machine, picks a
// fresh random nonce and sends
//
//	ask   = hex(HMAC-SHA256(K, "fairy-agent health ask v2" 0x00 nonce))
//
// The agent answers only a caller on this machine whose ask is right, with
//
//	{"proof": hex(HMAC-SHA256(K, "fairy-agent health v2" 0x00 nonce 0x00 version))}
//
// and the checker compares that with what it computes for the version it expects. Everybody else, and every
// request that is not exactly this, gets the answer of a path that does not exist (404 "not found").
//
// What nobody gets (review N1: the first form of this endpoint answered every address, without a token, with a
// value computed from the read token alone, which let any machine that reached the port test guesses of a
// hand-chosen token on its own, as fast as it could hash and without the agent's limit on wrong tokens):
//   - another machine: nothing, whatever it sends;
//   - a caller on this machine without the token: nothing that depends on the token. It can try a guess by
//     sending an ask made from it, which costs it one run of the slow function per guess;
//   - a program that took the agent's port: one nonce and one ask. The ask is under K, so testing a guess of
//     the token against it costs one run of the slow function too. With a token from `fairy-agent join` or
//     `gen-token` (256 random bits) there is nothing to guess in any case.
//
// The version is not in the answer: someone without the token learns nothing from it, not even which build
// runs here.

// HealthPath is the health check's endpoint.
const HealthPath = "/health"

const (
	healthLabel    = "fairy-agent health v2"
	healthAskLabel = "fairy-agent health ask v2"
	// healthKeyRounds is the cost of one guess of the read token against a health question or answer:
	// PBKDF2-HMAC-SHA256 with this many rounds (a fifth of a second on a PC, a second or two on a small ARM
	// board). The agent and the checker each pay it once per start.
	healthKeyRounds = 600_000
)

var healthNonceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

var (
	healthKeysMu sync.Mutex
	healthKeys   = map[[32]byte][32]byte{} // SHA-256(read token) -> K; one entry outside tests
)

// healthKey is the key of the health check for a read token (given as its SHA-256, which is all the agent
// keeps of it).
func healthKey(readHash [32]byte) [32]byte {
	healthKeysMu.Lock()
	defer healthKeysMu.Unlock()
	if k, ok := healthKeys[readHash]; ok {
		return k
	}
	var k [32]byte
	b, err := pbkdf2.Key(sha256.New, string(readHash[:]), []byte(healthLabel), healthKeyRounds, len(k))
	if err != nil { // cannot happen with these parameters; without a key nothing passes
		_, _ = rand.Read(k[:])
		return k
	}
	copy(k[:], b)
	if len(healthKeys) >= 8 {
		clear(healthKeys)
	}
	healthKeys[readHash] = k
	return k
}

func healthMAC(key [32]byte, parts ...string) string {
	m := hmac.New(sha256.New, key[:])
	for i, p := range parts {
		if i > 0 {
			m.Write([]byte{0})
		}
		m.Write([]byte(p))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// healthAsk is what the checker sends with its nonce: only a holder of the read token can compute it.
func healthAsk(key [32]byte, nonce string) string { return healthMAC(key, healthAskLabel, nonce) }

// healthProof is the answer to a health question: only a holder of the read token can compute it.
func healthProof(key [32]byte, nonce, version string) string {
	return healthMAC(key, healthLabel, nonce, version)
}

// isThisMachine reports whether a connection comes from this machine itself: from a loopback address, or
// from the very address it connected to.
func isThisMachine(remote, local netip.Addr) bool {
	return remote.IsValid() && (remote.IsLoopback() || (local.IsValid() && remote == local))
}

// health serves GET /health?c=<nonce>&p=<ask> (see the top of this file). It reports whether it answered; if
// not, the caller answers as for any path that does not exist.
func (a *Agent) health(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	var remote, local netip.Addr
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		remote = ap.Addr().Unmap().WithZone("")
	}
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		local = addrOf(la)
	}
	if !isThisMachine(remote, local) {
		return false
	}
	q := r.URL.Query()
	nonce, ask := q.Get("c"), q.Get("p")
	if !healthNonceRe.MatchString(nonce) || len(ask) != 2*sha256.Size {
		return false
	}
	// A caller on this machine can test a guess of the read token here: only the right one is answered. That
	// was not logged (audit 4, T-25). Now a wrong ask is written to the log, once a minute. It is not limited:
	// the update's check comes over this same route, and it cannot always be told from another local program's
	// asks (not on Windows; on Linux not when root's check has to come from an ordinary port, and not when the
	// installer is older than root's lane). A limit here made ten wrong asks of any local program enough to
	// fail the update in those cases (review R8), which is what counting /health in the wrong-token limiter
	// would do as well. What limits guessing is the cost of one guess (healthKeyRounds) and a random token.
	key := healthKey(a.readH)
	if subtle.ConstantTimeCompare([]byte(ask), []byte(healthAsk(key, nonce))) != 1 {
		a.logOnce("health", "health check: a request from this machine carried a wrong proof (a program here asks "+
			HealthPath+" without the read token, or tests guesses of it)", "remote", remote.String())
		return false
	}
	writeJSON(w, 200, map[string]any{"proof": healthProof(key, nonce, a.d.Version)})
	return true
}

// errNoHealth: the listener answered 404 to GET /health: a fairy-agent older than this check, one that was
// started with another read token (or does not see the checker as this machine), or no fairy-agent at all.
var errNoHealth = errors.New("no /health")

// CheckRunning asks the running agent to prove that it holds this machine's read token and runs version want
// (GET /health). The token itself is never sent.
func CheckRunning(ctx context.Context, cfg *Config, want string) error {
	err := checkRunning(ctx, cfg, want)
	if errors.Is(err, errNoHealth) {
		return fmt.Errorf("what answers on the agent's port does not know %s or does not hold this machine's read token: "+
			"it is not fairy-agent %s started with the token that is on disk now", HealthPath, want)
	}
	return err
}

// checkRunningFrom is CheckRunning for an installer of version self. A release older than self may be from
// before /health existed (it can only get here through `fairy-agent update --force` on the machine): then
// "the service is running", which the caller has checked, is all that can be said, and it is not asked for
// more. In particular it is not sent the token, as it used to be.
func checkRunningFrom(ctx context.Context, cfg *Config, self, want string) error {
	err := checkRunning(ctx, cfg, want)
	if !errors.Is(err, errNoHealth) {
		return err
	}
	if cmp, known := release.Compare(self, want); known && cmp >= 0 {
		return CheckRunning(ctx, cfg, want) // self or newer: it has /health, so this is not it
	}
	slog.Warn("health check: the agent on this machine does not know "+HealthPath+" (a release from before it): "+
		"only the service's state was checked", "version", want)
	return nil
}

func checkRunning(ctx context.Context, cfg *Config, want string) error {
	tok, err := cfg.LoadTokens()
	if err != nil {
		return err
	}
	addr, err := ListenAddr(ctx, cfg, 0)
	if err != nil {
		return err
	}
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
			addr = net.JoinHostPort("127.0.0.1", port)
		}
	}
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nb)
	key := healthKey(sha256.Sum256([]byte(tok.Read))) // before the clock of the request starts: it is slow once
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+HealthPath+"?c="+nonce+"&p="+healthAsk(key, nonce), nil)
	if err != nil {
		return err
	}
	// No Authorization header, no proxy, no redirect followed, no connection kept: whoever holds the port gets
	// one random nonce and the ask for it, and nothing else.
	// The connection comes from a port only root can use when this check runs as root on Linux (dialHealth).
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10, // the agent's answer has 150 bytes of header
		DialContext: dialHealth}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("agent not answering on %s", addr)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
	case 404:
		return errNoHealth
	default:
		return fmt.Errorf("agent answered HTTP %d", resp.StatusCode)
	}
	var m struct {
		Proof string `json:"proof"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&m); err != nil {
		return errors.New("agent answered with invalid JSON")
	}
	expect := healthProof(key, nonce, want)
	if subtle.ConstantTimeCompare([]byte(m.Proof), []byte(expect)) != 1 {
		return fmt.Errorf("what answers on %s did not prove that it is fairy-agent %s with this machine's token "+
			"(another version is running, or another program holds the port)", addr, want)
	}
	return nil
}
