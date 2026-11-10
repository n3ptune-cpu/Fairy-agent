package agent

import (
	"context"
	"crypto/hmac"
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
	"regexp"
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
// GET /health?c=<nonce> needs no token and gives none away. The agent answers
//
//	{"proof": hex(HMAC-SHA256(key = SHA-256(read token), "fairy-agent health v1" 0x00 nonce 0x00 version))}
//
// The checker picks a fresh random nonce, knows the read token (it runs as root / LocalSystem) and the version
// it expects, computes the same value and compares. A listener that does not hold the token cannot answer,
// and an old answer is no use for a new nonce. The version is not in the answer: someone without the token
// learns nothing from it, not even which build runs here.

// HealthPath is the health check's endpoint.
const HealthPath = "/health"

// healthPerMin is how many health questions one address may ask a minute (the installer asks once a second
// for at most two health timeouts).
const healthPerMin = 240

const healthLabel = "fairy-agent health v1"

var healthNonceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// healthProof is the answer to a health question: only a holder of the read token can compute it.
func healthProof(readHash [32]byte, nonce, version string) string {
	m := hmac.New(sha256.New, readHash[:])
	m.Write([]byte(healthLabel))
	m.Write([]byte{0})
	m.Write([]byte(nonce))
	m.Write([]byte{0})
	m.Write([]byte(version))
	return hex.EncodeToString(m.Sum(nil))
}

// health serves GET /health?c=<nonce>. No token: see the top of this file.
func (a *Agent) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	if !a.healthLim.allow(clientIP(r)) {
		writeJSON(w, 429, map[string]any{"error": "too many health checks; try again in a minute"})
		return
	}
	nonce := r.URL.Query().Get("c")
	if !healthNonceRe.MatchString(nonce) {
		writeJSON(w, 400, map[string]any{"error": "c must be 16 to 64 characters of A-Z a-z 0-9 _ -"})
		return
	}
	writeJSON(w, 200, map[string]any{"proof": healthProof(a.readH, nonce, a.d.Version)})
}

// errNoHealth: the listener answered 404 to GET /health (a fairy-agent older than this check, or not one).
var errNoHealth = errors.New("no /health")

// CheckRunning asks the running agent to prove that it holds this machine's read token and runs version want
// (GET /health). The token itself is never sent.
func CheckRunning(ctx context.Context, cfg *Config, want string) error {
	err := checkRunning(ctx, cfg, want)
	if errors.Is(err, errNoHealth) {
		return fmt.Errorf("what answers on the agent's port does not know %s: it is not fairy-agent %s", HealthPath, want)
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
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+HealthPath+"?c="+nonce, nil)
	if err != nil {
		return err
	}
	// No Authorization header, no proxy, no redirect followed, no connection kept: whoever holds the port gets
	// one random nonce and nothing else.
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
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
	expect := healthProof(sha256.Sum256([]byte(tok.Read)), nonce, want)
	if subtle.ConstantTimeCompare([]byte(m.Proof), []byte(expect)) != 1 {
		return fmt.Errorf("what answers on %s did not prove that it is fairy-agent %s with this machine's token "+
			"(another version is running, or another program holds the port)", addr, want)
	}
	return nil
}
