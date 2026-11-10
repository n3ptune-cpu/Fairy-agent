package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// healthCfg is a config whose listen address is srv and whose token files hold the test tokens.
func healthCfg(t *testing.T, url string) *Config {
	t.Helper()
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "token"), []byte(readTok), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "control-token"), []byte(ctlTok), 0o600)
	cfg, err := Parse([]byte("listen: "+strings.TrimPrefix(url, "http://")+"\nself_update: {enabled: true}\n"), filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// recorder is a program that holds the agent's port: it keeps everything it is sent.
type recorder struct {
	mu   sync.Mutex
	seen []string // every request, complete: request line, headers, body
	h    http.HandlerFunc
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var sb strings.Builder
	sb.WriteString(r.Method + " " + r.RequestURI + " " + r.Host + "\n")
	_ = r.Header.Write(&sb)
	sb.Write(b)
	rec.mu.Lock()
	rec.seen = append(rec.seen, sb.String())
	rec.mu.Unlock()
	rec.h(w, r)
}

// leaked fails the test if anything the recorder saw carries one of the tokens, in any header, the address or
// the body.
func (rec *recorder) leaked(t *testing.T, what string) {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.seen) == 0 {
		t.Fatalf("%s: the listener was not asked at all", what)
	}
	for _, req := range rec.seen {
		low := strings.ToLower(req)
		if strings.Contains(req, readTok) || strings.Contains(req, ctlTok) || strings.Contains(low, "authorization") ||
			strings.Contains(low, "bearer") {
			t.Fatalf("%s: the listener on the agent's port was sent a token:\n%s", what, req)
		}
	}
}

func TestHealthEndpoint(t *testing.T) {
	r := newUpdRig(t, "42-bbbbbbb", nil)
	get := func(path, tok string) (int, map[string]any, string) {
		req, _ := http.NewRequest("GET", r.srv.URL+path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return resp.StatusCode, m, string(b)
	}
	nonce := "0123456789abcdef0123456789abcdef"
	want := healthProof(sha256.Sum256([]byte(readTok)), nonce, "42-bbbbbbb")
	// no token needed, and a token changes nothing
	for _, tok := range []string{"", readTok, ctlTok, "wrong-token-xxxxxxxxxxxxxxxxxxxxx"} {
		st, m, raw := get("/health?c="+nonce, tok)
		if st != 200 || m["proof"] != want || len(m) != 1 {
			t.Fatalf("token %q: %d %s", tok, st, raw)
		}
		// nothing about the machine or the build is in the answer
		for _, secret := range []string{"42", "bbbbbbb", readTok, ctlTok, "version", "hostname"} {
			if strings.Contains(raw, secret) && !strings.Contains(want, secret) {
				t.Fatalf("the answer shows %q: %s", secret, raw)
			}
		}
	}
	// the proof depends on the nonce, the version and the token
	if p := healthProof(sha256.Sum256([]byte(readTok)), "fedcba9876543210fedcba9876543210", "42-bbbbbbb"); p == want {
		t.Fatal("same proof for another nonce")
	}
	if p := healthProof(sha256.Sum256([]byte(readTok)), nonce, "43-ccccccc"); p == want {
		t.Fatal("same proof for another version")
	}
	if p := healthProof(sha256.Sum256([]byte(ctlTok)), nonce, "42-bbbbbbb"); p == want {
		t.Fatal("same proof for another token")
	}
	// nonce and version cannot run into each other
	if healthProof([32]byte{}, "0123456789abcdef4", "2-b") == healthProof([32]byte{}, "0123456789abcdef", "42-b") {
		t.Fatal("ambiguous proof input")
	}
	for _, bad := range []string{"/health", "/health?c=", "/health?c=short", "/health?c=" + strings.Repeat("a", 65),
		"/health?c=0123456789abcde%00", "/health?c=0123456789abcdef%0a", "/health?c=0123456789abcdef+x", "/health?x=" + nonce} {
		if st, _, raw := get(bad, ""); st != 400 || strings.Contains(raw, "proof") {
			t.Fatalf("%s: %d %s", bad, st, raw)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		req, _ := http.NewRequest(m, r.srv.URL+"/health?c="+nonce, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 405 {
			t.Fatalf("%s: %d", m, resp.StatusCode)
		}
	}
	// the other paths still need their token (an old installer's check, GET /metrics, works as before)
	if st, _, _ := get("/metrics", ""); st != 401 {
		t.Fatal(st)
	}
	if st, m, _ := get("/metrics", readTok); st != 200 || m["agent_version"] != "42-bbbbbbb" {
		t.Fatal(st, m["agent_version"])
	}
	// one address cannot ask without limit
	n429 := 0
	for i := 0; i < healthPerMin+20; i++ {
		if st, _, _ := get("/health?c="+nonce, ""); st == 429 {
			n429++
		}
	}
	if n429 < 20 {
		t.Fatalf("no limit: %d of %d refused", n429, healthPerMin+20)
	}
}

// L30: the health check proves the agent without sending it anything secret.
func TestCheckRunning(t *testing.T) {
	r := newUpdRig(t, "42-bbbbbbb", nil)
	cfg := healthCfg(t, r.srv.URL)
	if err := CheckRunning(context.Background(), cfg, "42-bbbbbbb"); err != nil {
		t.Fatal(err)
	}
	if err := CheckRunning(context.Background(), cfg, "43-ccccccc"); err == nil || !strings.Contains(err.Error(), "did not prove") {
		t.Fatal("wrong version accepted:", err)
	}
	// an agent with another token on that port (another installation) is not this machine's agent
	other := New(mustParse(t, ""), Tokens{Read: "another-token-cccccccccccccccccccc"}, Deps{Version: "42-bbbbbbb"})
	osrv := httptest.NewServer(other.Handler())
	defer osrv.Close()
	if err := CheckRunning(context.Background(), healthCfg(t, osrv.URL), "42-bbbbbbb"); err == nil {
		t.Fatal("an agent with another token passed")
	}
	// nothing listening
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String()
	ln.Close()
	if err := CheckRunning(context.Background(), healthCfg(t, dead), "42-bbbbbbb"); err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Fatal(err)
	}
}

// L30: a program that took the agent's port while the agent restarted. Whatever it answers, it is never sent
// the token and never passes for the agent.
func TestCheckRunningSendsNoTokenToWhoeverHoldsThePort(t *testing.T) {
	good := healthProof(sha256.Sum256([]byte(readTok)), "0123456789abcdef0123456789abcdef", "42-bbbbbbb")
	answers := map[string]http.HandlerFunc{
		"asks for the token": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="fairy-agent"`)
			w.WriteHeader(401)
		},
		"redirects to /metrics": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/metrics" {
				_, _ = w.Write([]byte(`{"agent_version":"42-bbbbbbb"}`))
				return
			}
			http.Redirect(w, r, "/metrics", http.StatusTemporaryRedirect)
		},
		"claims the version like /metrics": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"agent_version":"42-bbbbbbb","proof":""}`))
		},
		"replays a proof for another nonce": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"proof":"` + good + `"}`))
		},
		"echoes the nonce": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"proof":"` + r.URL.Query().Get("c") + `"}`))
		},
		"answers rubbish": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) },
		"answers 500":     func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"knows no /health": func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		},
	}
	for name, h := range answers {
		rec := &recorder{h: h}
		srv := httptest.NewServer(rec)
		cfg := healthCfg(t, srv.URL)
		// the installer of the same version, of a newer one, and the Windows account move: all strict
		if err := CheckRunning(context.Background(), cfg, "42-bbbbbbb"); err == nil {
			t.Fatalf("%s: passed for the agent", name)
		}
		for _, self := range []string{"42-bbbbbbb", "41-aaaaaaa"} {
			if err := checkRunningFrom(context.Background(), cfg, self, "42-bbbbbbb"); err == nil {
				t.Fatalf("%s: passed for the agent (installer %s)", name, self)
			}
		}
		rec.leaked(t, name)
		rec.mu.Lock()
		for _, req := range rec.seen {
			if !strings.HasPrefix(req, "GET /health?c=") {
				t.Fatalf("%s: the listener was asked something else:\n%s", name, req)
			}
		}
		rec.mu.Unlock()
		srv.Close()
	}
}

// L30, going back by hand to a release from before /health (`fairy-agent update --force`, or its rollback):
// the old agent answers 404. The check then rests on the service's state alone. It does not fall back to the
// old question with the token.
func TestCheckRunningWithAnAgentFromBeforeHealth(t *testing.T) {
	old := &recorder{h: func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" { // what build 14 answers, to a request with the token
			_, _ = w.Write([]byte(`{"agent_version":"14-49a8907"}`))
			return
		}
		writeJSON(w, 404, map[string]any{"error": "not found"})
	}}
	srv := httptest.NewServer(old)
	defer srv.Close()
	cfg := healthCfg(t, srv.URL)
	// installer 42 put build 14 back: accepted on the service's state
	if err := checkRunningFrom(context.Background(), cfg, "42-bbbbbbb", "14-49a8907"); err != nil {
		t.Fatal(err)
	}
	// a version that cannot be compared (a local build was forced in): the same
	if err := checkRunningFrom(context.Background(), cfg, "42-bbbbbbb", "dev"); err != nil {
		t.Fatal(err)
	}
	// but not for this installer's own version or a newer one, which know /health
	for _, want := range []string{"42-bbbbbbb", "43-ccccccc"} {
		err := checkRunningFrom(context.Background(), cfg, "42-bbbbbbb", want)
		if err == nil || !strings.Contains(err.Error(), "does not know /health") {
			t.Fatalf("%s: %v", want, err)
		}
	}
	if err := CheckRunning(context.Background(), cfg, "14-49a8907"); err == nil {
		t.Fatal("the strict check accepted a listener without /health")
	}
	old.leaked(t, "an agent from before /health")
	for _, req := range old.seen {
		if strings.Contains(req, "/metrics") {
			t.Fatalf("fell back to /metrics:\n%s", req)
		}
	}
}

// L30: a port held by another program is not waited for without end.
func TestListenGivesUpWhenThePortIsTaken(t *testing.T) {
	old := listenRetry
	listenRetry = 5 * time.Millisecond
	defer func() { listenRetry = old }()

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	addr := taken.Addr().String()
	start := time.Now()
	ln, err := Listen(context.Background(), addr, WaitForever)
	if err == nil {
		ln.Close()
		t.Fatal("listening on a taken port")
	}
	if !errors.Is(err, ErrAddrInUse) || !strings.Contains(err.Error(), "tried 5 times") || !strings.Contains(err.Error(), addr) {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 4*listenRetry || d > 5*time.Second {
		t.Fatalf("gave up after %s", d)
	}

	// the port becomes free between two tries (the old agent was still going down): it is taken
	listenRetry = 50 * time.Millisecond
	go func() { time.Sleep(80 * time.Millisecond); taken.Close() }()
	ln, err = Listen(context.Background(), addr, WaitForever)
	if err != nil {
		t.Fatal("port freed after two tries:", err)
	}
	ln.Close()

	// an address that is not there yet (Tailscale still starting) is waited for as before, not given up on
	listenRetry = 5 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	ln, err = Listen(ctx, "192.0.2.77:9101", WaitForever) // TEST-NET-1: never an address of this machine
	if err == nil {
		ln.Close()
		t.Skip("this machine has 192.0.2.77")
	}
	if errors.Is(err, ErrAddrInUse) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("an absent address: %v", err)
	}
	// and with a limited wait the old error comes back
	if _, err := Listen(context.Background(), "192.0.2.77:9101", 20*time.Millisecond); err == nil || errors.Is(err, ErrAddrInUse) ||
		!strings.Contains(err.Error(), "cannot listen on") {
		t.Fatal(err)
	}
}
