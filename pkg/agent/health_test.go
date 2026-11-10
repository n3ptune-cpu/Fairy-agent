package agent

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
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

// healthRequest is a GET /health as the handler sees it, from remote to local ("" = no local address known).
func healthRequest(method, target, remote, local string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = remote
	if local != "" {
		req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey,
			net.Addr(net.TCPAddrFromAddrPort(netip.MustParseAddrPort(local)))))
	}
	return req
}

// answerOf is everything a caller gets: status, headers, body.
func answerOf(h http.Handler, req *http.Request) string {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(w.Code) + "\n")
	_ = w.Header().Write(&sb)
	sb.WriteString("\n" + w.Body.String())
	return sb.String()
}

func TestHealthEndpoint(t *testing.T) {
	h := New(mustParse(t, ""), Tokens{Read: readTok, Control: ctlTok}, Deps{Collector: agenttest.NewCollector(), Version: "42-bbbbbbb"}).Handler()
	key := healthKey(sha256.Sum256([]byte(readTok)))
	nonce := "0123456789abcdef0123456789abcdef"
	ask := healthAsk(key, nonce)
	want := healthProof(key, nonce, "42-bbbbbbb")
	const loop, own = "127.0.0.1:50000", "100.70.0.1:50000"
	good := "/health?c=" + nonce + "&p=" + ask

	// the checker's question, from this machine: over loopback, or from the agent's own address to itself
	for _, c := range [][2]string{{loop, "127.0.0.1:9101"}, {"[::1]:50000", "[::1]:9101"}, {own, "100.70.0.1:9101"}, {loop, ""}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, healthRequest("GET", good, c[0], c[1]))
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		if w.Code != 200 || m["proof"] != want || len(m) != 1 {
			t.Fatalf("%v: %d %s", c, w.Code, w.Body)
		}
		// nothing about the machine or the build is in the answer
		for _, secret := range []string{"42", "bbbbbbb", readTok, ctlTok, "version", "hostname"} {
			if strings.Contains(w.Body.String(), secret) && !strings.Contains(want, secret) {
				t.Fatalf("the answer shows %q: %s", secret, w.Body)
			}
		}
	}
	// the proof depends on the nonce, the version and the token; question and answer are different values
	if healthProof(key, "fedcba9876543210fedcba9876543210", "42-bbbbbbb") == want || healthProof(key, nonce, "43-ccccccc") == want ||
		healthProof(healthKey(sha256.Sum256([]byte(ctlTok))), nonce, "42-bbbbbbb") == want || ask == want ||
		healthProof(key, nonce, "") == ask {
		t.Fatal("the same value for different inputs")
	}
	// nonce and version cannot run into each other
	if healthProof([32]byte{}, "0123456789abcdef4", "2-b") == healthProof([32]byte{}, "0123456789abcdef", "42-b") {
		t.Fatal("ambiguous proof input")
	}

	// Everything else is the answer of a path that does not exist, to the byte.
	notFound := answerOf(h, healthRequest("GET", "/no-such-path", loop, "127.0.0.1:9101"))
	if !strings.HasPrefix(notFound, "404\n") || !strings.Contains(notFound, `{"error":"not found"}`) {
		t.Fatal(notFound)
	}
	otherAsk := healthAsk(healthKey(sha256.Sum256([]byte("another-token-cccccccccccccccccccc"))), nonce)
	for name, req := range map[string]*http.Request{
		// review N1: another machine, with or without the right question
		"another machine":                         healthRequest("GET", "/health?c="+nonce, "100.101.102.103:40000", "100.70.0.1:9101"),
		"another machine, right question":         healthRequest("GET", good, "100.101.102.103:40000", "100.70.0.1:9101"),
		"another machine, no local address":       healthRequest("GET", good, "100.101.102.103:40000", ""),
		"the panel's address":                     healthRequest("GET", good, "100.88.0.7:40000", "100.70.0.1:9101"),
		"no address at all":                       healthRequest("GET", good, "", ""),
		"this machine, no question":               healthRequest("GET", "/health?c="+nonce, loop, "127.0.0.1:9101"),
		"this machine, question for no nonce":     healthRequest("GET", "/health?p="+ask, loop, "127.0.0.1:9101"),
		"this machine, wrong question":            healthRequest("GET", "/health?c="+nonce+"&p="+strings.Repeat("0", 64), loop, "127.0.0.1:9101"),
		"this machine, another token":             healthRequest("GET", "/health?c="+nonce+"&p="+otherAsk, loop, "127.0.0.1:9101"),
		"this machine, the answer as question":    healthRequest("GET", "/health?c="+nonce+"&p="+want, loop, "127.0.0.1:9101"),
		"this machine, question of another nonce": healthRequest("GET", "/health?c=fedcba9876543210fedcba9876543210&p="+ask, loop, "127.0.0.1:9101"),
		"this machine, short question":            healthRequest("GET", "/health?c="+nonce+"&p="+ask[:63], loop, "127.0.0.1:9101"),
		"nonce too short":                         healthRequest("GET", "/health?c=short&p="+healthAsk(key, "short"), loop, "127.0.0.1:9101"),
		"nonce too long":                          healthRequest("GET", "/health?c="+strings.Repeat("a", 65)+"&p="+healthAsk(key, strings.Repeat("a", 65)), loop, "127.0.0.1:9101"),
		"nonce with other characters":             healthRequest("GET", "/health?c=0123456789abcdef%0a&p="+healthAsk(key, "0123456789abcdef\n"), loop, "127.0.0.1:9101"),
		"POST":                                    healthRequest("POST", good, loop, "127.0.0.1:9101"),
		"PUT":                                     healthRequest("PUT", good, loop, "127.0.0.1:9101"),
		"HEAD":                                    healthRequest("HEAD", good, loop, "127.0.0.1:9101"),
	} {
		if got := answerOf(h, req); got != notFound {
			t.Errorf("%s: not the answer of a path that does not exist:\n%s", name, got)
		}
	}
	// a token in the header changes nothing: /health is not asked with one
	for _, tok := range []string{readTok, ctlTok, "wrong-token-xxxxxxxxxxxxxxxxxxxxx"} {
		req := healthRequest("GET", "/health?c="+nonce, "100.101.102.103:40000", "100.70.0.1:9101")
		req.Header.Set("Authorization", "Bearer "+tok)
		if got := answerOf(h, req); got != notFound {
			t.Errorf("another machine with token %q:\n%s", tok, got)
		}
	}
	// the other paths still need their token (an old installer's check, GET /metrics, works as before)
	if w := httptest.NewRecorder(); true {
		h.ServeHTTP(w, healthRequest("GET", "/metrics", loop, "127.0.0.1:9101"))
		if w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
}

// Review N1: what a caller without the token gets from /health does not depend on the token at all. Two agents
// with different tokens (and versions) answer every such request with the same bytes, so there is nothing to
// test a guess against; and the reviewer's own offline loop finds nothing.
func TestHealthGivesNothingToTestATokenGuessAgainst(t *testing.T) {
	a1 := New(mustParse(t, ""), Tokens{Read: readTok}, Deps{Version: "41-aaaaaaa"})
	a2 := New(mustParse(t, ""), Tokens{Read: "hunter2-hunter2-hunter2-hunter2"}, Deps{Version: "42-bbbbbbb"})
	const nonce = "AAAAAAAAAAAAAAAA"
	guessKey := healthKey(sha256.Sum256([]byte("wrong-token-xxxxxxxxxxxxxxxxxxxxx")))
	for _, from := range [][2]string{{"100.101.102.103:40000", "100.70.0.1:9101"}, {"127.0.0.1:40000", "127.0.0.1:9101"}} {
		for _, target := range []string{"/health", "/health?c=" + nonce, "/health?c=" + nonce + "&p=" + healthAsk(guessKey, nonce),
			"/health?c=" + nonce + "&p=" + strings.Repeat("f", 64)} {
			r1 := answerOf(a1.Handler(), healthRequest("GET", target, from[0], from[1]))
			r2 := answerOf(a2.Handler(), healthRequest("GET", target, from[0], from[1]))
			if r1 != r2 || !strings.HasPrefix(r1, "404\n") || strings.Contains(r1, "proof") {
				t.Fatalf("%s from %s: the answer depends on the agent's token:\n%s\n---\n%s", target, from[0], r1, r2)
			}
		}
	}
	// the reviewer's proof: any device on the tailnet, no token
	w := httptest.NewRecorder()
	a1.Handler().ServeHTTP(w, healthRequest("GET", HealthPath+"?c="+nonce, "100.101.102.103:40000", ""))
	if w.Code == 200 {
		t.Fatal("a caller on another machine, without a token, got HTTP 200:", w.Body)
	}
	// The key is not the token's hash any more, and making it is slow on purpose: a guess of the token against
	// anything the health check ever puts on the wire costs healthKeyRounds rounds.
	if healthKeyRounds < 600_000 {
		t.Fatal("healthKeyRounds:", healthKeyRounds)
	}
	rh := sha256.Sum256([]byte(readTok))
	slow, err := pbkdf2.Key(sha256.New, string(rh[:]), []byte("fairy-agent health v2"), 600_000, 32)
	if k := healthKey(rh); err != nil || !bytes.Equal(k[:], slow) || k == rh {
		t.Fatal("the health key is not PBKDF2-HMAC-SHA256 of the token's hash with 600000 rounds")
	}
}

// Review N7: /health keeps nothing per caller (it had a limiter with up to 240 time stamps per source address
// and no cap on addresses).
func TestHealthKeepsNothingPerCaller(t *testing.T) {
	r := newRig(t, "")
	h := r.a.Handler()
	key := healthKey(sha256.Sum256([]byte(readTok)))
	ask := healthAsk(key, "AAAAAAAAAAAAAAAA")
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < 20000; i++ {
		remote := fmt.Sprintf("[2001:db8:1:1:%x:%x:%x:%x]:40000", i>>12&0xfff, i>>8&0xf, i>>4&0xf, i&0xf)
		h.ServeHTTP(httptest.NewRecorder(), healthRequest("GET", "/health?c=AAAAAAAAAAAAAAAA&p="+ask, remote, "[2001:db8:1:1::1]:9101"))
	}
	// and this machine may ask as often as it likes (the installer asks once a second; nothing counts it out)
	for i := 0; i < 2000; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, healthRequest("GET", "/health?c=AAAAAAAAAAAAAAAA&p="+ask, "127.0.0.1:40000", "127.0.0.1:9101"))
		if w.Code != 200 {
			t.Fatal(i, w.Code)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); grown > 1<<20 {
		t.Fatalf("20000 source addresses: the heap grew by %d KiB", grown/1024)
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
	good := healthProof(healthKey(sha256.Sum256([]byte(readTok))), "0123456789abcdef0123456789abcdef", "42-bbbbbbb")
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
		"echoes the question": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"proof":"` + r.URL.Query().Get("p") + `"}`))
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
