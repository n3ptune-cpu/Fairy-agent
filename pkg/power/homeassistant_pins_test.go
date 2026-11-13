package power

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// Review of the Home Assistant source: four changes to the code that no test noticed. Each has its test here.

// captured runs fn with the process's standard output and standard error, the log package and slog all
// written to files, and returns what was written.
func captured(t *testing.T, fn func()) string {
	t.Helper()
	dir := t.TempDir()
	files := [2]*os.File{}
	for i, name := range []string{"stdout", "stderr"} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		files[i] = f
	}
	oldOut, oldErr, oldLog, oldSlog := os.Stdout, os.Stderr, log.Writer(), slog.Default()
	os.Stdout, os.Stderr = files[0], files[1]
	slog.SetDefault(slog.New(slog.NewTextHandler(files[1], &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(files[1])
	func() {
		defer func() {
			os.Stdout, os.Stderr = oldOut, oldErr
			slog.SetDefault(oldSlog)
			log.SetOutput(oldLog)
		}()
		fn()
	}()
	var all bytes.Buffer
	for _, f := range files {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		all.Write(b)
	}
	return all.String()
}

// The token is not written to standard output or standard error (where the service's log is), whatever Home
// Assistant answers: not by the source, not by the log package, not by slog. TestHomeAssistantTokenNeverLeaves
// looks at errors and at slog; a line printed straight to the terminal passed it.
func TestHomeAssistantTokenIsNotPrinted(t *testing.T) {
	tok := fakeHAToken()
	hang := make(chan struct{})
	defer close(hang)
	echo := func(code int, format string) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			fmt.Fprintf(w, format, r.Header.Get("Authorization"))
		}
	}
	answers := map[string]func(w http.ResponseWriter, r *http.Request){
		"a reading":                 nil,
		"401 that repeats it":       echo(401, `{"message":"bad token %s"}`),
		"403 that repeats it":       echo(403, `%s`),
		"404 that repeats it":       echo(404, `{"message":"%s"}`),
		"500 that repeats it":       echo(500, `%s`),
		"not JSON, with the header": echo(200, `<html>%s</html>`),
		"the header as the state":   echo(200, `{"state":"%s","attributes":{"unit_of_measurement":"W"}}`),
		"the header as the unit":    echo(200, `{"state":"5","attributes":{"unit_of_measurement":"%s"}}`),
		"a redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/api/states?t="+r.Header.Get("Authorization"), http.StatusFound)
		},
		"connection cut": func(w http.ResponseWriter, _ *http.Request) {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		},
		"no answer in time": func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-hang:
			case <-r.Context().Done():
			}
		},
	}
	const marks = 4
	sent := 0
	out := captured(t, func() {
		// the four ways are really caught: each writes a line of its own
		fmt.Println("mark-1 standard output")
		fmt.Fprintln(os.Stderr, "mark-2 standard error")
		log.Print("mark-3 the log package")
		slog.Info("mark-4 slog")

		for name, answer := range answers {
			ha, srv := startHA(t, answer)
			s := haSource(t, srv.URL, map[string]any{"max_age_s": 60})
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				rs, err := s.Read(ctx, 300*time.Millisecond)
				cancel()
				if (err == nil) != (name == "a reading") {
					t.Errorf("%s: %+v %v", name, rs, err)
				}
			}
			_ = s.(Checker).Check()
			s.Close()
			srv.CloseClientConnections()
			for _, q := range ha.seen() {
				if q.auth == "Bearer "+tok {
					sent++
				}
			}
		}
		// a token that cannot be sent, and none at all
		_, srv := startHA(t, nil)
		for _, broken := range []string{tok + "\n", "two words " + tok, ""} {
			t.Setenv(haTokenEnv, broken)
			s := haSource(t, srv.URL, nil)
			if _, err := s.Read(context.Background(), time.Second); err == nil {
				t.Errorf("a token of %d bytes that cannot be sent was sent", len(broken))
			}
			_ = s.(Checker).Check()
		}
		// an entry with the token written into it
		for _, more := range []map[string]any{{"token": tok}, {"token_env": tok + ".x"}, {"url": "http://fairy:" + tok + "@192.0.2.10:8123"},
			{"max_age_s": tok}, {"id": strings.ToUpper(tok)}, {tok: 1}} {
			if _, err := Build(haEntry("http://192.0.2.10:8123", more), nil); err == nil {
				t.Errorf("%v: accepted", more)
			}
		}
	})
	if sent != 2*len(answers) {
		t.Fatalf("the token was sent with %d requests, want %d: this test saw too little", sent, 2*len(answers))
	}
	for i := 1; i <= marks; i++ {
		if !strings.Contains(out, fmt.Sprintf("mark-%d ", i)) {
			t.Fatalf("what was written is not all caught (mark-%d is missing):\n%s", i, out)
		}
	}
	if strings.Contains(out, tok) || strings.Contains(out, "Bearer") || strings.Contains(out, "Authorization") {
		t.Errorf("the token or its header was written to standard output or standard error:\n%s", out)
	}
	if n := strings.Count(out, "\n"); n != marks {
		t.Errorf("reading a Home Assistant wrote %d lines to standard output and standard error, want none:\n%s", n-marks, out)
	}
}

// The token is read from the environment for every request, as Read's comment and AGENT.md say: a source that
// was built with one token sends another one when the variable has changed. (Nothing in the agent changes its
// environment while it runs; the point is that the source keeps no copy of the token.)
func TestHomeAssistantReadsTheTokenForEveryRequest(t *testing.T) {
	first, second := fakeHAToken(), strings.Join([]string{"another", "made", "up", "token"}, "-")
	var mu sync.Mutex
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, haStateBody("95.5", "W", time.Now(), time.Now()))
	}))
	defer srv.Close()
	tlsSrv := httptest.NewTLSServer(srv.Config.Handler)
	defer tlsSrv.Close()
	ca := filepath.Join(t.TempDir(), "ha.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv(haTokenEnv, first)
	sources := []Source{haSource(t, srv.URL, nil), haSource(t, tlsSrv.URL, map[string]any{"ca_file": ca})} // http, and https with its own transport
	var want []string
	for _, tok := range []string{first, second, first} {
		t.Setenv(haTokenEnv, tok)
		for _, s := range sources {
			if rs, err := s.Read(context.Background(), 3*time.Second); err != nil || len(rs) != 1 {
				t.Fatalf("%+v %v", rs, err)
			}
			want = append(want, "Bearer "+tok)
		}
	}
	// the variable is taken away: no request, and the token of before is not used
	t.Setenv(haTokenEnv, "")
	for _, s := range sources {
		if _, err := s.Read(context.Background(), 3*time.Second); err == nil {
			t.Error("a reading without a token")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(auth, want) {
		t.Errorf("the requests carried other tokens than the variable held at the time of each (request by request, as expected: %v)",
			func() (same []bool) {
				for i := range max(len(auth), len(want)) {
					same = append(same, i < len(auth) && i < len(want) && auth[i] == want[i])
				}
				return same
			}())
	}
}

const proxyChildMark = "POWER_TEST_PROXY_CHILD"

// A proxy from the environment is never used: the token would go to the proxy (in clear for an http url, and
// as the name of the host for https). The proxy settings of the environment are read once in a process, so
// the readings are made in a process of their own (this test program, started again with HTTP_PROXY,
// HTTPS_PROXY and ALL_PROXY set to a listener of the test): the listener must see nothing of a Home Assistant
// source, and it does see the one request of an ordinary client that the child makes to show that the
// settings were in force.
func TestHomeAssistantUsesNoProxy(t *testing.T) {
	const notLocal = "192.0.2.10" // TEST-NET-1: not this machine (a proxy is never used for localhost), and nobody's
	if os.Getenv(proxyChildMark) == "1" {
		t.Setenv(haTokenEnv, fakeHAToken())
		for _, base := range []string{"http://" + notLocal + ":8123", "https://" + notLocal + ":8443"} {
			s := haSource(t, base, nil)
			_, err := s.Read(context.Background(), 300*time.Millisecond)
			fmt.Printf("CHILD read %s: %s\n", base[:5], devices.Describe(err))
		}
		ordinary := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
		resp, err := ordinary.Get("http://" + notLocal + "/control")
		if err == nil {
			resp.Body.Close()
		}
		fmt.Printf("CHILD control: %v\n", err == nil)
		return
	}

	// the transports themselves: no proxy function at all
	if tr, ok := devices.LANClient(time.Second).Transport.(*http.Transport); !ok || tr.Proxy != nil {
		t.Error("the shared transport (an http url) can use a proxy")
	}
	s := haSource(t, "https://"+notLocal+":8443", nil).(*homeAssistant)
	if s.tr == nil || s.tr.Proxy != nil {
		t.Error("the transport of an https source can use a proxy")
	}

	var mu sync.Mutex
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.RequestURI)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" {
			seen = append(seen, "with a credential")
		}
		mu.Unlock()
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Skip("this test program's own path is not known:", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestHomeAssistantUsesNoProxy$", "-test.count=1", "-test.v")
	cmd.Env = []string{proxyChildMark + "=1", "NO_PROXY=", "no_proxy="}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !strings.HasSuffix(strings.ToUpper(k), "_PROXY") && k != proxyChildMark {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		cmd.Env = append(cmd.Env, name+"="+proxy.URL)
	}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "CHILD read http:") || !strings.Contains(string(out), "CHILD read https") {
		t.Fatalf("the child did not make its readings: %v\n%s", err, out)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(string(out), "CHILD control: true") || !slices.Contains(seen, "GET http://"+notLocal+"/control") {
		t.Fatalf("the proxy settings were not in force in the child (its ordinary client did not come through the proxy): %v\n%s", seen, out)
	}
	if len(seen) != 1 {
		t.Errorf("a Home Assistant source went through the proxy of the environment: the proxy saw %v", seen)
	}
}

// A Home Assistant that does not answer is given up after the timeout of the reading, for an http and for an
// https url. The reading has a deadline of its own here (10 s), so a source that waits for ever fails this
// test after 10 s instead of stopping the whole run at the test program's limit.
func TestHomeAssistantGivesUpInTime(t *testing.T) {
	hang := make(chan struct{})
	defer close(hang)
	silent := func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}
	ha, srv := startHA(t, silent)
	tlsSrv := httptest.NewTLSServer(ha)
	t.Cleanup(tlsSrv.Close)
	ca := filepath.Join(t.TempDir(), "ha.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]Source{"http": haSource(t, srv.URL, nil), "https": haSource(t, tlsSrv.URL, map[string]any{"ca_file": ca})} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := time.Now()
		rs, err := s.Read(ctx, 200*time.Millisecond)
		took := time.Since(start)
		cancel()
		if err == nil || len(rs) != 0 || devices.Describe(err) != "timeout" {
			t.Errorf("%s: %+v %v", name, rs, err)
		}
		if took < 200*time.Millisecond || took > 5*time.Second {
			t.Errorf("%s: a reading with a timeout of 200 ms was given up after %v", name, took.Round(time.Millisecond))
		}
		srv.CloseClientConnections()
		tlsSrv.CloseClientConnections()
	}
	if n := len(ha.seen()); n != 2 {
		t.Errorf("%d requests reached the silent Home Assistant, want 2", n)
	}
}
