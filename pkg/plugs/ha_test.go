package plugs

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/plugs/hatest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// tokenEnv is the variable the tests keep the made-up token in. Not a FAIRY_ name: those are refused.
const tokenEnv = "PLUGS_TEST_HA_TOKEN"

const (
	bar1 = "switch.desk_bar_socket_1"
	bar2 = "switch.desk_bar_socket_2"
)

// startHA runs a fake Home Assistant with two sockets (the first on, the second off) and sets the token.
func startHA(t *testing.T) (*hatest.Server, *HA) {
	t.Helper()
	srv := hatest.New(map[string]string{bar1: "on", bar2: "off"})
	t.Cleanup(srv.Close)
	t.Setenv(tokenEnv, hatest.Token())
	return srv, newHA(t, srv.URL, "")
}

func newHA(t *testing.T, url, caFile string) *HA {
	t.Helper()
	h, err := NewHA(url, tokenEnv, caFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}

func bg() context.Context { return context.Background() }

// What a state read is: one GET for that entity with the token, and nothing else.
func TestStateIsOneGet(t *testing.T) {
	srv, h := startHA(t)
	for entity, want := range map[string]string{bar1: StateOn, bar2: StateOff} {
		got, err := h.State(bg(), entity, 2*time.Second)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v", entity, got, err)
		}
	}
	reqs := srv.Requests()
	if len(reqs) != 2 || srv.Problems() != "" {
		t.Fatalf("%d requests; %s", len(reqs), srv.Problems())
	}
	for _, q := range reqs {
		if q.Method != http.MethodGet || !q.TokenOK || q.Body != "" || !strings.HasPrefix(q.Path, "/api/states/switch.desk_bar_socket_") {
			t.Errorf("%+v", q.Method+" "+q.Path)
		}
	}
	if h.Scheme() != "http" || h.Host() != strings.TrimPrefix(srv.URL, "http://") || h.TokenEnv() != tokenEnv || !h.TokenSet() {
		t.Errorf("%s %s %s", h.Scheme(), h.Host(), h.TokenEnv())
	}
}

// What Home Assistant can say for a switch, and what is made of it.
func TestStateWords(t *testing.T) {
	srv, h := startHA(t)
	for said, want := range map[string]string{"on": StateOn, "off": StateOff, "unavailable": StateUnavailable, "unknown": StateUnknown,
		"": StateUnknown, "On": StateUnknown, "OFF": StateUnknown, "1": StateUnknown, "true": StateUnknown, "open": StateUnknown,
		"on ": StateUnknown, "toggle": StateUnknown, hatest.Token(): StateUnknown} {
		srv.Set(bar1, said)
		got, err := h.State(bg(), bar1, 2*time.Second)
		if err != nil || got != want {
			t.Errorf("Home Assistant says %q: %q, %v; want %q", said, got, err, want)
		}
	}
	// what is no state at all is an error with a fixed text
	srv.Set(bar1, "on")
	for name, c := range map[string]struct {
		do   func()
		want string
	}{
		"the entity is gone":            {func() { srv.Remove(bar2) }, "entity not found"},
		"http 500":                      {func() { srv.AnswerState(500) }, "http 500"},
		"http 502":                      {func() { srv.AnswerState(502) }, "http 502"},
		"a redirect":                    {func() { srv.Redirect("http://192.0.2.99:8123") }, "http 307"},
		"an answer for another entity":  {func() { srv.AnswerAs("switch.server_corner_socket") }, "home assistant answered for another entity"},
		"no answer":                     {func() { srv.HangState(true) }, "timeout"},
		"the token refused (401)":       {func() { srv.AnswerState(401) }, "home assistant refused the token"},
		"the token refused (403)":       {func() { srv.AnswerState(403) }, "home assistant refused the token"},
		"another token in the variable": {func() { t.Setenv(tokenEnv, "another-made-up-token") }, "home assistant refused the token"},
	} {
		c.do()
		entity := bar1
		if name == "the entity is gone" {
			entity = bar2
		}
		got, err := h.State(bg(), entity, 300*time.Millisecond)
		if err == nil || got != "" || Describe(err) != c.want {
			t.Errorf("%s: %q, %v (%q); want %q", name, got, err, Describe(err), c.want)
		}
		if wantRefused := strings.Contains(c.want, "refused"); power.Refused(err) != wantRefused {
			t.Errorf("%s: counts as a refusal of the token: %v", name, power.Refused(err))
		}
		srv.Honest()
		t.Setenv(tokenEnv, hatest.Token())
	}
	if srv.Problems() != "" {
		t.Error(srv.Problems())
	}
}

// Nothing is asked for an id that is not a switch's, and nothing without a token.
func TestNoRequestForWhatIsNotASwitchOrWithoutAToken(t *testing.T) {
	srv, h := startHA(t)
	for _, entity := range []string{"", "sensor.desk_plug_power", "light.desk", "lock.front_door", "script.all_off", "switch.", "switch.Desk",
		"switch.a/../../services/switch/toggle", "switch.a?x=1", "switch.a#b", "switch.a b", "switch.a\n", "switch.a%2f", "all",
		`switch.a","entity_id":"lock.front_door`, "switch." + strings.Repeat("a", 300)} {
		if st, err := h.State(bg(), entity, time.Second); err == nil || st != "" {
			t.Errorf("state of %q: %q", entity, st)
		}
		for _, on := range []bool{true, false} {
			err := h.Switch(bg(), entity, on, time.Second)
			var se *SwitchError
			if !errors.As(err, &se) || !se.NotSent {
				t.Errorf("switch of %q: %v", entity, err)
			}
		}
	}
	for name, tok := range map[string]string{"empty": "", "with a line break": hatest.Token() + "\n", "two words": "Bearer " + hatest.Token(), "not ASCII": "tökén"} {
		t.Setenv(tokenEnv, tok)
		if h.TokenSet() != (tok != "") {
			t.Errorf("%s: TokenSet", name)
		}
		_, err := h.State(bg(), bar1, time.Second)
		var nt *NoToken
		if !errors.As(err, &nt) || nt.Env != tokenEnv || !strings.Contains(Describe(err), tokenEnv) || (tok != "" && strings.Contains(Describe(err), tok)) {
			t.Errorf("a token that is %s, state: %v", name, err)
		}
		err = h.Switch(bg(), bar1, false, time.Second)
		var se *SwitchError
		if !errors.As(err, &se) || !se.NotSent || !strings.Contains(Describe(err), tokenEnv) || (tok != "" && strings.Contains(Describe(err), tok)) {
			t.Errorf("a token that is %s, switch: %v", name, err)
		}
	}
	if n := srv.Count(); n != 0 {
		t.Fatalf("%d requests were made: %+v", n, srv.Requests())
	}
}

// The one request that changes something: POST to turn_off for off and to turn_on for on, with the entity as
// the whole body, the token, once. Never toggle, never another path.
func TestSwitchIsOnePost(t *testing.T) {
	srv, h := startHA(t)
	for _, c := range []struct {
		entity string
		on     bool
		path   string
		after  string
	}{
		{bar1, false, "/api/services/switch/turn_off", "off"},
		{bar1, true, "/api/services/switch/turn_on", "on"},
		{bar2, true, "/api/services/switch/turn_on", "on"},
		{bar2, true, "/api/services/switch/turn_on", "on"}, // on already: sent all the same, and nothing changes
		{bar2, false, "/api/services/switch/turn_off", "off"},
	} {
		srv.Forget()
		if err := h.Switch(bg(), c.entity, c.on, 2*time.Second); err != nil {
			t.Fatalf("%s to %v: %v", c.entity, c.on, err)
		}
		reqs := srv.Requests()
		if len(reqs) != 1 {
			t.Fatalf("%s to %v: %d requests", c.entity, c.on, len(reqs))
		}
		q := reqs[0]
		if q.Method != http.MethodPost || q.Path != c.path || q.Body != `{"entity_id":"`+c.entity+`"}` || !q.TokenOK {
			t.Errorf("%s to %v: %s %s %s (token as expected: %v)", c.entity, c.on, q.Method, q.Path, q.Body, q.TokenOK)
		}
		if got := srv.State(c.entity); got != c.after {
			t.Errorf("%s to %v: the fake now says %q", c.entity, c.on, got)
		}
		if srv.Problems() != "" {
			t.Error(srv.Problems())
		}
	}
}

// A switch request is sent exactly once, whatever becomes of it: an error status, a redirect, no answer, a
// connection cut before or after the request was read, an answer after the timeout.
func TestSwitchIsNeverSentTwice(t *testing.T) {
	elsewhere := hatest.New(map[string]string{bar1: "on"}) // where a redirect points: it must see nothing
	defer elsewhere.Close()
	for name, c := range map[string]struct {
		do     func(*hatest.Server)
		status int // 0: no answer
	}{
		"http 500":           {func(s *hatest.Server) { s.AnswerSwitch(500) }, 500},
		"http 502":           {func(s *hatest.Server) { s.AnswerSwitch(502) }, 502},
		"http 503":           {func(s *hatest.Server) { s.AnswerSwitch(503) }, 503},
		"http 404":           {func(s *hatest.Server) { s.AnswerSwitch(404) }, 404},
		"http 400":           {func(s *hatest.Server) { s.AnswerSwitch(400) }, 400},
		"http 401":           {func(s *hatest.Server) { s.AnswerSwitch(401) }, 401},
		"http 403":           {func(s *hatest.Server) { s.AnswerSwitch(403) }, 403},
		"http 204":           {func(s *hatest.Server) { s.AnswerSwitch(204) }, 204},
		"http 202":           {func(s *hatest.Server) { s.AnswerSwitch(202) }, 202},
		"a redirect (307)":   {func(s *hatest.Server) { s.Redirect(elsewhere.URL) }, 307},
		"a redirect (308)":   {func(s *hatest.Server) { s.RedirectAs(elsewhere.URL, 308) }, 308},
		"a redirect (301)":   {func(s *hatest.Server) { s.RedirectAs(elsewhere.URL, 301) }, 301},
		"a redirect (302)":   {func(s *hatest.Server) { s.RedirectAs(elsewhere.URL, 302) }, 302},
		"a redirect (303)":   {func(s *hatest.Server) { s.RedirectAs(elsewhere.URL, 303) }, 303},
		"no answer":          {func(s *hatest.Server) { s.HangSwitch(true) }, 0},
		"the connection cut": {func(s *hatest.Server) { s.CutSwitch(true) }, 0},
		"an answer too late": {func(s *hatest.Server) { s.LateSwitch(2*time.Second, true) }, 0},
	} {
		srv, h := startHA(t)
		c.do(srv)
		for i := 0; i < 2; i++ { // twice in a row: the second has no kept connection of the first to trip over
			srv.Forget()
			start := time.Now()
			err := h.Switch(bg(), bar1, false, 300*time.Millisecond)
			var se *SwitchError
			if !errors.As(err, &se) || se.NotSent || se.Status != c.status {
				t.Fatalf("%s: %v", name, err)
			}
			// 401 and 403 included: Home Assistant answers a service call so also when its user may not switch
			// this entity. Only a state read tells that the token is refused.
			if power.Refused(err) {
				t.Errorf("%s: the answer to a switch request counts as a refusal of the token", name)
			}
			if took := time.Since(start); took > 5*time.Second {
				t.Errorf("%s: given up after %v", name, took)
			}
			time.Sleep(50 * time.Millisecond) // a second copy would have arrived by now
			if posts := srv.Posts(); len(posts) != 1 || srv.Count() != 1 {
				t.Fatalf("%s: the fake saw %d POSTs and %d requests in all, want one", name, len(posts), srv.Count())
			}
			if elsewhere.Count() != 0 {
				t.Fatalf("%s: the redirect was followed: %+v", name, elsewhere.Requests())
			}
			if strings.Contains(Describe(err), hatest.Token()) || strings.Contains(Describe(err), "made up") || strings.Contains(Describe(err), "127.0.0.1") {
				t.Errorf("%s: the error repeats the token, the answer or the address: %q", name, Describe(err))
			}
		}
		if srv.Problems() != "" {
			t.Errorf("%s: %s", name, srv.Problems())
		}
		srv.Close()
	}
}

// An entity that is not available is left out by Home Assistant, and the answer is still 200: Switch reports
// "taken", and the state says the truth. That is why nobody reports a switch from Switch's answer alone.
func TestSwitchOfAnUnavailableEntityIsStillAnswered200(t *testing.T) {
	srv, h := startHA(t)
	srv.Set(bar1, "unavailable")
	if err := h.Switch(bg(), bar1, false, 2*time.Second); err != nil {
		t.Fatalf("%v", err)
	}
	if st, err := h.State(bg(), bar1, 2*time.Second); err != nil || st != StateUnavailable {
		t.Fatalf("%q %v", st, err)
	}
	srv.Set(bar1, "on")
	srv.IgnoreSwitch(true)
	if err := h.Switch(bg(), bar1, false, 2*time.Second); err != nil {
		t.Fatalf("%v", err)
	}
	if st, _ := h.State(bg(), bar1, 2*time.Second); st != StateOn {
		t.Fatalf("%q", st)
	}
}

// https: the certificate is always checked; with the fake's own certificate as ca_file both requests work,
// without it neither is sent.
func TestHTTPSIsVerified(t *testing.T) {
	srv := hatest.NewTLS(map[string]string{bar1: "on"})
	defer srv.Close()
	t.Setenv(tokenEnv, hatest.Token())
	ca := filepath.Join(t.TempDir(), "ha.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.CertificateDER()}), 0o644); err != nil {
		t.Fatal(err)
	}
	stranger := newHA(t, srv.URL, "") // the system's own certificates: the fake's is none of them
	if st, err := stranger.State(bg(), bar1, 2*time.Second); err == nil || Describe(err) != "tls verification failed" {
		t.Errorf("state without the ca_file: %q %v", st, err)
	}
	var se *SwitchError
	if err := stranger.Switch(bg(), bar1, false, 2*time.Second); !errors.As(err, &se) || se.Status != 0 {
		t.Errorf("switch without the ca_file: %v", err)
	}
	if srv.Count() != 0 || srv.State(bar1) != "on" {
		t.Fatalf("a request reached a Home Assistant whose certificate was not checked: %+v", srv.Requests())
	}
	h := newHA(t, srv.URL, ca)
	if h.Scheme() != "https" {
		t.Fatal(h.Scheme())
	}
	if st, err := h.State(bg(), bar1, 2*time.Second); err != nil || st != StateOn {
		t.Fatalf("%q %v", st, err)
	}
	if err := h.Switch(bg(), bar1, false, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if srv.State(bar1) != "off" || len(srv.Posts()) != 1 || srv.Problems() != "" {
		t.Fatalf("%q, %d POSTs; %s", srv.State(bar1), len(srv.Posts()), srv.Problems())
	}
}

func TestNewHARefuses(t *testing.T) {
	secret := strings.Join([]string{"made", "up", "token", "in", "the", "wrong", "place"}, "-")
	for name, c := range map[string][3]string{
		"no url":                 {"", tokenEnv, ""},
		"a path":                 {"http://192.0.2.10:8123/api", tokenEnv, ""},
		"a user":                 {"http://fairy:" + secret + "@192.0.2.10:8123", tokenEnv, ""},
		"a query":                {"http://192.0.2.10:8123?x=1", tokenEnv, ""},
		"another scheme":         {"ftp://192.0.2.10", tokenEnv, ""},
		"no variable":            {"http://192.0.2.10:8123", "", ""},
		"the token as variable":  {"http://192.0.2.10:8123", secret, ""},
		"one of Fairy's own":     {"http://192.0.2.10:8123", "FAIRY_AGENT_CONTROL_TOKEN", ""},
		"a system variable":      {"http://192.0.2.10:8123", "PATH", ""},
		"ca_file with http":      {"http://192.0.2.10:8123", tokenEnv, "/etc/fairy-agent/ha.pem"},
		"ca_file that is absent": {"https://192.0.2.10:8123", tokenEnv, filepath.Join(t.TempDir(), "absent.pem")},
	} {
		h, err := NewHA(c[0], c[1], c[2])
		if err == nil || h != nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "192.0.2.10") {
			t.Errorf("%s: the error repeats a value: %v", name, err)
		}
	}
}

// captured runs fn with standard output, standard error, the log package and slog written to files.
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

// The token is in no error and in nothing that is printed or logged, whatever Home Assistant answers to a
// state read or to a switch request, also when the answer repeats the header it was sent.
func TestTokenIsNeverPrintedOrInAnError(t *testing.T) {
	tok := hatest.Token()
	t.Setenv(tokenEnv, tok)
	hang := make(chan struct{})
	defer close(hang)
	echo := func(code int, format string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			fmt.Fprintf(w, format, r.Header.Get("Authorization"))
		}
	}
	answers := map[string]http.HandlerFunc{
		"200 that repeats it":       echo(200, `{"state":"%s"}`),
		"200, a list with it":       echo(200, `[{"entity_id":"%s"}]`),
		"401 that repeats it":       echo(401, `{"message":"bad token %s"}`),
		"403 that repeats it":       echo(403, `%s`),
		"404 that repeats it":       echo(404, `{"message":"%s"}`),
		"500 that repeats it":       echo(500, `%s`),
		"not JSON, with the header": echo(200, `<html>%s</html>`),
		"a redirect with it": func(w http.ResponseWriter, r *http.Request) {
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
	var mu sync.Mutex
	sent := 0
	var said []string
	out := captured(t, func() {
		fmt.Println("mark-1 standard output")
		slog.Info("mark-2 slog")
		for name, answer := range answers {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				if r.Header.Get("Authorization") == "Bearer "+tok {
					sent++
				}
				mu.Unlock()
				_, _ = io.Copy(io.Discard, r.Body) // the whole request is read: only then does the server notice a client that gave up
				answer(w, r)
			}))
			h, err := NewHA(srv.URL, tokenEnv, "")
			if err != nil {
				t.Fatal(err)
			}
			st, err := h.State(bg(), bar1, 300*time.Millisecond)
			said = append(said, name+" / state: "+st+" "+Describe(err)+" "+fmt.Sprint(err))
			err = h.Switch(bg(), bar1, false, 300*time.Millisecond)
			said = append(said, name+" / switch: "+Describe(err)+" "+fmt.Sprint(err))
			h.Close()
			srv.CloseClientConnections()
			srv.Close()
		}
	})
	if sent != 2*len(answers) {
		t.Fatalf("the token was sent with %d requests, want %d: this test saw too little", sent, 2*len(answers))
	}
	if !strings.Contains(out, "mark-1 ") || !strings.Contains(out, "mark-2 ") {
		t.Fatalf("what was written is not all caught:\n%s", out)
	}
	for _, text := range append(said, out) {
		if strings.Contains(text, tok) || strings.Contains(text, "Bearer") || strings.Contains(text, "Authorization") {
			t.Errorf("the token or its header is in an error or in what was printed:\n%s", text)
		}
	}
	if n := strings.Count(out, "\n"); n != 2 {
		t.Errorf("asking a Home Assistant wrote %d lines to standard output and standard error, want none:\n%s", n-2, out)
	}
}

// The token is read from the environment for every request: the client keeps no copy.
func TestTokenIsReadForEveryRequest(t *testing.T) {
	srv, h := startHA(t)
	other := "another-made-up-token"
	t.Setenv(tokenEnv, other)
	_, _ = h.State(bg(), bar1, time.Second)
	_ = h.Switch(bg(), bar1, false, time.Second)
	t.Setenv(tokenEnv, hatest.Token())
	_, _ = h.State(bg(), bar1, time.Second)
	_ = h.Switch(bg(), bar1, false, time.Second)
	var got []string
	for _, q := range srv.Requests() {
		got = append(got, q.Method+" "+strconv.FormatBool(q.TokenOK)+" "+strconv.FormatBool(q.Auth == "Bearer "+other))
	}
	if want := []string{"GET false true", "POST false true", "GET true false", "POST true false"}; !slices.Equal(got, want) {
		t.Errorf("%v", got)
	}
	if srv.State(bar1) != "off" {
		t.Error("the switch with the right token did nothing")
	}
}

const proxyChildMark = "PLUGS_TEST_PROXY_CHILD"

// A proxy from the environment is never used, for a state read or for a switch request: the token and the
// request would go to the proxy. The requests are made in a process of their own with HTTP_PROXY, HTTPS_PROXY
// and ALL_PROXY set to a listener of the test, which must see nothing of them and does see the one request of
// an ordinary client (the model: pkg/power, TestHomeAssistantUsesNoProxy).
func TestNoProxyIsUsed(t *testing.T) {
	const notLocal = "192.0.2.10" // TEST-NET-1: not this machine, and nobody's
	if os.Getenv(proxyChildMark) == "1" {
		t.Setenv(tokenEnv, hatest.Token())
		for _, base := range []string{"http://" + notLocal + ":8123", "https://" + notLocal + ":8443"} {
			h, err := NewHA(base, tokenEnv, "")
			if err != nil {
				t.Fatal(err)
			}
			_, err = h.State(bg(), bar1, 300*time.Millisecond)
			fmt.Printf("CHILD state %s: %s\n", base[:5], Describe(err))
			err = h.Switch(bg(), bar1, false, 300*time.Millisecond)
			fmt.Printf("CHILD switch %s: %s\n", base[:5], Describe(err))
		}
		ordinary := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
		resp, err := ordinary.Get("http://" + notLocal + "/control")
		if err == nil {
			resp.Body.Close()
		}
		fmt.Printf("CHILD control: %v\n", err == nil)
		return
	}
	var mu sync.Mutex
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.RequestURI)
		mu.Unlock()
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Skip("this test program's own path is not known:", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestNoProxyIsUsed$", "-test.count=1", "-test.v")
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
	if err != nil || strings.Count(string(out), "CHILD state") != 2 || strings.Count(string(out), "CHILD switch") != 2 {
		t.Fatalf("the child did not make its requests: %v\n%s", err, out)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(string(out), "CHILD control: true") || !slices.Contains(seen, "GET http://"+notLocal+"/control") {
		t.Fatalf("the proxy settings were not in force in the child: %v\n%s", seen, out)
	}
	if len(seen) != 1 {
		t.Errorf("a request to Home Assistant went through the proxy of the environment: the proxy saw %v", seen)
	}
}

// What this package can send is what its first comment says, held against the source: every text in a file of
// the package (tests aside) that looks like a path of Home Assistant's API is one of three, and none holds
// "toggle"; the only HTTP method named is POST (GET is devices.ReadJSON's own); and nothing calls a function
// of net/http that sends a request other than the one Do of Switch.
func TestWhatThisPackageCanSend(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{"/api/states/", "/api/services/switch/turn_on", "/api/services/switch/turn_off"}
	var paths, methods, sends []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if x.Kind != token.STRING {
					return true
				}
				s, _ := strconv.Unquote(x.Value)
				if strings.Contains(strings.ToLower(s), "toggle") {
					t.Errorf("%s: the text %q", fset.Position(x.Pos()), s)
				}
				if strings.HasPrefix(s, "/api") || strings.Contains(s, "/services") || strings.Contains(s, "/states") {
					paths = append(paths, s)
				}
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "http" {
					switch {
					case strings.HasPrefix(x.Sel.Name, "Method"):
						methods = append(methods, x.Sel.Name)
					case slices.Contains([]string{"Get", "Post", "PostForm", "Head", "DefaultClient", "NewRequest"}, x.Sel.Name):
						t.Errorf("%s: http.%s", fset.Position(x.Pos()), x.Sel.Name)
					}
				}
				if x.Sel.Name == "Do" || x.Sel.Name == "RoundTrip" {
					sends = append(sends, fset.Position(x.Pos()).Filename)
				}
			}
			return true
		})
	}
	slices.Sort(paths)
	slices.Sort(allowed)
	if !slices.Equal(paths, allowed) {
		t.Errorf("the paths of Home Assistant's API in this package are %q, want exactly %q", paths, allowed)
	}
	if !slices.Equal(methods, []string{"MethodPost"}) {
		t.Errorf("the HTTP methods named in this package are %v, want one MethodPost", methods)
	}
	if !slices.Equal(sends, []string{"ha.go"}) {
		t.Errorf("requests are sent from %v, want one place in ha.go", sends)
	}
}
