package power

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

const (
	plugPassword = "S3cret/Plug+pw&x=1" // with characters that are written differently inside an address
	status8      = `{"StatusSNS":{"Time":"2026-01-01T00:00:00","ENERGY":{"Total":12.5,"Power":95,"Voltage":230,"Current":0.41}}}`
)

// fakePlug is a Tasmota plug with a web password. header: it takes the password in an Authorization header
// (newer firmware). warn200: without a password it answers 200 with a WARNING instead of 401 (older firmware).
type fakePlug struct {
	header, warn200 bool
	mu              sync.Mutex
	urls            []string // every request's address as the plug saw it
	auth            []string // every request's Authorization header
}

func (p *fakePlug) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.urls = append(p.urls, r.URL.String())
	p.auth = append(p.auth, r.Header.Get("Authorization"))
	p.mu.Unlock()
	q := r.URL.Query()
	u, pw, basic := r.BasicAuth()
	ok := q.Get("user") == "admin" && q.Get("password") == plugPassword
	if p.header && basic && u == "admin" && pw == plugPassword {
		ok = true
	}
	switch {
	case r.URL.Path != "/cm" || q.Get("cmnd") != "Status 8":
		http.NotFound(w, r)
	case ok:
		_, _ = w.Write([]byte(status8))
	case p.warn200:
		_, _ = w.Write([]byte(`{"WARNING":"Need user=<username>&password=<password>"}`))
	default:
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"WARNING":"Need user=<username>&password=<password>"}`))
	}
}

func (p *fakePlug) seen() (urls, auth []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.urls...), append([]string(nil), p.auth...)
}

func tasmotaSource(t *testing.T, base string) Source {
	t.Helper()
	t.Setenv("PLUG_PW", plugPassword)
	s, err := Build(map[string]any{"id": "desk", "type": "tasmota", "url": base, "password_env": "PLUG_PW"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// inAddress reports whether text holds the password in any form an address or a message can carry it.
func inAddress(text string) bool {
	return strings.Contains(text, plugPassword) || strings.Contains(text, url.QueryEscape(plugPassword)) ||
		strings.Contains(text, url.PathEscape(plugPassword)) || strings.Contains(text, "password=")
}

// Review O1: the plug's web password travelled in the address of every request (/cm?user=..&password=..).
// A plug that takes it in a header gets it there and never sees an address with it.
func TestTasmotaPasswordGoesInAHeaderWhenThePlugTakesIt(t *testing.T) {
	plug := &fakePlug{header: true}
	srv := httptest.NewServer(plug)
	defer srv.Close()
	s := tasmotaSource(t, srv.URL)
	for i := 0; i < 3; i++ {
		rs, err := s.Read(context.Background(), 2*time.Second)
		if err != nil || len(rs) != 1 || rs[0].Watts == nil || *rs[0].Watts != 95 {
			t.Fatalf("read %d: %+v %v", i, rs, err)
		}
	}
	urls, auth := plug.seen()
	if len(urls) != 3 {
		t.Fatalf("%d requests for 3 reads", len(urls))
	}
	for i, u := range urls {
		if inAddress(u) || strings.Contains(u, "user=") || u != "/cm?cmnd=Status+8" {
			t.Errorf("request %d: the address carries the password or the user: %s", i, u)
		}
		if !strings.HasPrefix(auth[i], "Basic ") {
			t.Errorf("request %d: no Authorization header", i)
		}
	}
}

// A plug with older firmware does not know the header. It is asked Tasmota's documented way, with the password
// in the address, and from then on only that way (no two requests for every reading).
func TestTasmotaOlderFirmwareStillWorks(t *testing.T) {
	for name, plug := range map[string]*fakePlug{"answers 401": {}, "answers 200 with a WARNING": {warn200: true}} {
		srv := httptest.NewServer(plug)
		s := tasmotaSource(t, srv.URL)
		for i := 0; i < 3; i++ {
			rs, err := s.Read(context.Background(), 2*time.Second)
			if err != nil || len(rs) != 1 || rs[0].Watts == nil || *rs[0].Watts != 95 {
				t.Fatalf("%s, read %d: %+v %v", name, i, rs, err)
			}
		}
		urls, _ := plug.seen()
		if len(urls) != 4 || inAddress(urls[0]) || !inAddress(urls[1]) || !inAddress(urls[2]) || !inAddress(urls[3]) {
			t.Errorf("%s: want one try with the header, then the address form three times; got %d requests", name, len(urls))
		}
		srv.Close()
	}
	// a plug without a password is asked as before, with neither
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.URL.RawQuery != "cmnd=Status+8" {
			t.Errorf("a plug without a password was sent %q %q", r.URL.RawQuery, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(status8))
	}))
	defer open.Close()
	s, err := Build(map[string]any{"id": "desk", "type": "tasmota", "url": open.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rs, err := s.Read(context.Background(), 2*time.Second); err != nil || len(rs) != 1 {
		t.Fatal(rs, err)
	}
}

// Whatever goes wrong with a request that carries the password in its address, the address and the password
// are in no error (its text, its details, what the API shows of it) and in no log line.
func TestTasmotaAddressWithPasswordNeverLeaves(t *testing.T) {
	var logged bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	// each case: a plug that needs the address form (so the request in question carries the password), and
	// then fails in its own way
	hang := make(chan struct{})
	defer close(hang)
	needsURL := func(then http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("password") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			then(w, r)
		})
	}
	cases := map[string]http.Handler{
		"wrong password (401 both ways)": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }),
		"server error":                   needsURL(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }),
		"redirect that repeats the address": needsURL(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://192.0.2.1"+r.URL.String(), http.StatusFound)
		}),
		"answer that is not JSON": needsURL(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>" + r.URL.String())) }),
		"answer without readings": needsURL(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"StatusSNS":{}}`)) }),
		"answer that echoes the address": needsURL(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"StatusSNS":{"ENERGY":{"Power":"%s"}}}`, r.URL.String())
		}),
		"connection cut": needsURL(func(w http.ResponseWriter, r *http.Request) {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		}),
		"no answer in time": needsURL(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-hang:
			case <-r.Context().Done():
			}
		}),
	}
	check := func(name string, rs []Reading, err error) {
		t.Helper()
		if err == nil { // an answer that parses: what is passed on are numbers, nothing of the answer's text
			if b, _ := json.Marshal(rs); !strings.Contains(name, "echoes") || inAddress(string(b)) || strings.Contains(string(b), "/cm?") {
				t.Errorf("%s: no error (%s)", name, b)
			}
			return
		}
		for form, text := range map[string]string{"Error()": err.Error(), "%+v": fmt.Sprintf("%+v", err), "%#v": fmt.Sprintf("%#v", err),
			"Describe": devices.Describe(err)} {
			if inAddress(text) || strings.Contains(text, "/cm?") || strings.Contains(text, "admin") {
				t.Errorf("%s: %s shows the address or the password: %s", name, form, text)
			}
		}
		for e := err; e != nil; e = unwrap(e) {
			if _, ok := e.(*url.Error); ok {
				t.Errorf("%s: a *url.Error (which holds the address) is inside the returned error", name)
			}
		}
	}
	for name, h := range cases {
		srv := httptest.NewServer(h)
		s := tasmotaSource(t, srv.URL)
		for i := 0; i < 2; i++ { // the second read goes straight to the address form where the first one worked
			rs, err := s.Read(context.Background(), 300*time.Millisecond)
			check(name, rs, err)
		}
		srv.CloseClientConnections()
		srv.Close()
	}
	// nothing listens at all, and an address the request cannot even be made for
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String()
	ln.Close()
	for name, base := range map[string]string{"nothing listens": dead} {
		s := tasmotaSource(t, base)
		st := s.(*tasmota)
		st.inURL.Store(true) // the address form at once
		rs, err := s.Read(context.Background(), 300*time.Millisecond)
		check(name, rs, err)
	}
	st := &tasmota{c: TasmotaConfig{Base: Base{ID: "desk"}, URL: "http://exa mple.invalid\x7f", Username: "admin", PasswordEnv: "PLUG_PW"}}
	st.inURL.Store(true)
	rs, err := st.Read(context.Background(), 300*time.Millisecond)
	check("an address that cannot be parsed", rs, err)

	if inAddress(logged.String()) || strings.Contains(logged.String(), "/cm?") {
		t.Errorf("a log line shows the address or the password:\n%s", logged.String())
	}
	// the second lock: an error that would carry the address is replaced by a fixed word
	leaky := &url.Error{Op: "Get", URL: "http://192.0.2.1/cm?cmnd=Status+8&password=" + url.QueryEscape(plugPassword) + "&user=admin", Err: context.DeadlineExceeded}
	if got := safeError(leaky, plugPassword); inAddress(got.Error()) || got.Error() != "request failed" {
		t.Fatal(got)
	}
	if got := safeError(fmt.Errorf("odd: %s", plugPassword), plugPassword); inAddress(got.Error()) {
		t.Fatal(got)
	}
	plain := devices.Errf("timeout")
	if got := safeError(plain, plugPassword); got != plain {
		t.Fatal("an ordinary error was replaced:", got)
	}
}

func unwrap(err error) error {
	u, ok := err.(interface{ Unwrap() error })
	if !ok {
		return nil
	}
	return u.Unwrap()
}
