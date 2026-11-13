package devices

// The "bearer" mode of ReadJSON / GetJSON (Home Assistant's long-lived token): one GET with the token in the
// Authorization header, and every limit the other modes have.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBearer is a made-up token, put together when the test runs: no text in this file looks like a credential.
func fakeBearer() string {
	return strings.Join([]string{"fake", "bearer", "token", "for", "tests"}, "-")
}

// seenRequests records what a server was sent.
type seenRequests struct {
	mu      sync.Mutex
	methods []string
	paths   []string
	auth    []string
}

func (s *seenRequests) add(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.methods = append(s.methods, r.Method)
	s.paths = append(s.paths, r.URL.RequestURI())
	s.auth = append(s.auth, r.Header.Get("Authorization"))
}

func (s *seenRequests) all() (methods, paths, auth []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.methods...), append([]string(nil), s.paths...), append([]string(nil), s.auth...)
}

func TestBearerIsOneGETWithTheTokenInTheHeader(t *testing.T) {
	tok := fakeBearer()
	for name, c := range map[string]struct {
		auth, pass string
		wantHeader string
	}{
		"bearer with a token":           {"bearer", tok, "Bearer " + tok},
		"bearer without a token":        {"bearer", "", ""},
		"no auth, a pass is not sent":   {"", tok, ""},
		"basic stays basic":             {"basic", tok, "Basic "},
		"digest sends nothing at first": {"digest", tok, ""},
	} {
		var seen seenRequests
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen.add(r)
			_, _ = io.WriteString(w, `{"state":"12.5"}`)
		}))
		d, err := GetJSON(context.Background(), LANClient(3*time.Second), srv.URL+"/api/states/sensor.desk_plug_power", c.auth, "someone", c.pass)
		srv.Close()
		if err != nil || d["state"] != "12.5" {
			t.Fatalf("%s: %v %v", name, d, err)
		}
		methods, paths, auth := seen.all()
		if len(methods) != 1 || methods[0] != http.MethodGet || paths[0] != "/api/states/sensor.desk_plug_power" {
			t.Errorf("%s: want one GET of the path asked, got %v %v", name, methods, paths)
			continue
		}
		if got := auth[0]; got != c.wantHeader && !(c.wantHeader == "Basic " && strings.HasPrefix(got, "Basic ")) {
			t.Errorf("%s: Authorization header %q", name, got)
		}
		if c.auth == "bearer" && strings.Contains(auth[0], "someone") {
			t.Errorf("%s: the user name went into the header: %q", name, auth[0])
		}
	}
}

// A refused token is one request and "http 401": there is no second try as with digest, whatever the answer
// offers (a WWW-Authenticate header that would start a digest exchange).
func TestBearerRefusedIsOneRequest(t *testing.T) {
	tok := fakeBearer()
	for _, code := range []int{401, 403, 404, 500} {
		var seen seenRequests
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen.add(r)
			w.Header().Set("WWW-Authenticate", `Digest realm="x", nonce="abc", qop="auth"`)
			w.WriteHeader(code)
			fmt.Fprintf(w, `{"message":"no: %s"}`, r.Header.Get("Authorization")) // an answer that repeats the header
		}))
		d, err := GetJSON(context.Background(), LANClient(3*time.Second), srv.URL+"/api/states/sensor.x", "bearer", "", tok)
		srv.Close()
		var he *HTTPStatusError
		if d != nil || err == nil || Describe(err) != fmt.Sprintf("http %d", code) {
			t.Errorf("%d: got %v %v", code, d, err)
		} else if he, _ = err.(*HTTPStatusError); he == nil || he.Code != code {
			t.Errorf("%d: not an HTTPStatusError with the code: %#v", code, err)
		}
		if methods, _, _ := seen.all(); len(methods) != 1 {
			t.Errorf("%d: %d requests for one read", code, len(methods))
		}
		for form, text := range map[string]string{"Error()": err.Error(), "%+v": fmt.Sprintf("%+v", err), "%#v": fmt.Sprintf("%#v", err), "Describe": Describe(err)} {
			if strings.Contains(text, tok) || strings.Contains(text, "Bearer") {
				t.Errorf("%d: %s shows the token or the header: %s", code, form, text)
			}
		}
	}
}

// A redirect is not followed with a bearer token either: the place it points to gets no request, so the token
// cannot be sent on (Go itself would resend the header to the same host name on another port).
func TestBearerDoesNotFollowRedirects(t *testing.T) {
	tok := fakeBearer()
	// the https client trusts exactly the test server's certificate, as a ca_file does
	clients := map[string]func(src *httptest.Server) *http.Client{
		"LANClient": func(*httptest.Server) *http.Client { return LANClient(3 * time.Second) },
		"ClientWith": func(src *httptest.Server) *http.Client {
			pool := x509.NewCertPool()
			pool.AddCert(src.Certificate())
			return ClientWith(3*time.Second, TLSTransport(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
		},
	}
	for name, mk := range clients {
		for _, code := range []int{301, 302, 303, 307, 308} {
			tgt := &target{}
			elsewhere := httptest.NewServer(tgt)
			src := redirector(t, name != "LANClient", code, func() string { return elsewhere.URL + "/api/states/sensor.x" })
			d, err := GetJSON(context.Background(), mk(src), src.URL+"/api/states/sensor.x", "bearer", "", tok)
			hits, auth := tgt.seen()
			if hits != 0 {
				t.Errorf("%s %d: followed (%d requests, Authorization sent: %v)", name, code, hits, len(auth) > 0 && auth[0] != "")
			}
			if d != nil || err == nil || Describe(err) != fmt.Sprintf("http %d", code) {
				t.Errorf("%s %d: want \"http %d\", got %v %v", name, code, code, d, err)
			}
			elsewhere.Close()
		}
	}
}

// The limits on one answer hold in bearer mode as in every other: an answer over 256 KiB is given up, with
// fixed words and without the token.
func TestBearerAnswerIsLimited(t *testing.T) {
	tok := fakeBearer()
	big := `{"state":"12.5","attributes":{"friendly_name":"` + strings.Repeat("a", maxJSONBody) + `"}}`
	many := `{"state":"12.5","attributes":{"x":[` + strings.TrimSuffix(strings.Repeat("0,", maxJSONValues+8), ",") + `]}}`
	for name, c := range map[string]struct{ body, want string }{
		"over 256 KiB":     {big, "answer from device is too large (over 256 KiB)"},
		"over 8192 values": {many, "answer from device has too many values (over 8192)"},
		"not JSON":         {"<html>Bearer " + tok, "invalid JSON from device"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, c.body) }))
		called := false
		err := ReadJSON(context.Background(), LANClient(5*time.Second), srv.URL+"/api/states/sensor.x", "bearer", "", tok,
			func(map[string]any) error { called = true; return nil })
		srv.Close()
		if err == nil || called || Describe(err) != c.want {
			t.Errorf("%s: called=%v, error %v", name, called, err)
		}
		if err != nil && strings.Contains(err.Error(), tok) {
			t.Errorf("%s: the error shows the token", name)
		}
	}
}
