package devices

// Audit 3, L10: the clients for BMCs and Proxmox followed redirects (up to 10 steps), also from https to http
// and to other hosts. With the host name unchanged the credentials went along in clear.

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// target records what reaches the place a redirect points to.
type target struct {
	mu   sync.Mutex
	hits int
	auth []string
}

func (g *target) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.hits++
	g.auth = append(g.auth, r.Header.Get("Authorization"))
	g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"PowerControl":[{"PowerConsumedWatts":31337}]}`))
}

func (g *target) seen() (int, []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hits, g.auth
}

func redirector(t *testing.T, tlsServer bool, code int, location func() string) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", location())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"PowerControl":[{"PowerConsumedWatts":4242}]}`)) // a redirect's body is no reading
	})
	var srv *httptest.Server
	if tlsServer {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestClientsDoNotFollowRedirects(t *testing.T) {
	insecure := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server certificate
	clients := map[string]func() *http.Client{
		"TLSClient":  func() *http.Client { return TLSClient(3*time.Second, insecure) },
		"ClientWith": func() *http.Client { return ClientWith(3*time.Second, TLSTransport(insecure)) },
		"LANClient":  func() *http.Client { return LANClient(3 * time.Second) },
	}
	for name, mk := range clients {
		for _, code := range []int{301, 302, 303, 307, 308} {
			// same host name, plain http, another port: Go would resend the Authorization header here
			tgt := &target{}
			plain := httptest.NewServer(tgt)
			https := name != "LANClient"
			src := redirector(t, https, code, func() string { return plain.URL + "/redfish/v1/Chassis/1/Power" })
			d, err := GetJSON(context.Background(), mk(), src.URL+"/redfish/v1/Chassis/1/Power", "basic", "root", "bmc-password")
			hits, auth := tgt.seen()
			if hits != 0 {
				t.Errorf("%s %d to http on the same host: followed (%d requests, Authorization %q)", name, code, hits, auth)
			}
			if err == nil || d != nil || !strings.Contains(Describe(err), "http 3") {
				t.Errorf("%s %d: want an \"http %d\" error, got %v %v", name, code, code, d, err)
			}
			plain.Close()

			// another host name (localhost instead of 127.0.0.1)
			tgt = &target{}
			other := httptest.NewServer(tgt)
			otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
			src = redirector(t, https, code, func() string { return otherURL + "/x" })
			if _, err := GetJSON(context.Background(), mk(), src.URL+"/x", "basic", "root", "bmc-password"); err == nil {
				t.Errorf("%s %d to another host: no error", name, code)
			}
			if hits, _ := tgt.seen(); hits != 0 {
				t.Errorf("%s %d to another host: followed (%d requests)", name, code, hits)
			}
			other.Close()
		}
	}
}

// The client itself (the panel uses TLSClient for Proxmox with its own request code): Do returns the 3xx answer.
func TestTLSClientReturnsTheRedirectAnswer(t *testing.T) {
	tgt := &target{}
	plain := httptest.NewServer(tgt)
	defer plain.Close()
	src := redirector(t, true, 302, func() string { return plain.URL + "/api2/json/nodes" })
	c := TLSClient(3*time.Second, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test server certificate
	req, _ := http.NewRequest(http.MethodGet, src.URL+"/api2/json/nodes", nil)
	req.Header.Set("Authorization", "PVEAPIToken=fairy@pve!ro=secret")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if hits, auth := tgt.seen(); hits != 0 {
		t.Fatalf("followed: %d requests, Authorization %q", hits, auth)
	}
}
