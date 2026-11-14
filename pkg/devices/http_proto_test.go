package devices

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Every client of this package speaks HTTP/1.1, also to a server that offers HTTP/2: the transports have a
// dialer of their own and no ForceAttemptHTTP2. The agent relies on it in one place: with GODEBUG=http2debug
// Go prints the headers of every HTTP/2 request it sends, the Authorization header among them, to the log
// (pkg/agent, GuardStdLog and TestStdLogGuard). A client that sends a device's password or a token must not
// get there.
func TestDeviceClientsSpeakHTTP1Only(t *testing.T) {
	var mu sync.Mutex
	var protos []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protos = append(protos, r.Proto)
		mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	// the server does speak HTTP/2 with a client that asks for it
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("the test's server answered its own client with %s, want HTTP/2", resp.Proto)
	}

	// the two ways an https client is built here (a BMC, a Home Assistant with ca_file); both are the LAN
	// transport with TLS settings
	for name, c := range map[string]*http.Client{
		"TLSClient":    TLSClient(10*time.Second, &tls.Config{RootCAs: pool}),
		"TLSTransport": ClientWith(10*time.Second, TLSTransport(&tls.Config{RootCAs: pool})),
	} {
		d, err := GetJSON(context.Background(), c, srv.URL, "bearer", "", "x")
		if err != nil || d["ok"] != true {
			t.Fatalf("%s: %v %v", name, d, err)
		}
		c.CloseIdleConnections()
	}
	if lanTransport.ForceAttemptHTTP2 || lanTransport.Protocols != nil || lanTransport.DialContext == nil || len(lanTransport.TLSNextProto) != 0 {
		t.Errorf("the LAN transport would try HTTP/2: %+v", lanTransport)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(protos) != 3 || protos[0] != "HTTP/2.0" {
		t.Fatalf("the server saw %v", protos)
	}
	for _, p := range protos[1:] {
		if p != "HTTP/1.1" {
			t.Errorf("a client of this package spoke %s to a server that offers HTTP/2, want HTTP/1.1 (requests: %v)", p, protos)
		}
	}
}
