package agent

// Audit 4, T-07: the BMC relay's Redfish backend sent the BMC account's user name and password (HTTP Basic) in
// its very first request, to whatever certificate answered, and wrote the "learned" pin only after an HTTP
// answer. Someone on the BMC's network who showed any certificate, read the header and hung up got the password
// with every request, was never pinned, and the agent only said "not reachable".

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBMCListener is a TLS listener with a certificate of its own. It records the Basic credentials of every
// request it can read. With hangUp it then closes the connection without an answer; otherwise it answers like a
// BMC whose system is on.
type fakeBMCListener struct {
	url, fingerprint string
	mu               sync.Mutex
	creds            []string
	handshakes       int
}

func (l *fakeBMCListener) seen() (creds []string, handshakes int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.creds...), l.handshakes
}

func newFakeBMCListener(t *testing.T, hangUp bool) *fakeBMCListener {
	t.Helper()
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	sum := sha256.Sum256(cert.Certificate[0])
	l := &fakeBMCListener{url: "https://" + ln.Addr().String(), fingerprint: hex.EncodeToString(sum[:])}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				l.mu.Lock()
				l.handshakes++
				l.mu.Unlock()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				if a := req.Header.Get("Authorization"); strings.HasPrefix(a, "Basic ") {
					if b, err := base64.StdEncoding.DecodeString(a[6:]); err == nil {
						l.mu.Lock()
						l.creds = append(l.creds, string(b))
						l.mu.Unlock()
					}
				}
				if hangUp {
					return
				}
				body := `{"Members":[{"@odata.id":"/redfish/v1/Systems/1"}],"PowerState":"On"}`
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			}(c)
		}
	}()
	return l
}

// selfSignedCert makes a new self-signed certificate for 127.0.0.1, another one with every call.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "a BMC"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// No fingerprint in config.yaml and none learned by an earlier version: nothing but a TLS handshake reaches
// the address. No request, no user name, no password, whether the other side answers or hangs up, for "status"
// and for "on". Nothing is pinned by itself. The answer names the setting and the certificate that was shown.
func TestBMCRelayRedfishSendsNoPasswordToAnUnnamedCertificate(t *testing.T) {
	t.Setenv("T07_BMC_PW", "t07-test-bmc-password")
	for _, hangUp := range []bool{true, false} {
		l := newFakeBMCListener(t, hangUp)
		pins := filepath.Join(t.TempDir(), "bmc-pins.json")
		relay := NewBMCRelay(BMCRelayConfig{Enabled: true, Targets: []BMCTarget{
			{ID: "srv1", Backend: "redfish", URL: l.url, Username: "fairy", PasswordEnv: "T07_BMC_PW"}}}, pins)
		for i, action := range []string{"status", "on", "status"} {
			st, body := relay.Handle(context.Background(), BMCRequest{Target: "srv1", Action: action})
			msg, _ := body["error"].(string)
			if st != 409 || body["code"] != "bmc_fingerprint_missing" {
				t.Fatalf("hangUp=%v request %d (%s): want 409 bmc_fingerprint_missing, got %d %v", hangUp, i+1, action, st, body)
			}
			if !strings.Contains(msg, "tls_fingerprint: "+l.fingerprint) || !strings.Contains(msg, "srv1") {
				t.Fatalf("the answer does not say what to set: %q", msg)
			}
			if strings.Contains(msg, "t07-test-bmc-password") {
				t.Fatalf("the password is in the answer: %q", msg)
			}
			if _, err := os.Stat(pins); err == nil {
				t.Fatalf("hangUp=%v: a certificate was pinned by itself after request %d", hangUp, i+1)
			}
		}
		creds, handshakes := l.seen()
		if len(creds) != 0 {
			t.Fatalf("hangUp=%v: a certificate nobody named received the BMC user and password %d times: %q", hangUp, len(creds), creds)
		}
		if handshakes == 0 {
			t.Fatalf("hangUp=%v: the listener was never asked for its certificate: the test tests nothing", hangUp)
		}
	}
}

// With the fingerprint in config.yaml the relay works, and another certificate gets nothing.
func TestBMCRelayRedfishFingerprintInConfig(t *testing.T) {
	t.Setenv("T07_BMC_PW", "t07-test-bmc-password")
	l := newFakeBMCListener(t, false)
	relay := NewBMCRelay(BMCRelayConfig{Enabled: true, Targets: []BMCTarget{
		{ID: "srv1", URL: l.url, Username: "fairy", PasswordEnv: "T07_BMC_PW", TLSFingerprint: l.fingerprint}}}, "")
	if st, body := relay.Handle(context.Background(), BMCRequest{Target: "srv1", Action: "status"}); st != 200 || body["power"] != "on" {
		t.Fatal(st, body)
	}
	if creds, _ := l.seen(); len(creds) == 0 || creds[0] != "fairy:t07-test-bmc-password" {
		t.Fatalf("the named certificate did not get the login: %q", creds)
	}
	other := newFakeBMCListener(t, true) // someone else at the BMC's address, with a certificate of their own
	relay = NewBMCRelay(BMCRelayConfig{Enabled: true, Targets: []BMCTarget{
		{ID: "srv1", URL: other.url, Username: "fairy", PasswordEnv: "T07_BMC_PW", TLSFingerprint: l.fingerprint}}}, "")
	if st, body := relay.Handle(context.Background(), BMCRequest{Target: "srv1", Action: "on"}); st != 502 || body["code"] != "bmc_certificate_changed" {
		t.Fatal(st, body)
	}
	if creds, _ := other.seen(); len(creds) != 0 {
		t.Fatalf("another certificate than the named one received the login: %q", creds)
	}
}

// A certificate that an earlier version learned (bmc-pins.json in the state folder) is still used, so a relay
// that worked keeps working after the update; another certificate gets nothing.
func TestBMCRelayRedfishKeepsAPinLearnedEarlier(t *testing.T) {
	t.Setenv("T07_BMC_PW", "t07-test-bmc-password")
	l := newFakeBMCListener(t, false)
	pins := filepath.Join(t.TempDir(), "bmc-pins.json")
	saved, _ := json.Marshal(map[string]string{"srv1": l.fingerprint})
	if err := os.WriteFile(pins, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := BMCRelayConfig{Enabled: true, Targets: []BMCTarget{{ID: "srv1", URL: l.url, Username: "fairy", PasswordEnv: "T07_BMC_PW"}}}
	relay := NewBMCRelay(cfg, pins)
	if st, body := relay.Handle(context.Background(), BMCRequest{Target: "srv1", Action: "status"}); st != 200 || body["power"] != "on" {
		t.Fatal(st, body)
	}
	if got := relay.WithoutFingerprint(); len(got) != 0 {
		t.Fatalf("a target with a learned certificate is listed as unusable: %v", got)
	}
	other := newFakeBMCListener(t, true) // someone else at the BMC's address
	cfg.Targets[0].URL = other.url
	relay = NewBMCRelay(cfg, pins)
	if st, body := relay.Handle(context.Background(), BMCRequest{Target: "srv1", Action: "on"}); st != 502 || body["code"] != "bmc_certificate_changed" {
		t.Fatal(st, body)
	}
	if creds, _ := other.seen(); len(creds) != 0 {
		t.Fatalf("another certificate than the learned one received the login: %q", creds)
	}
}

// Which targets cannot be used until tls_fingerprint is set: what the agent warns about at start and what
// check-config prints.
func TestBMCRelayTargetsWithoutFingerprint(t *testing.T) {
	cfg := BMCRelayConfig{Enabled: true, Targets: []BMCTarget{
		{ID: "ipmi", Host: "192.168.1.5", Username: "u", PasswordEnv: "P"},
		{ID: "named", URL: "https://192.168.1.6", Username: "u", PasswordEnv: "P", TLSFingerprint: strings.Repeat("ab", 32)},
		{ID: "unnamed", URL: "https://192.168.1.7", Username: "u", PasswordEnv: "P"},
		{ID: "learned", URL: "https://192.168.1.8", Username: "u", PasswordEnv: "P"},
	}}
	if got := strings.Join(cfg.RedfishWithoutFingerprint(), ","); got != "unnamed,learned" {
		t.Fatalf("config: %q", got)
	}
	pins := filepath.Join(t.TempDir(), "bmc-pins.json")
	saved, _ := json.Marshal(map[string]string{"learned": strings.Repeat("cd", 32)})
	if err := os.WriteFile(pins, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(NewBMCRelay(cfg, pins).WithoutFingerprint(), ","); got != "unnamed" {
		t.Fatalf("relay: %q", got)
	}
}
