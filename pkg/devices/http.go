package devices

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var lanTransport = &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 2, IdleConnTimeout: 90 * time.Second,
	DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}

// LANClient never uses an HTTP proxy (devices live on the local network / tailnet).
func LANClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: lanTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// TLSClient for BMCs: optional custom CA / verification off (owner's choice in config). It has its own
// transport: build it once per device, not per request, so connections (and BMC sessions) are reused.
func TLSClient(timeout time.Duration, cfg *tls.Config) *http.Client {
	return ClientWith(timeout, TLSTransport(cfg))
}

// TLSTransport is a LAN transport (no proxy) with these TLS settings.
func TLSTransport(cfg *tls.Config) *http.Transport {
	tr := lanTransport.Clone()
	tr.TLSClientConfig = cfg
	return tr
}

// ClientWith is a client with this timeout on a shared transport.
func ClientWith(timeout time.Duration, tr http.RoundTripper) *http.Client {
	return &http.Client{Timeout: timeout, Transport: tr}
}

func describeHTTP(err error) error {
	var de *Error
	if errors.As(err, &de) {
		return err
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return Errf("timeout")
	}
	if strings.Contains(err.Error(), "certificate") {
		return Errf("tls verification failed")
	}
	return Errf("connection failed")
}

// GetJSON fetches a JSON object. auth: "" | "basic" | "digest".
func GetJSON(ctx context.Context, c *http.Client, rawURL, auth, user, pass string) (map[string]any, error) {
	do := func(hdr string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, Errf("invalid url")
		}
		req.Header.Set("Accept", "application/json")
		if auth == "basic" && pass != "" {
			req.SetBasicAuth(user, pass)
		}
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		return c.Do(req)
	}
	resp, err := do("")
	if err != nil {
		return nil, describeHTTP(err)
	}
	if resp.StatusCode == http.StatusUnauthorized && auth == "digest" && pass != "" {
		chal := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		u, _ := url.Parse(rawURL)
		hdr, derr := DigestAuthorization(chal, http.MethodGet, u.RequestURI(), user, pass)
		if derr != nil {
			return nil, derr
		}
		if resp, err = do(hdr); err != nil {
			return nil, describeHTTP(err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, &HTTPStatusError{Code: resp.StatusCode}
	}
	var out map[string]any
	dec := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
	if err := dec.Decode(&out); err != nil {
		return nil, Errf("invalid JSON from device")
	}
	return out, nil
}

// HTTPStatusError is an HTTP error status from a device (shown as "http <code>").
type HTTPStatusError struct{ Code int }

// Error returns "http <code>".
func (e *HTTPStatusError) Error() string { return fmt.Sprintf("http %d", e.Code) }
