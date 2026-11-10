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

// MaxResponseHeaderBytes is how much response header Fairy reads from a device, a BMC, a Proxmox API, an agent
// or a release server before it gives the answer up. net/http's own limit, when none is set, is 10 MiB for
// every answer, read into memory before the first byte of the body: nine or ten hostile devices or agents
// answering at once took the panel past its memory limit with headers alone (the body limits do not count
// them), and the agent has 64 MiB in all. What these senders really send: a Tasmota or Shelly plug a few
// hundred bytes, a Redfish BMC and the Proxmox API one to two KiB (session cookies, links), an agent 150 bytes,
// GitHub about 5 KiB. 64 KiB leaves all of them more than ten times that.
const MaxResponseHeaderBytes = 64 << 10

var lanTransport = &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 2, IdleConnTimeout: 90 * time.Second,
	MaxResponseHeaderBytes: MaxResponseHeaderBytes,
	DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext}

// noRedirect makes a client hand back a 3xx answer instead of following it. A device, a BMC or a Proxmox API
// that answers with a redirect could otherwise send Fairy to any address and scheme it can reach, and to the
// same host name over plain http with the credentials still attached.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// LANClient never uses an HTTP proxy (devices live on the local network / tailnet) and never follows redirects.
func LANClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: lanTransport, CheckRedirect: noRedirect}
}

// TLSClient for BMCs: optional custom CA / verification off (owner's choice in config). It has its own
// transport: build it once per device, not per request, so connections (and BMC sessions) are reused.
// Like every client of this package it never follows redirects.
func TLSClient(timeout time.Duration, cfg *tls.Config) *http.Client {
	return ClientWith(timeout, TLSTransport(cfg))
}

// TLSTransport is a LAN transport (no proxy, the same limit on response headers) with these TLS settings.
func TLSTransport(cfg *tls.Config) *http.Transport {
	tr := lanTransport.Clone()
	tr.TLSClientConfig = cfg
	return tr
}

// ClientWith is a client with this timeout on a shared transport. It never follows redirects: a BMC that sends
// http to https must be configured with its https address.
func ClientWith(timeout time.Duration, tr http.RoundTripper) *http.Client {
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: noRedirect}
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

// GetJSON fetches a JSON object. auth: "" | "basic" | "digest". Any answer that is not 2xx is an error
// ("http <code>"), a redirect included.
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
	if resp.StatusCode >= 300 { // 3xx too: redirects are not followed, and their body is not a reading
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
