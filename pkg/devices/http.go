package devices

import (
	"bytes"
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
	"sync"
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

// Limits on one JSON answer of a device or a BMC. Decoded into generic values (maps, lists), JSON costs up to
// about 350 bytes for every value, whatever the answer's size: one answer of 4 MiB of {"":0} held 216 MiB, the
// same size as nested one-key objects 275 MiB, and 6 KB on the wire were enough when sent with gzip. The agent
// has 64 MiB in all and the panel 512 MiB (audit 4, T-02). So an answer is cut three ways, each counted on the
// JSON text itself (after gzip): its size, its number of values and its depth. With these limits the most
// expensive answer that still passes holds under 3 MiB while it is used.
//
// What the supported devices send (the answers in pkg/power's TestLargeHonestAnswers, written after the devices'
// documentation): a Tasmota "Status 8" up to 700 bytes with 65 values, a Shelly Gen2 status 300 bytes, a Shelly
// Gen1 /status 1 to 2 KiB with 75 values, and the largest, a BMC's Redfish "Power" document with one entry for
// every voltage sensor and power supply: for a large four-socket server about 2100 values, 6 levels deep, in
// 30 KiB (95 KiB when the BMC indents it). The limits leave that document 2.7 times its size and 3.8 times its
// values. A BMC with a larger document can be read through a smaller one (power_path).
const (
	maxJSONBody   = 256 << 10 // bytes of JSON text
	maxJSONValues = 8192      // objects, lists, numbers, strings, true, false, null (keys are not counted)
	maxJSONDepth  = 32        // objects and lists inside each other
)

// jsonGate lets one decoded answer exist at a time: it is held from the decoding until the caller has taken
// what it needs. So the decoded values of many devices answering at once cost what those of one cost. Nothing
// waits for the network while holding it (an answer is read completely first), so one slow device cannot hold
// up the others.
//
// The text of an answer is outside the gate: every answer that is still arriving holds its own buffer, up to
// maxJSONBody. That does add up over devices. The review of this fix measured it with the real agent in
// 64 MiB: 128 hostile sources that each send 255 KiB and then say nothing use 48 MiB, about 170 at the same
// moment use it up (before the fix one answer was enough). Reading fewer at a time would let silent devices
// hold up honest ones, so it is left so. NUT and Tuya answers do not come through here at all: they have
// limits of their own (NUTMaxReply, the Tuya frame size), which this fix did not change.
var jsonGate sync.Mutex

// jsonBudget counts the values and the depth of the first JSON value in a text, as it arrives.
//
// It counts one value for the outermost "{" or "[", and one for every "{", "[" and "," outside strings. Every
// value in a JSON text is either the outermost one, the first in its object or list, or follows a comma, so for
// an answer that is an object or a list the count is never below the number of values a decoder builds (an
// empty object or list counts as two). Text that is not JSON may be counted wrongly, but it is never decoded:
// the decoder checks the whole value before it builds anything.
type jsonBudget struct {
	values, depth int
	inString, esc bool
	started, done bool // done: the first value is complete
}

func (b *jsonBudget) scan(p []byte) error {
	for _, c := range p {
		if b.done {
			return nil
		}
		if b.inString {
			switch {
			case b.esc:
				b.esc = false
			case c == '\\':
				b.esc = true
			case c == '"':
				b.inString = false
			}
			continue
		}
		switch c {
		case '"':
			b.inString = true
		case '{', '[':
			if !b.started {
				b.started = true
				b.values++
			}
			b.values++
			if b.depth++; b.depth > maxJSONDepth {
				return Errf("answer from device is nested too deep (over %d levels)", maxJSONDepth)
			}
		case ',':
			b.values++
		case '}', ']':
			if b.depth--; b.depth <= 0 {
				b.done = b.started
			}
		}
		if b.values > maxJSONValues {
			return Errf("answer from device has too many values (over %d)", maxJSONValues)
		}
	}
	return nil
}

// DecodeJSON reads one JSON object from body and hands it to use. It reads at most 256 KiB and refuses an answer
// with more than 8192 values or more than 32 levels (see maxJSONBody); what follows the object is not read.
// Only one answer is decoded at a time, and the next one waits until use has returned: use should take the few
// values it needs and return, and must not call DecodeJSON, ReadJSON or GetJSON itself. The object is nil for
// the JSON value null.
func DecodeJSON(body io.Reader, use func(map[string]any) error) error {
	var budget jsonBudget
	buf := make([]byte, 0, 1024)
	for !budget.done {
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}
		room := buf[len(buf):min(cap(buf), maxJSONBody+1)]
		n, err := body.Read(room)
		if serr := budget.scan(room[:n]); serr != nil {
			return serr
		}
		if buf = buf[:len(buf)+n]; len(buf) > maxJSONBody {
			return Errf("answer from device is too large (over %d KiB)", maxJSONBody>>10)
		}
		if err != nil { // the end, or a failed read: what has arrived is decoded or refused below
			break
		}
	}
	jsonGate.Lock()
	defer jsonGate.Unlock()
	var out map[string]any
	if err := json.NewDecoder(bytes.NewReader(buf)).Decode(&out); err != nil {
		return Errf("invalid JSON from device")
	}
	return use(out)
}

// GetJSON fetches a JSON object. auth: "" | "basic" | "digest". Any answer that is not 2xx is an error
// ("http <code>"), a redirect included. The answer is limited as DecodeJSON describes. A caller that reads a
// few values from it should use ReadJSON, which keeps only one decoded answer alive at a time.
func GetJSON(ctx context.Context, c *http.Client, rawURL, auth, user, pass string) (map[string]any, error) {
	var out map[string]any
	err := ReadJSON(ctx, c, rawURL, auth, user, pass, func(d map[string]any) error { out = d; return nil })
	return out, err
}

// ReadJSON fetches a JSON object like GetJSON and hands it to use (see DecodeJSON). It returns use's error.
func ReadJSON(ctx context.Context, c *http.Client, rawURL, auth, user, pass string, use func(map[string]any) error) error {
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
		return describeHTTP(err)
	}
	if resp.StatusCode == http.StatusUnauthorized && auth == "digest" && pass != "" {
		chal := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		u, _ := url.Parse(rawURL)
		hdr, derr := DigestAuthorization(chal, http.MethodGet, u.RequestURI(), user, pass)
		if derr != nil {
			return derr
		}
		if resp, err = do(hdr); err != nil {
			return describeHTTP(err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 { // 3xx too: redirects are not followed, and their body is not a reading
		return &HTTPStatusError{Code: resp.StatusCode}
	}
	return DecodeJSON(resp.Body, use)
}

// HTTPStatusError is an HTTP error status from a device (shown as "http <code>").
type HTTPStatusError struct{ Code int }

// Error returns "http <code>".
func (e *HTTPStatusError) Error() string { return fmt.Sprintf("http %d", e.Code) }
