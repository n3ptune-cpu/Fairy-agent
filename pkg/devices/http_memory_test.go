package devices

// Audit 4, T-02: one answer of a configured device, decoded into generic JSON, cost about 50 times its size in
// memory. About 1 MiB of {"":0}, or 6 KB of it sent with gzip, or one answer of nested one-key objects, took the
// agent past its 64 MiB and the panel past its 512 MiB, again after every restart.
//
// These tests feed the shapes the auditors and verifiers used and measure what one answer costs.

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// maxAnswerCost is what one device answer may make this process allocate in all (not only what stays): the
// read buffer, the decoder's copy, the decoded values and the HTTP client's own work. Before the fix one 4 MiB
// answer of {"":0} allocated 285 MiB and kept 216 MiB.
const maxAnswerCost = 8 << 20

// maxAnswerLive is what a decoded answer may still hold after a full collection, while the caller keeps it.
const maxAnswerLive = 4 << 20

// hostileShapes are JSON answers of just under size bytes. Every one starts with a good reading, so that a caller
// that accepted it would show a normal value.
func hostileShapes(size int) map[string][]byte {
	list := func(unit string) []byte { // {"apower":5,...,"x":[unit,unit,...]}
		n := (size - len(goodHead) - 16) / (len(unit) + 1)
		if n < 1 {
			n = 1
		}
		return []byte(goodHead + strings.TrimSuffix(strings.Repeat(unit+",", n), ",") + "]}")
	}
	chain := func(open, leaf, shut string, depth int) string {
		return strings.Repeat(open, depth) + leaf + strings.Repeat(shut, depth)
	}
	return map[string][]byte{
		`flat {"":0}`:        list(`{"":0}`),                           // the auditors' shape: 51 times its size
		`flat {"a":1}`:       list(`{"a":1}`),                          //
		`flat [{"":1}]`:      list(`[{"":1}]`),                         // the BMC relay proof's shape
		`flat {}`:            list(`{}`),                               //
		`flat []`:            list(`[]`),                               //
		`flat 1`:             list(`1`),                                //
		`flat ""`:            list(`""`),                               //
		`nested objects 9k`:  list(chain(`{"":`, "0", "}", 9000)),      // verifier V5: 5 bytes a map, under Go's own depth limit
		`nested objects 20`:  list(chain(`{"":`, "0", "}", 20)),        // inside any sensible depth limit
		`nested objects 2`:   list(chain(`{"":`, "0", "}", 2)),         //
		`deep arrays 9k`:     list(chain(`[`, "", "]", 9000)),          //
		`deep arrays 20`:     list(chain(`[`, "", "]", 20)),            //
		`one chain, objects`: list(chain(`{"":`, "0", "}", size/5-64)), // deeper than Go's own limit when size is large
		`one chain, arrays`:  list(chain(`[`, "", "]", size/2-128)),    //
	}
}

// goodHead opens an answer that every parser of this package reads as a normal value (5 W).
const goodHead = `{"apower":5,"StatusSNS":{"ENERGY":{"Power":5}},"meters":[{"power":5}],"PowerControl":[{"PowerConsumedWatts":5}],"x":[`

// gzipped packs body the way a device may send it (Content-Encoding: gzip).
func gzipped(t testing.TB, body []byte) []byte {
	t.Helper()
	var zb bytes.Buffer
	zw, err := gzip.NewWriterLevel(&zb, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return zb.Bytes()
}

// serveBody answers every request with body (sent with gzip when zipped).
func serveBody(t testing.TB, body []byte, zipped bool) string {
	t.Helper()
	wire := body
	if zipped {
		wire = gzipped(t, body)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if zipped {
			w.Header().Set("Content-Encoding", "gzip")
		}
		_, _ = w.Write(wire)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// cost runs f and returns what it allocated in all and what its result still holds after a full collection.
func cost(f func() any) (total, live uint64) {
	runtime.GC()
	var m0, m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m0)
	v := f()
	runtime.ReadMemStats(&m1)
	runtime.GC()
	runtime.ReadMemStats(&m2)
	runtime.KeepAlive(v)
	if m2.HeapAlloc > m0.HeapAlloc {
		live = m2.HeapAlloc - m0.HeapAlloc
	}
	return m1.TotalAlloc - m0.TotalAlloc, live
}

// A hostile answer of any of the proof shapes and of any size costs a small, fixed amount of memory, with and
// without gzip, and it is not taken for a reading.
func TestGetJSONHostileAnswerCostsLittle(t *testing.T) {
	for _, size := range []int{4 << 20, 1 << 20, 256 << 10, 64 << 10} {
		for name, body := range hostileShapes(size) {
			for _, zipped := range []bool{false, true} {
				url := serveBody(t, body, zipped)
				var err error
				total, live := cost(func() any {
					var d map[string]any
					d, err = GetJSON(context.Background(), LANClient(10*time.Second), url, "", "", "")
					return d
				})
				label := fmt.Sprintf("%s, %d KiB, gzip %v", name, len(body)>>10, zipped)
				if total > maxAnswerCost || live > maxAnswerLive {
					t.Errorf("%s: allocated %d KiB, kept %d KiB (limits %d and %d KiB), err=%v",
						label, total>>10, live>>10, maxAnswerCost>>10, maxAnswerLive>>10, err)
				}
				if err == nil {
					t.Errorf("%s: accepted as a good answer", label)
				} else if _, ok := err.(*Error); !ok {
					t.Errorf("%s: the error is not one of this package's fixed words: %v", label, err)
				}
			}
		}
	}
}

// A gzip answer is counted by what comes out of it: 64 MiB of JSON travel as about 64 KB.
func TestGetJSONGzipBomb(t *testing.T) {
	body := append([]byte(goodHead), bytes.Repeat([]byte(`{"":0},`), (64<<20)/7)...)
	body = append(body[:len(body)-1], "]}"...)
	wire := gzipped(t, body)
	if len(wire) > 256<<10 {
		t.Fatalf("the test answer is %d bytes on the wire, expected a small one", len(wire))
	}
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			t.Errorf("the client did not ask for gzip (Accept-Encoding %q): this test no longer tests anything", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("Content-Encoding", "gzip")
		n, _ := w.Write(wire)
		served.Add(int64(n))
	}))
	defer srv.Close()
	body = nil
	var err error
	total, live := cost(func() any {
		var d map[string]any
		d, err = GetJSON(context.Background(), LANClient(10*time.Second), srv.URL, "", "", "")
		return d
	})
	t.Logf("64 MiB of JSON in %d bytes on the wire: allocated %d KiB, kept %d KiB, err=%v", len(wire), total>>10, live>>10, err)
	if err == nil || total > maxAnswerCost || live > maxAnswerLive {
		t.Fatalf("allocated %d KiB, kept %d KiB, err=%v", total>>10, live>>10, err)
	}
}

// The most expensive answers that still pass every limit: this is the real upper bound of one answer.
func TestGetJSONWorstAcceptedAnswer(t *testing.T) {
	chain := func(depth int) string { return strings.Repeat(`{"":`, depth) + "0" + strings.Repeat("}", depth) }
	fill := func(unit string, valuesPerUnit int) []byte { // as many units as the value limit allows
		n := (maxJSONValues - 16) / valuesPerUnit
		return []byte(goodHead + strings.TrimSuffix(strings.Repeat(unit+",", n), ",") + "]}")
	}
	pad := func(b []byte) []byte { // the same values in the largest body that passes: long keys cost memory too
		room := maxJSONBody - len(b) - 16
		return append([]byte(`{"`+strings.Repeat("k", room)+`":0,`), b[1:]...)
	}
	deep := maxJSONDepth - 2
	for name, body := range map[string][]byte{
		"one-key objects in a list":        fill(`{"":0}`, 2),
		"chains of nested objects":         fill(chain(deep), deep+1),
		"chains, padded to the size limit": pad(fill(chain(deep), deep+1)),
		"numbers":                          fill("1", 1),
	} {
		url := serveBody(t, body, false)
		var err error
		total, live := cost(func() any {
			var d map[string]any
			d, err = GetJSON(context.Background(), LANClient(10*time.Second), url, "", "", "")
			return d
		})
		t.Logf("%s: %d bytes, allocated %d KiB, kept %d KiB", name, len(body), total>>10, live>>10)
		if err != nil {
			t.Errorf("%s: %d bytes inside every limit were refused: %v", name, len(body), err)
		}
		if total > maxAnswerCost || live > maxAnswerLive {
			t.Errorf("%s: allocated %d KiB, kept %d KiB (limits %d and %d KiB)", name, total>>10, live>>10, maxAnswerCost>>10, maxAnswerLive>>10)
		}
	}
}

// The limits themselves, one at a time, each with the answer just inside and just outside.
func TestJSONLimits(t *testing.T) {
	get := func(body []byte) error {
		return DecodeJSON(bytes.NewReader(body), func(map[string]any) error { return nil })
	}
	list := func(n int) []byte { // n values in all: the object, the list, n-2 numbers
		return []byte(`{"x":[` + strings.TrimSuffix(strings.Repeat("1,", n-2), ",") + `]}`)
	}
	nest := func(depth int) []byte {
		return []byte(strings.Repeat(`{"a":`, depth) + "1" + strings.Repeat("}", depth))
	}
	sized := func(n int) []byte { // one string, n bytes in all
		return []byte(`{"a":"` + strings.Repeat("x", n-8) + `"}`)
	}
	for name, c := range map[string]struct {
		body []byte
		want string // "" = accepted
	}{
		"values at the limit":   {list(maxJSONValues), ""},
		"values over the limit": {list(maxJSONValues + 1), "too many values"},
		"depth at the limit":    {nest(maxJSONDepth), ""},
		"depth over the limit":  {nest(maxJSONDepth + 1), "nested too deep"},
		"size at the limit":     {sized(maxJSONBody), ""},
		"size over the limit":   {sized(maxJSONBody + 1), "too large"},
		"not JSON":              {[]byte("<html>,,,,[[[[</html>"), "invalid JSON from device"},
		"cut off":               {[]byte(`{"apower":5,"x":[1,2`), "invalid JSON from device"},
		"empty":                 {nil, "invalid JSON from device"},
		// brackets, commas and quotes inside strings are text, not structure
		"structure inside strings": {[]byte(`{"a":"` + strings.Repeat(`[{,\"\\`, maxJSONValues) + `"}`), ""},
	} {
		err := get(c.body)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: want an error with %q, got %v", name, c.want, err)
		}
	}
}

// What a device sends after its first JSON value was ignored before and still is, and an answer is complete as
// soon as that value is: a device that keeps the connection open does not hold the reading back.
func TestDecodeJSONStopsAfterTheFirstValue(t *testing.T) {
	var got map[string]any
	err := DecodeJSON(strings.NewReader(" \r\n{\"apower\": 5}\r\n<trailer>,,,[[[["), func(d map[string]any) error { got = d; return nil })
	if err != nil || got["apower"] != 5.0 {
		t.Fatal(got, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"apower": 7}`))
		w.(http.Flusher).Flush()
		<-r.Context().Done() // never ends the answer
	}))
	defer srv.Close()
	start := time.Now()
	d, err := GetJSON(context.Background(), LANClient(20*time.Second), srv.URL, "", "", "")
	if err != nil || d["apower"] != 7.0 {
		t.Fatal(d, err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("waited %s for the end of an answer that was complete", took)
	}
}

// Only one decoded answer exists at a time: a second one waits until the first has been used. So many devices
// answering at once cost what one costs.
func TestDecodeJSONOneAtATime(t *testing.T) {
	inside, second, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		_ = DecodeJSON(strings.NewReader(`{"a":1}`), func(map[string]any) error {
			close(inside)
			<-release
			return nil
		})
	}()
	<-inside
	go func() {
		_ = DecodeJSON(strings.NewReader(`{"b":2}`), func(map[string]any) error { close(second); return nil })
	}()
	select {
	case <-second:
		t.Fatal("a second answer was decoded and used while the first was still in use")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case <-second:
	case <-time.After(10 * time.Second):
		t.Fatal("the second answer was never used")
	}
}

// The count of values is never below what the decoder builds, for any input the decoder accepts.
func FuzzJSONBudget(f *testing.F) {
	for _, s := range []string{`{"apower":5}`, `{"a":[1,{"b":[]},"x,[{"],"c":{}}`, `{"a":"\\\"],[{"}`, ` {"a":{"b":{"c":[[[1]]]}}} trailing`,
		`{"StatusSNS":{"ENERGY":{"Power":[1,2,3]}}}`, `null`, `[1,2]`, `"{[,"`, `{"\"":{"\\":[]}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var b jsonBudget
		budgetErr := b.scan(body)
		var got map[string]any
		if err := DecodeJSON(bytes.NewReader(body), func(d map[string]any) error { got = d; return nil }); err != nil {
			return
		}
		if budgetErr != nil {
			t.Fatalf("decoded although over the budget: %v", budgetErr)
		}
		values, depth := 0, 0
		var walk func(v any, d int)
		walk = func(v any, d int) {
			values++
			if d > depth {
				depth = d
			}
			switch x := v.(type) {
			case map[string]any:
				for _, e := range x {
					walk(e, d+1)
				}
			case []any:
				for _, e := range x {
					walk(e, d+1)
				}
			}
		}
		if got != nil {
			walk(got, 1)
		}
		if values > b.values || depth > maxJSONDepth || values > maxJSONValues {
			t.Fatalf("decoder built %d values, %d deep; counted %d", values, depth, b.values)
		}
	})
}
