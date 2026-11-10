package devices

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// headerServer answers every request with a prepared answer whose header has headerBytes of filler. The
// answer is built once, before any measurement, and written as raw bytes: nothing is allocated here per
// request.
func headerServer(t *testing.T, headerBytes int) (base string) {
	t.Helper()
	body := `{"apower": 5}`
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n")
	for sb.Len() < headerBytes { // many header lines of 1 KiB, as a hostile device would send
		sb.WriteString("X-Fill-" + strconv.Itoa(sb.Len()) + ": " + strings.Repeat("a", 1000) + "\r\n")
	}
	sb.WriteString("\r\n" + body)
	answer := []byte(sb.String())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				_, _ = c.Write(answer)
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

// The response header is limited to 64 KiB on every client this package builds (review of the panel's data
// paths, N3). net/http's own limit is 10 MiB when none is set, read into memory before the body's limit is
// even looked at: an answer with 9 MiB of headers was accepted, and nine or ten hostile devices or agents
// answering at once took the panel past its 512 MiB. Now such an answer fails at once and costs a few KiB.
func TestResponseHeaderIsLimited(t *testing.T) {
	if MaxResponseHeaderBytes != 64<<10 || lanTransport.MaxResponseHeaderBytes != MaxResponseHeaderBytes {
		t.Fatal(MaxResponseHeaderBytes, lanTransport.MaxResponseHeaderBytes)
	}
	clients := map[string]*http.Client{
		"LANClient":                LANClient(5 * time.Second),
		"TLSClient":                TLSClient(5*time.Second, &tls.Config{}),
		"ClientWith(TLSTransport)": ClientWith(5*time.Second, TLSTransport(&tls.Config{})),
	}
	for name, c := range clients {
		if tr, ok := c.Transport.(*http.Transport); !ok || tr.MaxResponseHeaderBytes != MaxResponseHeaderBytes {
			t.Fatalf("%s has no limit on the response header", name)
		}
	}
	huge := headerServer(t, 9<<20)
	normal := headerServer(t, 2<<10) // more header than any real device sends
	roomy := headerServer(t, 48<<10) // far more: still read
	for name, c := range clients {
		// what real devices send, and ten times that: read as before
		for _, base := range []string{normal, roomy} {
			d, err := GetJSON(context.Background(), c, base+"/rpc/Switch.GetStatus?id=0", "", "", "")
			if err != nil || d["apower"] != 5.0 {
				t.Fatalf("%s: an ordinary answer: %v %v", name, d, err)
			}
		}
		// 9 MiB of header: refused at once, with a fixed word, and almost nothing allocated
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		d, err := GetJSON(context.Background(), c, huge+"/rpc/Switch.GetStatus?id=0", "", "", "")
		took := time.Since(start)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Fatalf("%s: an answer with 9 MiB of header was accepted: %v", name, d)
		}
		if Describe(err) != "connection failed" {
			t.Errorf("%s: the error is %q", name, Describe(err))
		}
		if took > 2*time.Second {
			t.Errorf("%s: refused only after %s", name, took)
		}
		if allocated := int64(after.TotalAlloc) - int64(before.TotalAlloc); allocated > 1<<20 {
			t.Errorf("%s: %d KiB were allocated for an answer with 9 MiB of header", name, allocated>>10)
		} else {
			t.Logf("%s: 9 MiB of header refused after %s, %d KiB allocated", name, took.Round(time.Millisecond), allocated>>10)
		}
	}
	// ten at once, as ten hostile devices would: the heap in use stays where it was
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := GetJSON(context.Background(), LANClient(5*time.Second), huge+"/status", "", "", ""); err == nil {
				t.Error("accepted")
			}
		}()
	}
	wg.Wait()
	runtime.ReadMemStats(&after)
	if allocated := int64(after.TotalAlloc) - int64(before.TotalAlloc); allocated > 4<<20 {
		t.Errorf("ten answers with 9 MiB of header each: %d KiB allocated", allocated>>10)
	}
}
