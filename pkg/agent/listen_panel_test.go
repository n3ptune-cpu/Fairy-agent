package agent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// blockingProcs is a collector whose process listing takes as long as the test says (the real one takes the
// time of a /proc scan, half a second for the first listing).
type blockingProcs struct {
	collect.Collector
	release chan struct{}
	calls   *atomic.Int64
}

func (b blockingProcs) Processes(ctx context.Context, o collect.ProcOptions) ([]collect.Process, int, error) {
	if b.calls != nil {
		b.calls.Add(1)
	}
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
	return b.Collector.Processes(ctx, o)
}

// slowProcs is a collector whose process listing takes d, like a /proc scan on a busy machine.
type slowProcs struct {
	collect.Collector
	d     time.Duration
	calls *atomic.Int64
}

func (s slowProcs) Processes(ctx context.Context, o collect.ProcOptions) ([]collect.Process, int, error) {
	s.calls.Add(1)
	select {
	case <-time.After(s.d):
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
	return s.Collector.Processes(ctx, o)
}

// servePanel runs the agent's real HTTP server behind LimitConns on 127.0.0.1 with floodPanel as the paired
// panel's address; no loopback address counts as this machine.
func servePanel(t *testing.T, r *rig, o ConnLimits) (*LimitListener, string) {
	t.Helper()
	return servePanelAt(t, r, o, floodPanel)
}

// servePanelAt is servePanel with another address as the panel's.
func servePanelAt(t *testing.T, r *rig, o ConnLimits, panel string) (*LimitListener, string) {
	t.Helper()
	probe, err := net.Listen("tcp", panel+":0")
	if err != nil {
		t.Skip("no other 127.0.0.0/8 address to connect from:", err)
	}
	probe.Close()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o.Panel = func() string { return panel }
	o.Local = func(remote, _ netip.Addr) bool { return false }
	ln := LimitConns(tcp, o)
	srv := r.a.Server()
	srv.ErrorLog = nil
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln, ln.Addr().String()
}

// processRequest sends one GET /processes with the read token on a new connection from the panel's address and
// does not read the answer.
func processRequest(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := dialFrom(floodPanel, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "GET /processes?limit=25&sort=cpu HTTP/1.1\r\nHost: agent\r\nAuthorization: Bearer %s\r\n\r\n", readTok)
	return c
}

// Review N6. The paired panel was a sender like any other for the per-sender cap: eight connections. The panel
// opens one connection per request in flight, and a viewer's browser asks for the process list of a machine
// every two seconds per open tab; the agent served those one at a time. Eight process requests in flight were
// enough for the panel's next /metrics poll, or an admin's "cancel shutdown", to be reset. (The reviewer's
// proof, with more of them.)
func TestPanelsOwnRequestsDoNotLockItOut(t *testing.T) {
	r := newRig(t, "power_control: {enabled: true}\ncontrol_rate_per_min: 60\n")
	release := make(chan struct{})
	var listings atomic.Int64
	r.a.d.Collector = blockingProcs{Collector: r.a.d.Collector, release: release, calls: &listings}
	ln, addr := servePanel(t, r, ConnLimits{})
	// 24 viewers' process tabs, through the panel, while a listing takes its time
	for i := 0; i < 24; i++ {
		processRequest(t, addr)
	}
	// 16 of them wait for the one listing (maxProcessWaiters); the other 8 were told "busy" at once
	waitStats(t, ln, func(s ConnStats) bool { return s.Trusted == 24 })
	deadline := time.Now().Add(5 * time.Second)
	for len(r.a.procWaiters) != maxProcessWaiters || listings.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("%d requests wait for %d listings, want %d for 1", len(r.a.procWaiters), listings.Load(), maxProcessWaiters)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// the panel's poll, and an admin's control request
	if st, err := metricsFrom(floodPanel, addr); err != nil || st != 200 {
		t.Fatalf("with 24 of the panel's own requests in flight, the panel's /metrics poll: HTTP %d, %v (stats %+v)", st, err, ln.Stats())
	}
	if st, body, err := requestFrom(floodPanel, addr, "POST", "/power", ctlTok, `{"action":"shutdown","delay_s":120}`); err != nil || st != 200 {
		t.Fatalf("with 24 of the panel's own requests in flight, a control request: HTTP %d %s, %v", st, body, err)
	}
	if s := ln.Stats(); s.Refused != 0 {
		t.Fatalf("a connection of the panel was refused: %+v", s)
	}
	// a 17th waiter is answered at once, with a code the panel can show, and the connection stays usable
	st, body, err := requestFrom(floodPanel, addr, "GET", "/processes?limit=5", readTok, "")
	if err != nil || st != 503 || !bytes.Contains(body, []byte(`"code":"busy"`)) {
		t.Fatalf("one more process request: HTTP %d %s, %v", st, body, err)
	}
	close(release)
	// every waiting request is answered from the one listing
	deadline = time.Now().Add(5 * time.Second)
	for len(r.a.procWaiters) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("requests still wait after the listing was made:", len(r.a.procWaiters))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := listings.Load(); n != 1 {
		t.Fatalf("%d listings were made for 16 requests that asked at the same time, want 1", n)
	}
}

// requestFrom sends one request on a new connection from src and returns the answer.
func requestFrom(src, addr, method, path, token, body string) (int, []byte, error) {
	c, err := dialFrom(src, addr)
	if err != nil {
		return 0, nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: agent\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s", method, path, token, len(body), body)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

// A connection of the panel that is over a cap waits for a slot instead of being reset, and is served the
// moment one of the panel's requests is done. It waits ConnWait at most; then it is reset like any other.
func TestPanelConnWaits(t *testing.T) {
	r := newRig(t, "")
	release := make(chan struct{})
	r.a.d.Collector = blockingProcs{Collector: r.a.d.Collector, release: release}
	ln, addr := servePanel(t, r, ConnLimits{PerSender: 4, PerPanel: 4, Waiting: 2, Wait: 700 * time.Millisecond})
	var four []net.Conn
	for i := 0; i < 4; i++ {
		four = append(four, processRequest(t, addr))
	}
	waitStats(t, ln, func(s ConnStats) bool { return s.Trusted == 4 })

	// the fifth: not answered while the four are busy, answered when they are done
	type answer struct {
		st  int
		err error
		at  time.Time
	}
	fifth := make(chan answer, 1)
	go func() {
		st, err := metricsFrom(floodPanel, addr)
		fifth <- answer{st, err, time.Now()}
	}()
	waitStats(t, ln, func(s ConnStats) bool { return s.Waiting == 1 })
	select {
	case a := <-fifth:
		t.Fatalf("the fifth connection did not wait: HTTP %d, %v", a.st, a.err)
	case <-time.After(200 * time.Millisecond):
	}
	released := time.Now()
	close(release)
	for _, c := range four { // the panel reads its answers and is done with these connections
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatal(resp, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		c.Close()
	}
	if a := <-fifth; a.err != nil || a.st != 200 || a.at.Before(released) {
		t.Fatalf("the fifth connection after the others were done: HTTP %d, %v", a.st, a.err)
	}
	if s := ln.Stats(); s.Refused != 0 || s.Waited != 1 || s.Waiting != 0 || s.Peak > 4 {
		t.Fatalf("%+v", s)
	}
}

// Waiting has two bounds: how many wait (the next one is reset at once) and for how long.
func TestPanelConnWaitIsBounded(t *testing.T) {
	r := newRig(t, "")
	release := make(chan struct{})
	defer close(release)
	r.a.d.Collector = blockingProcs{Collector: r.a.d.Collector, release: release}
	ln, addr := servePanel(t, r, ConnLimits{PerSender: 4, PerPanel: 4, Waiting: 2, Wait: 700 * time.Millisecond})
	for i := 0; i < 4; i++ {
		processRequest(t, addr)
	}
	waitStats(t, ln, func(s ConnStats) bool { return s.Trusted == 4 })
	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	took := make([]time.Duration, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = metricsFrom(floodPanel, addr)
			took[i] = time.Since(start)
		}()
	}
	waitStats(t, ln, func(s ConnStats) bool { return s.Waiting == 2 })
	// a third one finds the waiting room full
	if st, err := metricsFrom(floodPanel, addr); err == nil {
		t.Fatal("a seventh connection was answered: HTTP", st)
	}
	if s := ln.Stats(); s.Refused != 1 || s.Waiting != 2 || s.Open != 4 {
		t.Fatalf("%+v", s)
	}
	wg.Wait()
	for i, err := range errs {
		if err == nil || took[i] < 600*time.Millisecond || took[i] > 3*time.Second {
			t.Fatalf("waiting connection %d: %v after %s, want a reset after 700 ms", i, err, took[i])
		}
	}
	if s := ln.Stats(); s.Refused != 3 || s.Waiting != 0 || s.Waited != 0 || s.Open != 4 {
		t.Fatalf("%+v", s)
	}
}

// A stranger never waits: over a cap its connection is closed at once, as before (M4).
func TestStrangerConnNeverWaits(t *testing.T) {
	ln, addr := serveLimited(t, ConnLimits{})
	for i := 0; i < MaxConnsPerSender; i++ {
		c, held, err := halfOpen("127.0.1.1", addr, 100)
		if err != nil || !held {
			t.Fatal(i, held, err)
		}
		defer c.Close()
	}
	start := time.Now()
	if c, held, err := halfOpen("127.0.1.1", addr, 100); err != nil || held {
		c.Close()
		t.Fatal("a stranger's ninth connection was kept:", held, err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatal("a stranger's ninth connection was closed only after", took)
	}
	if s := ln.Stats(); s.Waiting != 0 || s.Refused != 1 || s.Open != MaxConnsPerSender {
		t.Fatalf("%+v", s)
	}
}

// Closing the listener closes the connections that wait.
func TestListenerCloseDropsWaitingConns(t *testing.T) {
	r := newRig(t, "")
	release := make(chan struct{})
	defer close(release)
	r.a.d.Collector = blockingProcs{Collector: r.a.d.Collector, release: release}
	ln, addr := servePanel(t, r, ConnLimits{PerSender: 2, PerPanel: 2, Wait: time.Minute})
	for i := 0; i < 2; i++ {
		processRequest(t, addr)
	}
	waitStats(t, ln, func(s ConnStats) bool { return s.Trusted == 2 })
	c, err := dialFrom(floodPanel, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitStats(t, ln, func(s ConnStats) bool { return s.Waiting == 1 })
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatal("the waiting connection was not closed with the listener:", err)
	}
	if _, err := ln.Accept(); err == nil {
		t.Fatal("Accept after Close")
	}
	if s := ln.Stats(); s.Waiting != 0 {
		t.Fatalf("%+v", s)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// panelClient is the HTTP client the panel talks to agents with (devices.LANClient: no cap on connections per
// host, two idle ones kept), sending from the panel's address.
func panelClient(t *testing.T, panel string) *http.Client {
	t.Helper()
	tr := devices.TLSTransport(nil) // a copy of the shared transport's settings
	tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(panel)}}).DialContext
	t.Cleanup(tr.CloseIdleConnections)
	return devices.ClientWith(0, tr)
}

// Review N6, on the real server with the panel's own HTTP client. Viewers' Processes tabs (or one script with
// a viewer's session) send process requests through the panel, 12, 24, 48 and 96 at a time and some 5000 a
// second in all, while the panel polls /metrics as it does (here every 20 ms instead of every second, each
// with the panel's 4 s limit) and an admin sends control requests. Not one poll and not one control request
// may fail, and no connection of the panel may be refused. On b59a2d0 twelve at a time lost 44 to 47 of 60
// polls on the real binary.
//
// The last round, 144 at a time, is at the edge of what the agent takes (32 slots and 128 waiting): it is
// run and reported, not judged. On a slow run a few of its connections find the waiting room full.
func TestPanelBurstNeverStarvesItsPolls(t *testing.T) {
	if testing.Short() {
		t.Skip("takes several seconds")
	}
	for i, parallel := range []int{12, 24, 48, 96, 144} {
		t.Run(fmt.Sprint(parallel, " process requests at a time"), func(t *testing.T) {
			// A panel address of its own for every round: the panel's client opens a new connection for nearly
			// every request (it keeps two idle ones), and the ports of closed connections stay taken for a
			// minute.
			panel := fmt.Sprintf("127.0.7.%d", i+1)
			r := newRig(t, "power_control: {enabled: true}\ncontrol_rate_per_min: 60\n")
			var listings atomic.Int64
			r.a.d.Collector = slowProcs{Collector: r.a.d.Collector, d: 300 * time.Millisecond, calls: &listings}
			ln, addr := servePanelAt(t, r, ConnLimits{}, panel)
			client := panelClient(t, panel)
			get := func(path string, limit time.Duration) (int, error) {
				ctx, cancel := context.WithTimeout(context.Background(), limit)
				defer cancel()
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+path, nil)
				req.Header.Set("Authorization", "Bearer "+readTok)
				resp, err := client.Do(req)
				if err != nil {
					return 0, err
				}
				defer resp.Body.Close()
				_, _ = io.Copy(io.Discard, resp.Body)
				return resp.StatusCode, nil
			}
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var procOK, procBusy, procFailed atomic.Int64
			for i := 0; i < parallel; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						switch st, err := get("/processes?limit=25&sort=cpu", 6*time.Second); {
						case err != nil:
							procFailed.Add(1)
						case st == 200:
							procOK.Add(1)
						case st == 503:
							procBusy.Add(1)
						default:
							procFailed.Add(1)
						}
						time.Sleep(time.Duration(parallel) * 200 * time.Microsecond) // some 5000 requests a second in all
					}
				}()
			}
			polls, control, pollsFailed, controlFailed := 0, 0, 0, 0
			var slowest time.Duration
			for end := time.Now().Add(2500 * time.Millisecond); time.Now().Before(end); {
				start := time.Now()
				if st, err := get("/metrics", 4*time.Second); err != nil || st != 200 {
					if pollsFailed++; pollsFailed <= 3 {
						t.Logf("poll %d failed: HTTP %d, %v (stats %+v)", polls, st, err, ln.Stats())
					}
				}
				slowest = max(slowest, time.Since(start))
				polls++
				if polls%10 == 0 { // an admin's control request, as the panel sends it
					ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
					req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/power",
						bytes.NewReader([]byte(`{"action":"cancel"}`)))
					req.Header.Set("Authorization", "Bearer "+ctlTok)
					req.Header.Set("Content-Type", "application/json")
					resp, err := client.Do(req)
					if err != nil {
						controlFailed++
						t.Logf("control request %d failed: %v (stats %+v)", control, err, ln.Stats())
					} else {
						if resp.StatusCode >= 500 {
							controlFailed++
							t.Logf("control request %d: HTTP %d", control, resp.StatusCode)
						}
						resp.Body.Close()
					}
					cancel()
					control++
				}
				time.Sleep(20 * time.Millisecond)
			}
			close(stop)
			wg.Wait()
			s := ln.Stats()
			t.Logf("%d at a time: %d polls (%d failed, slowest %s) and %d control requests (%d failed); process requests: %d answered, "+
				"%d told busy, %d failed; %d listings made; connections: peak %d open, %d waited for a slot, %d refused",
				parallel, polls, pollsFailed, slowest.Round(time.Millisecond), control, controlFailed, procOK.Load(), procBusy.Load(), procFailed.Load(),
				listings.Load(), s.Peak, s.Waited, s.Refused)
			if parallel > MaxConnsPanel+MaxWaitingConns/2 {
				return // beyond what is promised: a measurement
			}
			if pollsFailed != 0 || controlFailed != 0 {
				t.Errorf("%d polls and %d control requests failed", pollsFailed, controlFailed)
			}
			// How many polls fit in a round measures the machine, not the agent: with six copies of this test
			// at once on four cores a round had 12 to 19 of them, the slowest took half a second, and none
			// failed. What is judged is that none fails inside the panel's own 4 s; the count only has to show
			// that the poller ran.
			if polls < 3 {
				t.Errorf("only %d polls in 2.5 s", polls)
			}
			if s.Refused != 0 {
				t.Errorf("%d of the panel's connections were refused", s.Refused)
			}
			if procFailed.Load() != 0 {
				t.Errorf("%d process requests failed", procFailed.Load())
			}
			if parallel <= maxProcessWaiters && procBusy.Load() != 0 {
				t.Errorf("%d of the process requests were told busy with only %d at a time", procBusy.Load(), parallel)
			}
			if n := listings.Load(); n > 4 {
				t.Errorf("%d listings in 2.5 s: /proc is to be read once a second at most, however many ask", n)
			}
		})
	}
}

// M4 with the panel's cap and the waiting room in use: a flood of half-open connections from 300 addresses
// while the panel's address itself opens far more connections than it may have. The agent still never has
// more than 64 connections open and 128 waiting, strangers still hold at most 48, and the heap does not grow
// with either.
func TestConnFloodWithPanelBurst(t *testing.T) {
	if testing.Short() {
		t.Skip("opens thousands of connections")
	}
	ln, addr := serveLimited(t, ConnLimits{})
	const conns, senders, workers, panelConns = 3000, 300, 24, 400

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var (
		mu   sync.Mutex
		kept []net.Conn
		next atomic.Int64
		wg   sync.WaitGroup
	)
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range kept {
			c.Close()
		}
	}()
	keep := func(c net.Conn) {
		mu.Lock()
		kept = append(kept, c)
		mu.Unlock()
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= conns {
					return
				}
				s := i % senders
				if c, held, err := halfOpen(fmt.Sprintf("127.0.%d.%d", 1+s/250, 1+s%250), addr, 2048); err == nil && held {
					keep(c)
				}
			}
		}()
	}
	// the panel's address: 400 connections that each hold 2 KiB of unfinished request
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < panelConns; i++ {
			c, err := dialFrom(floodPanel, addr)
			if err != nil {
				continue
			}
			_, _ = c.Write([]byte("GET /metrics HTTP/1.1\r\nHost: agent\r\nX-Fill: " + string(bytes.Repeat([]byte("a"), 2048))))
			keep(c)
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	// meanwhile this machine asks, as the update's health check does: answered every time
	asked := make(chan int, 1)
	go func() {
		n := 0
		for {
			select {
			case <-done:
				asked <- n
				return
			default:
			}
			if st, err := metricsFrom(floodLocal, addr); err != nil || st != 200 {
				t.Errorf("/metrics from this machine during the flood: HTTP %d, %v (stats %+v)", st, err, ln.Stats())
			}
			n++
			time.Sleep(5 * time.Millisecond)
		}
	}()
	peakWaiting := 0
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for flooding := true; flooding; {
		select {
		case <-done:
			flooding = false
		case <-tick.C:
			s := ln.Stats()
			peakWaiting = max(peakWaiting, s.Waiting)
			if s.Open > MaxConns || s.Waiting > MaxWaitingConns || s.Open-s.Trusted > MaxConns-ReservedConns {
				t.Fatalf("over a cap during the flood: %+v", s)
			}
		}
	}
	s := ln.Stats()
	if s.Peak > MaxConns {
		t.Fatalf("more than %d connections were open: %+v", MaxConns, s)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	grown := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("flood of %d connections from %d senders plus %d from the panel's address: refused %d, peak open %d, peak waiting %d, "+
		"waited and served %d; this machine was answered %d times; heap %+d KiB", conns, senders, panelConns, s.Refused, s.Peak,
		peakWaiting, s.Waited, <-asked, grown/1024)
	if peakWaiting == 0 {
		t.Error("no connection of the panel's address ever waited: the test did not reach the waiting room")
	}
	if grown > 4<<20 {
		t.Fatalf("the heap grew by %d KiB during the flood", grown/1024)
	}
}
