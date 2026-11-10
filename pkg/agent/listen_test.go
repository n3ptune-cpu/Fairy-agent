package agent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

// The admission rules, without a network: 64 in all, 8 per sender (32 for the panel's address), 16 of the 64
// kept for the panel and this machine.
func TestConnLimitRules(t *testing.T) {
	l := LimitConns(nil, ConnLimits{})
	if l.o.Total != 64 || l.o.PerSender != 8 || l.o.Reserved != 16 || l.o.PerPanel != 32 || l.o.Waiting != 128 || l.o.Wait != 3*time.Second {
		t.Fatalf("defaults: %+v", l.o)
	}
	// one sender: 8, not 9
	for i := 0; i < 8; i++ {
		if why := l.admit("100.64.0.50", false); why != "" {
			t.Fatal(i, why)
		}
	}
	if why := l.admit("100.64.0.50", false); !strings.Contains(why, "this sender") {
		t.Fatal("ninth connection of one sender:", why)
	}
	// six senders fill what strangers may have (48); a seventh sender gets nothing ...
	for s := 1; s < 6; s++ {
		for i := 0; i < 8; i++ {
			if why := l.admit(fmt.Sprint("100.64.1.", s), false); why != "" {
				t.Fatal(s, i, why)
			}
		}
	}
	if why := l.admit("100.64.2.1", false); !strings.Contains(why, "kept for the panel") {
		t.Fatal("49th stranger:", why)
	}
	// ... but the panel and this machine still get 8 each
	for i := 0; i < 8; i++ {
		if why := l.admit("panel", true); why != "" {
			t.Fatal("panel", i, why)
		}
		if why := l.admit("local", true); why != "" {
			t.Fatal("local", i, why)
		}
	}
	// that is all 64: the panel's next one finds no room (on the wire it waits for one, see TestPanelConnWaits)
	if why := l.admit("panel", true); why != "too many open connections" {
		t.Fatal("65th connection:", why)
	}
	if why := l.admit("local", true); !strings.Contains(why, "this sender") {
		t.Fatal("ninth connection of this machine:", why)
	}
	if st := l.Stats(); st.Open != 64 || st.Trusted != 16 || st.Peak != 64 || st.Refused != 4 {
		t.Fatalf("%+v", st)
	}
	// a closed connection frees its slot for the same and for other senders
	l.release("100.64.0.50", false)
	if why := l.admit("100.64.2.1", false); why != "" {
		t.Fatal(why)
	}
	for i := 0; i < 8; i++ {
		l.release("panel", true)
	}
	if st := l.Stats(); st.Open != 56 || st.Trusted != 8 || st.Peak != 64 || len(l.open) != 8 {
		t.Fatalf("%+v %v", st, l.open)
	}
	// strangers never get the reserved slots, however few the panel uses
	if why := l.admit("100.64.3.1", false); why == "" {
		t.Fatal("a stranger got a reserved slot")
	}

	// The panel's address has its own cap, 32: what the panel can have in flight to one agent (MaxConnsPanel).
	// With eight, as for a stranger, its ninth connection was reset (review N6).
	l = LimitConns(nil, ConnLimits{})
	for i := 0; i < MaxConnsPanel; i++ {
		if why := l.admit("panel", true); why != "" {
			t.Fatal("panel", i, why)
		}
	}
	if why := l.admit("panel", true); !strings.Contains(why, "this sender") {
		t.Fatal("33rd panel connection:", why)
	}
	// the cap is for the panel's address only: a stranger still has eight, and so has this machine
	for i := 0; i < 8; i++ {
		if why := l.admit("100.64.0.50", false); why != "" {
			t.Fatal(i, why)
		}
		if why := l.admit("local", true); why != "" {
			t.Fatal(i, why)
		}
	}
	if why := l.admit("100.64.0.50", false); !strings.Contains(why, "this sender") {
		t.Fatal("ninth connection of a stranger:", why)
	}
	// while the panel holds 32, strangers get what is left of the 64 after this machine's eight
	for s := 1; s <= 2; s++ {
		for i := 0; i < 8; i++ {
			if why := l.admit(fmt.Sprint("100.64.1.", s), false); why != "" {
				t.Fatal(s, i, why)
			}
		}
	}
	if why := l.admit("100.64.1.3", false); why != "too many open connections" {
		t.Fatal("65th connection:", why)
	}
}

type fakeConn struct {
	net.Conn
	remote, local string
}

func (c fakeConn) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(c.remote))
}
func (c fakeConn) LocalAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(c.local))
}

// Who counts as the panel, as this machine, and as one sender.
func TestConnSender(t *testing.T) {
	panel := "100.88.0.7"
	l := LimitConns(nil, ConnLimits{Panel: func() string { return panel }})
	for _, c := range []struct {
		remote, local, key string
		trusted            bool
	}{
		{"100.88.0.7:40000", "100.70.0.1:9101", "panel", true},
		{"[::ffff:100.88.0.7]:40000", "100.70.0.1:9101", "panel", true}, // the same address, IPv4-mapped
		{"100.70.0.1:51000", "100.70.0.1:9101", "local", true},          // the update's health check: own address
		{"127.0.0.1:51000", "127.0.0.1:9101", "local", true},
		{"[::1]:51000", "[::1]:9101", "local", true},
		{"100.88.0.8:40000", "100.70.0.1:9101", "100.88.0.8", false},
		{"100.88.0.8:40001", "100.70.0.1:9101", "100.88.0.8", false}, // the port does not matter
		{"[fd7a:115c:a1e0::1234]:40000", "[fd7a:115c:a1e0::1]:9101", "fd7a:115c:a1e0::/64", false},
		{"[fd7a:115c:a1e0::9999]:40000", "[fd7a:115c:a1e0::1]:9101", "fd7a:115c:a1e0::/64", false}, // one /64, one sender
		{"[fd7a:115c:a1e0:1::1]:40000", "[fd7a:115c:a1e0::1]:9101", "fd7a:115c:a1e0:1::/64", false},
	} {
		key, trusted := l.sender(fakeConn{remote: c.remote, local: c.local})
		if key != c.key || trusted != c.trusted {
			t.Errorf("%s -> %s: got %q %v, want %q %v", c.remote, c.local, key, trusted, c.key, c.trusted)
		}
	}
	// no panel on record (tokens set up by hand), or nonsense in the file: nobody is "the panel"
	for _, p := range []string{"", "not an address", "100.88.0.7:9101"} {
		panel = p
		if key, trusted := l.sender(fakeConn{remote: "100.88.0.7:40000", local: "100.70.0.1:9101"}); trusted || key != "100.88.0.7" {
			t.Errorf("panel %q: %q %v", p, key, trusted)
		}
	}
}

// The opt-in "only the panel's address".
func TestConnPanelOnly(t *testing.T) {
	panel := "100.88.0.7"
	l := LimitConns(nil, ConnLimits{Panel: func() string { return panel }, PanelOnly: true})
	if why := l.admit("100.88.0.8", false); !strings.Contains(why, "only the panel") {
		t.Fatal("a stranger was accepted:", why)
	}
	if why := l.admit("panel", true); why != "" {
		t.Fatal(why)
	}
	if why := l.admit("local", true); why != "" {
		t.Fatal(why)
	}
	// Without a panel address on record the setting fails closed: "nobody but the panel" must not turn into
	// "everybody" because the panel is unknown (never paired through Add host, a join code that expired or
	// was closed for wrong codes, an unreadable state file). This machine itself is still accepted: the
	// update's health check, and `fairy-agent join` runs here anyway.
	for _, p := range []string{"", "not an address", "100.88.0.7:9101"} {
		panel = p
		before := l.Stats()
		for _, stranger := range []string{"100.88.0.8", "100.88.0.7", "fd7a:115c:a1e0::/64", "unknown"} {
			why := l.admit(stranger, false)
			if why != NoPanelRefusal || !strings.Contains(why, "no panel address on record") || !strings.Contains(why, "Re-pair") {
				t.Fatalf("panel %q, sender %s: %q", p, stranger, why)
			}
		}
		if why := l.admit("local", true); why != "" {
			t.Fatalf("panel %q: this machine was refused: %s", p, why)
		}
		l.release("local", true)
		if after := l.Stats(); after.Refused != before.Refused+4 || after.Open != before.Open {
			t.Fatalf("panel %q: %+v -> %+v", p, before, after)
		}
	}
	// once a panel is on record (the join command ran) it is accepted again, and only it
	panel = "100.88.0.9"
	if why := l.admit("panel", true); why != "" {
		t.Fatal(why)
	}
	if why := l.admit("100.88.0.8", false); !strings.Contains(why, "only the panel") {
		t.Fatal("a stranger was accepted:", why)
	}
	// off (the default): strangers are accepted within the caps
	l = LimitConns(nil, ConnLimits{Panel: func() string { return "100.88.0.7" }})
	if why := l.admit("100.88.0.8", false); why != "" {
		t.Fatal(why)
	}
}

// The owner's opt-in is a config key, off by default.
func TestOnlyFromPanelSetting(t *testing.T) {
	if mustParse(t, "").OnlyFromPanel {
		t.Fatal("only_from_panel must be off by default")
	}
	if !mustParse(t, "only_from_panel: true\n").OnlyFromPanel {
		t.Fatal("only_from_panel: true was not read")
	}
	if _, err := Parse([]byte("only_from_panel: maybe\n"), "c.yaml"); err == nil {
		t.Fatal("only_from_panel takes true or false")
	}
}

func TestPairedPanel(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Unix()
	for name, c := range map[string]struct {
		st   *enroll.State
		want string
	}{
		"no file":       {nil, ""},
		"paired":        {&enroll.State{Version: 1, Panel: "100.88.0.7", PairedBy: "100.88.0.7", PairedAt: now, Closed: "paired", ExpiresAt: now - 5}, "100.88.0.7"},
		"code open":     {&enroll.State{Version: 1, Panel: "100.88.0.9", Verifier: "v", CreatedAt: now, ExpiresAt: now + 600}, "100.88.0.9"},
		"code expired":  {&enroll.State{Version: 1, Panel: "100.88.0.9", Verifier: "v", CreatedAt: now - 900, ExpiresAt: now - 300}, ""},
		"closed, wrong": {&enroll.State{Version: 1, Panel: "100.88.0.9", Closed: "too many wrong codes", ExpiresAt: now + 600}, ""},
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		if c.st != nil {
			if err := enroll.WriteState(p, *c.st); err != nil {
				t.Fatal(err)
			}
		}
		if got := PairedPanel(p)(); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
	// the file is not read for every connection: an answer is kept for five seconds
	p := filepath.Join(dir, "cached.json")
	get := PairedPanel(p)
	if get() != "" {
		t.Fatal("no file yet")
	}
	if err := enroll.WriteState(p, enroll.State{Version: 1, PairedBy: "100.88.0.7", Closed: "paired"}); err != nil {
		t.Fatal(err)
	}
	if got := get(); got != "" {
		t.Fatal("read again within five seconds:", got)
	}
	if got := PairedPanel(p)(); got != "100.88.0.7" {
		t.Fatal(got)
	}
	if err := os.WriteFile(p, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := PairedPanel(p)(); got != "" {
		t.Fatal("a broken file:", got)
	}
}

const (
	floodPanel = "127.0.0.9" // "the panel" of the flood tests
	floodLocal = "127.0.0.1" // "this machine"
)

// serveLimited runs the agent's real HTTP server (Agent.Server) behind LimitConns on 127.0.0.1. Of all the
// loopback addresses only floodLocal counts as this machine, so the others can play strangers.
func serveLimited(t *testing.T, o ConnLimits) (*LimitListener, string) {
	t.Helper()
	for _, a := range []string{floodPanel, "127.0.1.1", "127.0.2.50"} {
		probe, err := net.Listen("tcp", a+":0")
		if err != nil {
			t.Skip("this system has no other 127.0.0.0/8 addresses to connect from:", err)
		}
		probe.Close()
	}
	r := newRig(t, "")
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if o.Panel == nil {
		o.Panel = func() string { return floodPanel }
	}
	o.Local = func(remote, _ netip.Addr) bool { return remote.String() == floodLocal }
	ln := LimitConns(tcp, o)
	srv := r.a.Server()
	srv.ErrorLog = nil
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln, ln.Addr().String()
}

func dialFrom(src, addr string) (net.Conn, error) {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 5 * time.Second}
	return d.Dial("tcp", addr)
}

// The flood tests and Windows' ports.
//
// Every outgoing connection takes a local port. Windows has one pool of them for the whole PC, 16384 by
// default (49152 to 65535, whatever the local address), and after a connection is closed the side that closed
// first keeps its port for minutes (TIME_WAIT). On Linux a port is only taken for its own local address, and
// for one minute, which is why the burst test gives every round an address of its own; that does not help on
// Windows. The burst test alone opens some 35000 connections in 13 seconds on Linux, nearly all of them closed
// by the client. On its first run on Windows the suite got through the flood tests and then failed twenty
// tests that came after them, each at its first connection ("connectex: Only one usage of each socket address
// (protocol/network address/port) is normally permitted"), with the test servers on ports at the very top of
// that range. A run could do the same to every other program on the PC for some minutes.
//
// So on Windows these tests open fewer connections (floodPause, floodConns). Measured on Linux with the
// Windows numbers: some 6300 in the whole package instead of 40000, and in the burst test, whose connections
// are the ones the client closes, some 1300 instead of 35000. What the tests judge is the same: how many
// connections are open at a time, who is refused and who waits, and that the panel's and this machine's
// requests are answered throughout. Elsewhere nothing changes.
const windowsPorts = runtime.GOOS == "windows"

// floodConns is how many connections a flood of n opens: all of them, a third on Windows.
func floodConns(n int) int {
	if windowsPorts {
		return n / 3
	}
	return n
}

// floodPause is the pause between two requests of one of the burst's senders: d, on Windows half a second
// (the senders still all ask at the same moment, a few times in a round, instead of as often as they can).
func floodPause(d time.Duration) time.Duration {
	if windowsPorts {
		return 500 * time.Millisecond
	}
	return d
}

func waitStats(t *testing.T, ln *LimitListener, ok func(ConnStats) bool) ConnStats {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s := ln.Stats()
		if ok(s) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out; stats %+v", s)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// metricsFrom asks /metrics with the read token over a new connection from src.
func metricsFrom(src, addr string) (int, error) {
	c, err := dialFrom(src, addr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(c, "GET /metrics HTTP/1.1\r\nHost: agent\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", readTok); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// halfOpen connects from src and sends n bytes of a request header that never ends. held reports whether the
// agent kept the connection (false: it was closed at once).
func halfOpen(src, addr string, n int) (c net.Conn, held bool, err error) {
	c, err = dialFrom(src, addr)
	if errors.Is(err, syscall.ECONNRESET) {
		return nil, false, nil // closed so fast that connecting itself reports it (seen on loopback)
	}
	if err != nil {
		return nil, false, err
	}
	_, _ = c.Write([]byte("GET /metrics HTTP/1.1\r\nHost: agent\r\nX-Fill: " + strings.Repeat("a", n)))
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, rerr := c.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(rerr, &ne) && ne.Timeout() {
		return c, true, nil
	}
	c.Close()
	return nil, false, nil
}

// One sender gets eight connections, whatever it does.
func TestConnLimitPerSender(t *testing.T) {
	ln, addr := serveLimited(t, ConnLimits{})
	var kept []net.Conn
	defer func() {
		for _, c := range kept {
			c.Close()
		}
	}()
	for i := 0; i < 20; i++ {
		c, held, err := halfOpen("127.0.1.1", addr, 100)
		if err != nil {
			t.Fatal(err)
		}
		if held {
			kept = append(kept, c)
		}
	}
	if s := ln.Stats(); len(kept) != 8 || s.Open != 8 || s.Refused != 12 || s.Trusted != 0 {
		t.Fatalf("kept %d, stats %+v", len(kept), s)
	}
	// another sender is not affected, and closing gives the slots back
	if st, err := metricsFrom("127.0.1.2", addr); err != nil || st != 200 {
		t.Fatal(st, err)
	}
	for _, c := range kept {
		c.Close()
	}
	kept = nil
	waitStats(t, ln, func(s ConnStats) bool { return s.Open == 0 })
	if st, err := metricsFrom("127.0.1.1", addr); err != nil || st != 200 {
		t.Fatal(st, err)
	}
}

// M4: 3000 half-open connections from 300 addresses, each holding 2 KiB of unfinished request. The agent never
// has more than 64 connections open, the panel and the update's health check are answered all the way through,
// and the memory in use does not grow with the flood.
func TestConnFlood(t *testing.T) {
	ln, addr := serveLimited(t, ConnLimits{})
	const conns, senders, workers = 3000, 300, 24

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	var (
		mu      sync.Mutex
		kept    []net.Conn
		next    atomic.Int64
		dialErr atomic.Int64
		wg      sync.WaitGroup
	)
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range kept {
			c.Close()
		}
	}()
	flooding := make(chan struct{})
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
				c, held, err := halfOpen(fmt.Sprintf("127.0.%d.%d", 1+s/250, 1+s%250), addr, 2048)
				if err != nil {
					if dialErr.Add(1) == 1 {
						t.Log("first connection error:", err)
					}
					continue
				}
				if held {
					mu.Lock()
					kept = append(kept, c)
					mu.Unlock()
				}
			}
		}()
	}
	go func() { wg.Wait(); close(flooding) }()

	// meanwhile: the panel polls and the update's health check asks, each over a new connection
	asked := map[string]int{}
	for done := false; !done; {
		select {
		case <-flooding:
			done = true
		default:
		}
		for _, src := range []string{floodPanel, floodLocal} {
			st, err := metricsFrom(src, addr)
			if err != nil || st != 200 {
				t.Fatalf("/metrics from %s during the flood: HTTP %d, %v (stats %+v)", src, st, err, ln.Stats())
			}
			asked[src]++
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := dialErr.Load(); n > conns/10 {
		t.Fatalf("%d of %d connections could not even be opened", n, conns)
	}

	s := ln.Stats()
	if s.Peak > MaxConns || s.Open > MaxConns {
		t.Fatalf("more than %d connections were open: %+v", MaxConns, s)
	}
	if s.Open-s.Trusted > MaxConns-ReservedConns {
		t.Fatalf("strangers hold more than %d connections: %+v", MaxConns-ReservedConns, s)
	}
	if s.Refused < conns-conns/5 {
		t.Fatalf("only %d of %d flood connections were refused: %+v", s.Refused, conns, s)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	grown := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("flood: %d connections from %d senders; refused %d, peak open %d, open now %d; /metrics answered %d times to the panel, %d times to this machine; heap %+d KiB",
		conns, senders, s.Refused, s.Peak, s.Open, asked[floodPanel], asked[floodLocal], grown/1024)
	// While the flood still holds every slot strangers may have, one more stranger finds the door shut and the
	// panel does not. (The held connections are dropped two seconds after they were opened; on a machine too
	// slow to get here in time this part is skipped.)
	full := func() bool { s := ln.Stats(); return s.Open-s.Trusted == MaxConns-ReservedConns }
	if full() {
		c, held, err := halfOpen("127.0.9.9", addr, 16)
		st, perr := metricsFrom(floodPanel, addr)
		if full() {
			if err != nil || held {
				t.Fatal("a new stranger got in while the flood held every slot:", held, err)
			}
			if perr != nil || st != 200 {
				t.Fatal("the panel was not answered while the flood held every slot:", st, perr)
			}
		} else if c != nil {
			c.Close()
		}
	}
	// 3000 connections with 2 KiB each would be at least 6 MiB of request data alone, without the limit
	if grown > 4<<20 {
		t.Fatalf("the heap grew by %d KiB during the flood", grown/1024)
	}
}

// With the opt-in on, a stranger's connection is closed before anything is read; the panel is served.
func TestConnPanelOnlyServer(t *testing.T) {
	ln, addr := serveLimited(t, ConnLimits{PanelOnly: true})
	before := ln.Stats().Refused
	if st, err := metricsFrom("127.0.1.1", addr); err == nil {
		t.Fatal("a stranger was answered: HTTP", st)
	}
	for _, src := range []string{floodPanel, floodLocal} {
		if st, err := metricsFrom(src, addr); err != nil || st != 200 {
			t.Fatal(src, st, err)
		}
	}
	if s := ln.Stats(); s.Refused != before+1 || s.Peak > 2 {
		t.Fatalf("%+v", s)
	}

	// No panel address on record: closed to every other machine, the address that used to be the panel's
	// included; this machine is still served (the update's health check).
	ln, addr = serveLimited(t, ConnLimits{PanelOnly: true, Panel: func() string { return "" }})
	for _, src := range []string{"127.0.1.1", "127.0.2.50", floodPanel} {
		if st, err := metricsFrom(src, addr); err == nil {
			t.Fatalf("no panel on record, but %s was answered: HTTP %d", src, st)
		}
	}
	if st, err := metricsFrom(floodLocal, addr); err != nil || st != 200 {
		t.Fatal("this machine was refused:", st, err)
	}
	if s := ln.Stats(); s.Refused != 3 || s.Peak > 1 {
		t.Fatalf("%+v", s)
	}
}

// The state file decides, through PairedPanel, as the running agent uses it: only_from_panel with a join code
// that expired unused, or one closed for wrong codes, is closed; a new join command opens it to the new panel
// address.
func TestOnlyFromPanelFollowsThePairingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pairing.json")
	now := time.Now().Unix()
	admit := func() (stranger, panel string) {
		l := LimitConns(nil, ConnLimits{Panel: PairedPanel(path), PanelOnly: true}) // a fresh reader: no five-second cache
		key, trusted := l.sender(fakeConn{remote: "100.88.0.7:40000", local: "100.70.0.1:9101"})
		return l.admit("100.88.0.8", false), l.admit(key, trusted)
	}
	write := func(st enroll.State) {
		t.Helper()
		if err := enroll.WriteState(path, st); err != nil {
			t.Fatal(err)
		}
	}
	// never paired: no file
	if s, p := admit(); s != NoPanelRefusal || p != NoPanelRefusal {
		t.Fatalf("no state file: stranger %q, panel %q", s, p)
	}
	for name, st := range map[string]enroll.State{
		"code expired unused":        {Version: 1, Panel: "100.88.0.7", Key2: "k", CreatedAt: now - 1000, ExpiresAt: now - 100},
		"closed for wrong codes":     {Version: 1, Panel: "100.88.0.7", Closed: "too many wrong codes", ExpiresAt: now + 600},
		"paired, address not stored": {Version: 1, Closed: "paired", PairedAt: now},
	} {
		write(st)
		if s, p := admit(); s != NoPanelRefusal || p != NoPanelRefusal {
			t.Fatalf("%s: stranger %q, panel's old address %q", name, s, p)
		}
	}
	// the join command ran: open to the address the code is for, and to nobody else
	write(enroll.State{Version: 1, Panel: "100.88.0.7", Key2: "k", CreatedAt: now, ExpiresAt: now + 600})
	if s, p := admit(); !strings.Contains(s, "only the panel") || p != "" {
		t.Fatalf("code open: stranger %q, panel %q", s, p)
	}
	write(enroll.State{Version: 1, Panel: "100.88.0.7", PairedBy: "100.88.0.7", PairedAt: now, Closed: "paired"})
	if s, p := admit(); !strings.Contains(s, "only the panel") || p != "" {
		t.Fatalf("paired: stranger %q, panel %q", s, p)
	}
}

// A request header must fit in 4 KiB (plus the 4 KiB Go always allows on top) and arrive within two seconds.
func TestServerHeaderLimits(t *testing.T) {
	r := newRig(t, "")
	srv := r.a.Server()
	if srv.ReadHeaderTimeout != 2*time.Second || srv.MaxHeaderBytes != 4096 {
		t.Fatal(srv.ReadHeaderTimeout, srv.MaxHeaderBytes)
	}
	ln, addr := serveLimited(t, ConnLimits{})

	// the panel's kind of request, with a generous 2 KiB of extra headers: answered
	c, err := dialFrom(floodPanel, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "GET /metrics HTTP/1.1\r\nHost: agent\r\nAuthorization: Bearer %s\r\nX-Fill: %s\r\n\r\n", readTok, strings.Repeat("a", 2048))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(resp, err)
	}
	resp.Body.Close()
	c.Close()

	// 9 KiB of header: refused with 431, the connection is closed
	c2, err := dialFrom("127.0.1.1", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c2, "GET /metrics HTTP/1.1\r\nHost: agent\r\nX-Fill: %s\r\n\r\n", strings.Repeat("a", 9<<10))
	resp, err = http.ReadResponse(bufio.NewReader(c2), nil)
	if err != nil || resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatal(resp, err)
	}
	resp.Body.Close()
	c2.Close()

	// a header that never ends: the agent hangs up after two seconds and the slot is free again
	c3, held, err := halfOpen("127.0.1.2", addr, 1024)
	if err != nil || !held {
		t.Fatal(held, err)
	}
	defer c3.Close()
	start := time.Now()
	_ = c3.SetReadDeadline(start.Add(6 * time.Second))
	_, _ = io.Copy(io.Discard, c3) // until the agent closes it (or says 408 and closes)
	if took := time.Since(start); took < time.Second || took > 4*time.Second {
		t.Fatal("an unfinished request was kept for", took)
	}
	waitStats(t, ln, func(s ConnStats) bool { return s.Open == 0 })
}
