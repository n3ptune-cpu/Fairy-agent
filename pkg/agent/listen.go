package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

// tailnet is the CGNAT range Tailscale gives out addresses from.
var tailnet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// IfaceAddr is one address of one network interface.
type IfaceAddr struct {
	Iface string
	IP    net.IP
}

// TailscaleIP picks this machine's Tailscale IPv4 address: the only 100.64.0.0/10 address, or the only one on
// an interface named like "tailscale". ok is false when there is none or it is ambiguous.
func TailscaleIP(addrs []IfaceAddr) (net.IP, bool) {
	var all, named []net.IP
	for _, a := range addrs {
		ip := a.IP.To4()
		if ip == nil || !tailnet.Contains(ip) {
			continue
		}
		all = append(all, ip)
		if strings.Contains(strings.ToLower(a.Iface), "tailscale") {
			named = append(named, ip)
		}
	}
	switch {
	case len(named) == 1:
		return named[0], true
	case len(all) == 1:
		return all[0], true
	}
	return nil, false
}

func systemAddrs() []IfaceAddr {
	ifs, _ := net.Interfaces()
	var out []IfaceAddr
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		as, _ := i.Addrs()
		for _, a := range as {
			if n, ok := a.(*net.IPNet); ok {
				out = append(out, IfaceAddr{Iface: i.Name, IP: n.IP})
			}
		}
	}
	return out
}

// WaitForever makes ListenAddr and Listen wait until the address exists (or ctx ends).
const WaitForever time.Duration = -1

// ListenAddr is the configured address, or the Tailscale address on DefaultPort. At boot Tailscale may come up
// after the agent (on Windows without "Run unattended" only after someone signs in), so it waits up to wait for
// the address to appear (WaitForever: as long as it takes, saying so in the log once a minute). Several
// Tailscale-looking addresses are an error at once: waiting would not help.
func ListenAddr(ctx context.Context, cfg *Config, wait time.Duration) (string, error) {
	if cfg.Listen != "" {
		return cfg.Listen, nil
	}
	start := time.Now()
	var lastLog time.Time
	for {
		addrs := systemAddrs()
		if ip, ok := TailscaleIP(addrs); ok {
			if !lastLog.IsZero() {
				slog.Info("Tailscale address found", "address", ip.String(), "after", time.Since(start).Round(time.Second).String())
			}
			return net.JoinHostPort(ip.String(), strconv.Itoa(DefaultPort)), nil
		}
		if n := countTailnet(addrs); n > 1 {
			return "", fmt.Errorf("%d Tailscale-looking addresses (100.64.0.0/10) on this machine; set listen: <address>:9101 in config.yaml", n)
		}
		if wait >= 0 && time.Since(start) > wait {
			return "", errors.New("no Tailscale address (100.64.0.0/10) found on this machine; " +
				"set listen: <address>:9101 in config.yaml (the agent never listens on every network by default)")
		}
		if wait < 0 && time.Since(lastLog) >= time.Minute {
			slog.Warn("waiting for this machine's Tailscale address (Tailscale not up yet; on Windows turn on \"Run unattended\" in Tailscale)",
				"waited", time.Since(start).Round(time.Second).String())
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func countTailnet(addrs []IfaceAddr) int {
	n := 0
	for _, a := range addrs {
		if ip := a.IP.To4(); ip != nil && tailnet.Contains(ip) {
			n++
		}
	}
	return n
}

// listenRetry is the pause between two tries of Listen; addrInUseTries is how many tries in a row may find the
// port taken by another program before Listen gives up.
var listenRetry = 3 * time.Second

const addrInUseTries = 5

// ErrAddrInUse is returned by Listen when another program holds the agent's port.
var ErrAddrInUse = errors.New("another program is listening on the agent's port")

// Listen opens addr, retrying while the address does not exist yet (Tailscale still starting): up to wait, or
// as long as it takes with WaitForever (logged once a minute).
//
// A port that another program holds is a different matter: waiting for it kept the service "running" with
// nothing listening, for as long as that program stayed, and an update's health check then talked to that
// program. After addrInUseTries tries in a row Listen gives up with ErrAddrInUse, the agent ends, and the
// service manager shows the failure and starts it again later. On Windows the port is opened for exclusive
// use, so that no other program can open the same address next to the agent.
func Listen(ctx context.Context, addr string, wait time.Duration) (net.Listener, error) {
	start := time.Now()
	var lastLog time.Time
	inUse := 0
	for {
		ln, err := listenTCP(ctx, addr)
		if err == nil {
			return ln, nil
		}
		if addrInUse(err) {
			if inUse++; inUse >= addrInUseTries {
				return nil, fmt.Errorf("cannot listen on %s: %w (%v); tried %d times", addr, ErrAddrInUse, err, inUse)
			}
		} else {
			inUse = 0
		}
		if wait >= 0 && time.Since(start) > wait {
			return nil, fmt.Errorf("cannot listen on %s: %w", addr, err)
		}
		if time.Since(lastLog) >= time.Minute {
			if inUse > 0 {
				slog.Warn("the agent's port is taken by another program; trying a few more times", "listen", addr, "error", err.Error())
			} else {
				slog.Warn("waiting for the listen address to appear", "listen", addr, "error", err.Error())
			}
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(listenRetry):
		}
	}
}

// The caps on open connections (LimitConns). A sender that opens thousands (each may hold a few KiB of
// unfinished request) must not be able to fill the agent's memory, and must not be able to lock the panel or
// the update's health check out while it tries.
const (
	MaxConns          = 64 // open connections in all
	MaxConnsPerSender = 8  // per sending address
	// ReservedConns of MaxConns are kept for the paired panel's address and for this machine itself (the
	// update's health check): every other sender together gets at most MaxConns - ReservedConns.
	ReservedConns = 16
	// MaxConnsPanel is the cap for the paired panel's address. The panel has no cap of its own: it opens one
	// connection for every request in flight and keeps two idle ones (pkg/devices, lanTransport; the v0.5.2
	// panel uses the same code). What it can have in flight to one agent at once: /metrics once a second with
	// a 4.5 s limit (5 when the agent is slow), control requests (the agent accepts control_rate_per_min a
	// minute, 6 by default, the panel waits 12 s for each), process lists (maxProcessWaiters, 16), fan status
	// (maxFanStatus, 4) and one /pair: 32. More than that is not refused but waits (MaxWaitingConns).
	MaxConnsPanel = 32
	// MaxWaitingConns connections of the panel's address that are over a cap are kept waiting, unread, for a
	// free slot (at most ConnWait) instead of being reset: they cost a socket each and nothing else. With the
	// 32 slots that takes well over a hundred requests of the panel at the same moment (tested with 96). This machine's own connections
	// wait in the same way, a quarter as many (the update's health check is one connection a second). Any
	// other sender's connection over a cap is closed at once.
	MaxWaitingConns = 128
	// ConnWait is how long such a connection waits: less than the panel's limit for a poll (4 s).
	ConnWait = 3 * time.Second
	// LocalReservedConns of ReservedConns are for this machine alone: whatever the panel and everybody else
	// have open, the update's health check finds a slot.
	LocalReservedConns = 4
)

// ConnLimits configures LimitConns. Zero numbers mean the defaults above.
type ConnLimits struct {
	Total     int
	PerSender int
	Reserved  int
	// LocalReserved of Reserved are kept for this machine alone (LocalReservedConns; negative: none).
	LocalReserved int
	PerPanel      int           // MaxConnsPanel
	Waiting       int           // MaxWaitingConns (this machine: a quarter of it); negative: nobody waits
	Wait          time.Duration // ConnWait
	// Panel returns the paired panel's address ("" while there is none). See PairedPanel.
	Panel func() string
	// PanelOnly refuses every sender but the panel's address and this machine itself. While Panel returns no
	// address (never paired through Add host, or a join code that expired or was closed) it refuses every
	// sender but this machine: the setting says "nobody but the panel", so not knowing the panel must not
	// mean "everybody".
	PanelOnly bool
	// Local reports whether a connection comes from this machine itself (default: a loopback address, or the
	// very address it connected to).
	Local func(remote, local netip.Addr) bool
}

// NoPanelRefusal is why a connection is refused while only_from_panel is on and no panel address is on record.
const NoPanelRefusal = "only_from_panel is on and this agent has no panel address on record: only this machine itself is " +
	"accepted (run the panel's Add host or Re-pair command on this machine, or remove only_from_panel from config.yaml)"

// The keys the panel's and this machine's connections are counted under.
const (
	panelKey = "panel"
	localKey = "local"
)

// LimitConns wraps ln so that at most o.Total connections are open, at most o.PerSender per sending address
// (IPv6: per /64; o.PerPanel for the paired panel's address), with o.Reserved of them kept for the panel's
// address and this machine. A connection over a cap is closed at once, before a byte is read and before the
// HTTP server learns of it; one from the panel's address or from this machine waits for a slot first (o.Waiting
// of them, for o.Wait), unread.
func LimitConns(ln net.Listener, o ConnLimits) *LimitListener {
	if o.Total <= 0 {
		o.Total = MaxConns
	}
	if o.PerSender <= 0 {
		o.PerSender = MaxConnsPerSender
	}
	if o.Reserved <= 0 {
		o.Reserved = ReservedConns
	}
	if o.PerPanel <= 0 {
		o.PerPanel = MaxConnsPanel
	}
	if o.Waiting == 0 {
		o.Waiting = MaxWaitingConns
	}
	if o.Wait <= 0 {
		o.Wait = ConnWait
	}
	o.PerSender = min(o.PerSender, o.Total)
	o.PerPanel = min(max(o.PerPanel, o.PerSender), o.Total)
	o.Reserved = min(o.Reserved, o.Total)
	if o.LocalReserved == 0 {
		o.LocalReserved = LocalReservedConns
	}
	o.LocalReserved = min(max(o.LocalReserved, 0), o.Reserved)
	if o.Local == nil {
		o.Local = func(remote, local netip.Addr) bool {
			return remote.IsLoopback() || (local.IsValid() && remote == local)
		}
	}
	return &LimitListener{Listener: ln, o: o, open: map[string]int{}, conns: map[*limitedConn]struct{}{}, ready: make(chan net.Conn, o.Total),
		errs: make(chan error), done: make(chan struct{})}
}

// LimitListener is a listener with the caps of LimitConns.
type LimitListener struct {
	net.Listener
	o ConnLimits

	start sync.Once     // the goroutine that takes connections from Listener
	ready chan net.Conn // connections within the caps, for Accept
	errs  chan error    // Listener's own Accept errors, for Accept
	done  chan struct{} // closed by Close

	mu      sync.Mutex
	closed  bool
	open    map[string]int            // open connections per sender key
	conns   map[*limitedConn]struct{} // the open connections themselves
	trusted int                       // open connections of the panel and this machine
	others  int                       // open connections of everybody else
	waiting []*waitingConn            // the panel's and this machine's connections that wait for a slot, oldest first
	peak    int
	refused uint64
	waited  uint64
	evicted uint64
	logAt   time.Time
	logged  uint64
}

// waitingConn is a connection of the panel or of this machine that found a cap reached.
type waitingConn struct {
	c     *limitedConn
	why   string
	timer *time.Timer
}

// ConnStats is a snapshot of a LimitListener.
type ConnStats struct {
	Open    int    // open connections now
	Trusted int    // of them, the panel's and this machine's
	Waiting int    // connections of the panel and this machine that wait for a slot now
	Peak    int    // the most that were ever open at once
	Refused uint64 // connections closed because a cap was reached
	Waited  uint64 // connections that got their slot after waiting for it
	Evicted uint64 // idle connections closed to make room for a new one of the same sender
}

// Stats returns the listener's counters.
func (l *LimitListener) Stats() ConnStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return ConnStats{Open: l.trusted + l.others, Trusted: l.trusted, Waiting: len(l.waiting), Peak: l.peak,
		Refused: l.refused, Waited: l.waited, Evicted: l.evicted}
}

// Accept returns the next connection that is within the caps. The others are closed, or kept waiting, by the
// goroutine that takes them from the wrapped listener, so that a waiting connection gets its slot the moment
// one is free and not only when the next connection arrives.
func (l *LimitListener) Accept() (net.Conn, error) {
	l.start.Do(func() { go l.take() })
	select {
	case <-l.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case c := <-l.ready:
		return c, nil
	case err := <-l.errs:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// take hands every connection of the wrapped listener to arrive, and its errors to Accept (whose caller, the
// HTTP server, waits a moment after a passing error; this loop waits with it).
func (l *LimitListener) take() {
	for {
		c, err := l.Listener.Accept()
		if err == nil {
			l.arrive(c)
			continue
		}
		select {
		case l.errs <- err:
		case <-l.done:
			return
		}
		if errors.Is(err, net.ErrClosed) {
			return
		}
	}
}

// Close closes the wrapped listener and every connection that waits for a slot or for Accept.
func (l *LimitListener) Close() error {
	err := l.Listener.Close()
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return err
	}
	l.closed = true
	close(l.done)
	waiting := l.waiting
	l.waiting = nil
	l.mu.Unlock()
	for _, w := range waiting {
		w.timer.Stop()
		reset(w.c.Conn)
	}
	for {
		select {
		case c := <-l.ready: // counted in, never handed out
			_ = c.Close()
		default:
			return err
		}
	}
}

// arrive counts a new connection in and passes it to Accept, keeps it waiting, or closes it.
func (l *LimitListener) arrive(c net.Conn) {
	key, trusted := l.sender(c)
	lc := &limitedConn{Conn: c, l: l, sender: key, trusted: trusted}
	why := l.panelOnly(trusted)
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = c.Close()
		return
	}
	if why == "" {
		why = l.check(key, trusted)
	}
	var idle *limitedConn
	if why != "" {
		// An idle connection is one whose request was answered and that was kept open for a next one. Closing
		// it is always allowed, and a sender whose slots are all taken by such connections is not locked out:
		// the oldest of them makes room.
		if idle = l.idleConn(key, why); idle != nil {
			l.uncount(idle)
			l.evicted++
			why = l.check(key, trusted)
		}
	}
	switch {
	case why == "":
		l.countConn(lc)
		l.ready <- lc // never blocks: at most Total connections are counted in
		l.mu.Unlock()
		if idle != nil {
			_ = idle.Conn.Close()
		}
		return
	case trusted && l.waitingOf(key) < l.room(key):
		// The panel's own next connection, or the update's health check: a reset would be a failed poll, a
		// failed "cancel shutdown", a failed update. It waits, unread, until one of its sender's requests is
		// done.
		w := &waitingConn{c: lc, why: why}
		w.timer = time.AfterFunc(l.o.Wait, func() { l.giveUp(w) })
		l.waiting = append(l.waiting, w)
		l.mu.Unlock()
		if idle != nil {
			_ = idle.Conn.Close()
		}
		return
	}
	l.refused++
	l.mu.Unlock()
	if idle != nil {
		_ = idle.Conn.Close()
	}
	l.refuse(c, key, why)
}

// idleConn picks the connection that is closed to make room for a new one of sender key that check refused
// with why: this machine's own oldest idle connection, when this machine has all of its slots in use. (Eight
// idle connections of a local user used to keep the update's health check out for as long as they were held:
// review N2.) nil: there is none. Caller holds l.mu.
func (l *LimitListener) idleConn(key, why string) *limitedConn {
	if key != localKey || why != tooManyOfSender {
		return nil
	}
	var oldest *limitedConn
	for c := range l.conns {
		if c.sender != key || c.idleSince.IsZero() {
			continue
		}
		if oldest == nil || c.idleSince.Before(oldest.idleSince) {
			oldest = c
		}
	}
	return oldest
}

// room is how many connections of a trusted sender may wait at once.
func (l *LimitListener) room(key string) int {
	if key == localKey {
		return l.o.Waiting / 4
	}
	return l.o.Waiting
}

// waitingOf counts the waiting connections of one sender. Caller holds l.mu.
func (l *LimitListener) waitingOf(key string) (n int) {
	for _, w := range l.waiting {
		if w.c.sender == key {
			n++
		}
	}
	return n
}

// giveUp closes a connection that waited o.Wait for a slot in vain.
func (l *LimitListener) giveUp(w *waitingConn) {
	l.mu.Lock()
	i := slices.Index(l.waiting, w)
	if i < 0 { // it got its slot, or the listener was closed
		l.mu.Unlock()
		return
	}
	l.waiting = slices.Delete(l.waiting, i, i+1)
	l.refused++
	l.mu.Unlock()
	l.refuse(w.c.Conn, w.c.sender, w.why+" (it waited "+l.o.Wait.String()+" for a free one)")
}

func addrOf(a net.Addr) netip.Addr {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort().Addr().Unmap().WithZone("")
	}
	if a != nil {
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			return ap.Addr().Unmap().WithZone("")
		}
	}
	return netip.Addr{}
}

// sender returns the key a connection is counted under and whether it is the panel or this machine.
func (l *LimitListener) sender(c net.Conn) (key string, trusted bool) {
	remote := addrOf(c.RemoteAddr())
	if !remote.IsValid() {
		return "unknown", false
	}
	if l.o.Local(remote, addrOf(c.LocalAddr())) {
		return localKey, true
	}
	if panel := l.panel(); panel.IsValid() && remote == panel {
		return panelKey, true
	}
	if remote.Is6() { // one machine owns a whole /64
		if p, err := remote.Prefix(64); err == nil {
			return p.String(), false
		}
	}
	return remote.String(), false
}

func (l *LimitListener) panel() netip.Addr {
	if l.o.Panel == nil {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(strings.TrimSpace(l.o.Panel()))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

// panelOnly is why only_from_panel refuses a sender ("" when it does not, or when the setting is off).
func (l *LimitListener) panelOnly(trusted bool) string {
	switch {
	case !l.o.PanelOnly || trusted:
		return ""
	case !l.panel().IsValid():
		return NoPanelRefusal
	}
	return "only the panel's address is accepted"
}

// capOf is how many connections one sender key may have open.
func (l *LimitListener) capOf(key string, trusted bool) int {
	if trusted && key == panelKey {
		return l.o.PerPanel
	}
	return l.o.PerSender
}

const tooManyOfSender = "too many open connections from this sender"

// check says which cap a new connection of this sender would break ("" when none). Caller holds l.mu.
func (l *LimitListener) check(key string, trusted bool) string {
	switch {
	case l.open[key] >= l.capOf(key, trusted):
		return tooManyOfSender
	case l.trusted+l.others >= l.o.Total:
		return "too many open connections"
	case !trusted && l.others >= l.o.Total-l.o.Reserved:
		return "too many open connections (the rest is kept for the panel)"
	case key != localKey && l.trusted+l.others-l.open[localKey] >= l.o.Total-l.o.LocalReserved:
		return "too many open connections (the rest is kept for this machine)"
	}
	return ""
}

// count counts a connection in. Caller holds l.mu.
func (l *LimitListener) count(key string, trusted bool) {
	l.open[key]++
	if trusted {
		l.trusted++
	} else {
		l.others++
	}
	l.peak = max(l.peak, l.trusted+l.others)
}

// countConn counts a connection in and keeps it for idleConn. Caller holds l.mu.
func (l *LimitListener) countConn(c *limitedConn) {
	l.count(c.sender, c.trusted)
	l.conns[c] = struct{}{}
}

// uncount takes a connection out of the counts, once. Caller holds l.mu.
func (l *LimitListener) uncount(c *limitedConn) bool {
	if _, ok := l.conns[c]; !ok {
		return false
	}
	delete(l.conns, c)
	l.forget(c.sender, c.trusted)
	return true
}

// admit counts a connection in, or says why not (the rules alone: nobody waits here).
func (l *LimitListener) admit(key string, trusted bool) (refusal string) {
	refusal = l.panelOnly(trusted)
	l.mu.Lock()
	defer l.mu.Unlock()
	if refusal == "" {
		refusal = l.check(key, trusted)
	}
	if refusal != "" {
		l.refused++
		return refusal
	}
	l.count(key, trusted)
	return ""
}

// forget is the opposite of count. Caller holds l.mu.
func (l *LimitListener) forget(key string, trusted bool) {
	if l.open[key]--; l.open[key] <= 0 {
		delete(l.open, key)
	}
	if trusted {
		l.trusted--
	} else {
		l.others--
	}
}

// release gives a slot back and hands it to the connections that wait for one, oldest first.
func (l *LimitListener) release(key string, trusted bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.forget(key, trusted)
	l.serveWaiting()
}

// connClosed is release for a connection that was closed (it is not counted any more if it was closed to make
// room).
func (l *LimitListener) connClosed(c *limitedConn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.uncount(c) {
		l.serveWaiting()
	}
}

// serveWaiting gives free slots to the connections that wait, oldest first. Caller holds l.mu.
func (l *LimitListener) serveWaiting() {
	if l.closed || len(l.waiting) == 0 {
		return
	}
	still := l.waiting[:0]
	for _, w := range l.waiting {
		if l.check(w.c.sender, true) != "" {
			still = append(still, w)
			continue
		}
		w.timer.Stop()
		l.countConn(w.c)
		l.waited++
		l.ready <- w.c
	}
	clear(l.waiting[len(still):])
	l.waiting = still
}

// reset closes a connection so that nothing of it lingers in the kernel.
func reset(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.SetLinger(0)
	}
	_ = c.Close()
}

// refuse closes a connection that is over a cap, with a reset, and says so in the log at most once a minute.
func (l *LimitListener) refuse(c net.Conn, key, why string) {
	reset(c)
	l.mu.Lock()
	now := time.Now()
	if !l.logAt.IsZero() && now.Sub(l.logAt) < time.Minute {
		l.mu.Unlock()
		return
	}
	n := l.refused - l.logged
	l.logAt, l.logged = now, l.refused
	open := l.trusted + l.others
	l.mu.Unlock()
	slog.Warn("connections refused", "reason", why, "last_sender", key, "refused_since_last_report", n, "open", open)
}

// limitedConn gives its slot back when it is closed (once).
type limitedConn struct {
	net.Conn
	l       *LimitListener
	sender  string // the key it is counted under
	trusted bool
	// idleSince is when its last request was answered, zero while a request is being read or served (l.mu).
	idleSince time.Time
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.l.connClosed(c)
	return err
}

// ConnState is told by the HTTP server (Agent.Server) what the connection is doing.
func (c *limitedConn) ConnState(s http.ConnState) {
	c.l.mu.Lock()
	if s == http.StateIdle {
		c.idleSince = time.Now()
	} else {
		c.idleSince = time.Time{}
	}
	c.l.mu.Unlock()
}

// CloseWrite lets the HTTP server half-close the connection as it does on a plain TCP connection.
func (c *limitedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// PairedPanel returns a function that reports the panel's address from the pairing state file (path): the
// address that paired, or, while a join code is open, the address the code is open to. It is "" when the agent
// was never paired through Add host (tokens set up by hand). The file is read at most every five seconds.
func PairedPanel(path string) func() string {
	var (
		mu   sync.Mutex
		at   time.Time
		addr string
	)
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now()
		if !at.IsZero() && now.Sub(at) < 5*time.Second {
			return addr
		}
		at, addr = now, ""
		if st, err := enroll.ReadState(path); err == nil {
			switch {
			case st.Closed == "paired":
				addr = st.PairedBy
			case st.Active(now):
				addr = st.Panel
			}
		}
		return addr
	}
}
