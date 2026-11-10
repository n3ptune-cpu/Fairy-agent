package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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

// Listen opens addr, retrying while the address does not exist yet (Tailscale still starting): up to wait, or
// as long as it takes with WaitForever (logged once a minute).
func Listen(ctx context.Context, addr string, wait time.Duration) (net.Listener, error) {
	start := time.Now()
	var lastLog time.Time
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln, nil
		}
		if wait >= 0 && time.Since(start) > wait {
			return nil, fmt.Errorf("cannot listen on %s: %w", addr, err)
		}
		if time.Since(lastLog) >= time.Minute {
			slog.Warn("waiting for the listen address to appear", "listen", addr, "error", err.Error())
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// The caps on open connections (LimitConns). The panel keeps a handful of connections to an agent; a sender
// that opens thousands (each may hold a few KiB of unfinished request) must not be able to fill the agent's
// memory, and must not be able to lock the panel or the update's health check out while it tries.
const (
	MaxConns          = 64 // open connections in all
	MaxConnsPerSender = 8  // per sending address
	// ReservedConns of MaxConns are kept for the paired panel's address and for this machine itself (the
	// update's health check): every other sender together gets at most MaxConns - ReservedConns.
	ReservedConns = 16
)

// ConnLimits configures LimitConns. Zero numbers mean the defaults above.
type ConnLimits struct {
	Total     int
	PerSender int
	Reserved  int
	// Panel returns the paired panel's address ("" while there is none). See PairedPanel.
	Panel func() string
	// PanelOnly refuses every sender but the panel's address and this machine itself. It only applies while
	// Panel returns an address: an agent that has no panel address on record keeps accepting.
	PanelOnly bool
	// Local reports whether a connection comes from this machine itself (default: a loopback address, or the
	// very address it connected to).
	Local func(remote, local netip.Addr) bool
}

// LimitConns wraps ln so that at most o.Total connections are open, at most o.PerSender per sending address
// (IPv6: per /64), with o.Reserved of them kept for the panel's address and this machine. A connection over a
// cap is closed at once, before a byte is read and before the HTTP server learns of it.
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
	o.PerSender = min(o.PerSender, o.Total)
	o.Reserved = min(o.Reserved, o.Total)
	if o.Local == nil {
		o.Local = func(remote, local netip.Addr) bool {
			return remote.IsLoopback() || (local.IsValid() && remote == local)
		}
	}
	return &LimitListener{Listener: ln, o: o, open: map[string]int{}}
}

// LimitListener is a listener with the caps of LimitConns.
type LimitListener struct {
	net.Listener
	o ConnLimits

	mu      sync.Mutex
	open    map[string]int // open connections per sender key
	trusted int            // open connections of the panel and this machine
	others  int            // open connections of everybody else
	peak    int
	refused uint64
	logAt   time.Time
	logged  uint64
}

// ConnStats is a snapshot of a LimitListener.
type ConnStats struct {
	Open    int    // open connections now
	Trusted int    // of them, the panel's and this machine's
	Peak    int    // the most that were ever open at once
	Refused uint64 // connections closed at once because a cap was reached
}

// Stats returns the listener's counters.
func (l *LimitListener) Stats() ConnStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return ConnStats{Open: l.trusted + l.others, Trusted: l.trusted, Peak: l.peak, Refused: l.refused}
}

// Accept returns the next connection that is within the caps; the others are closed here.
func (l *LimitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		key, trusted := l.sender(c)
		if why := l.admit(key, trusted); why != "" {
			l.refuse(c, key, why)
			continue
		}
		return &limitedConn{Conn: c, release: sync.OnceFunc(func() { l.release(key, trusted) })}, nil
	}
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
		return "local", true
	}
	if panel := l.panel(); panel.IsValid() && remote == panel {
		return "panel", true
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

// admit counts a connection in, or says why not.
func (l *LimitListener) admit(key string, trusted bool) (refusal string) {
	panelOnly := l.o.PanelOnly && !trusted && l.panel().IsValid()
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case panelOnly:
		refusal = "only the panel's address is accepted"
	case l.open[key] >= l.o.PerSender:
		refusal = "too many open connections from this sender"
	case l.trusted+l.others >= l.o.Total:
		refusal = "too many open connections"
	case !trusted && l.others >= l.o.Total-l.o.Reserved:
		refusal = "too many open connections (the rest is kept for the panel)"
	}
	if refusal != "" {
		l.refused++
		return refusal
	}
	l.open[key]++
	if trusted {
		l.trusted++
	} else {
		l.others++
	}
	l.peak = max(l.peak, l.trusted+l.others)
	return ""
}

func (l *LimitListener) release(key string, trusted bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open[key]--; l.open[key] <= 0 {
		delete(l.open, key)
	}
	if trusted {
		l.trusted--
	} else {
		l.others--
	}
}

// refuse closes a connection that is over a cap, with a reset so that nothing of it lingers in the kernel, and
// says so in the log at most once a minute.
func (l *LimitListener) refuse(c net.Conn, key, why string) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.SetLinger(0)
	}
	_ = c.Close()
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
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
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
