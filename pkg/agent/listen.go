package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
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
