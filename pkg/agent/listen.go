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

// ListenAddr is the configured address, or the Tailscale address on DefaultPort. At boot Tailscale may come up
// after the agent, so it waits up to wait for the address to appear.
func ListenAddr(ctx context.Context, cfg *Config, wait time.Duration) (string, error) {
	if cfg.Listen != "" {
		return cfg.Listen, nil
	}
	deadline := time.Now().Add(wait)
	for {
		if ip, ok := TailscaleIP(systemAddrs()); ok {
			return net.JoinHostPort(ip.String(), strconv.Itoa(DefaultPort)), nil
		}
		if time.Now().After(deadline) {
			return "", errors.New("no single Tailscale address (100.64.0.0/10) found on this machine; " +
				"set listen: <address>:9101 in config.yaml (the agent never listens on every network by default)")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// Listen opens addr, retrying while the address does not exist yet (Tailscale still starting).
func Listen(ctx context.Context, addr string, wait time.Duration) (net.Listener, error) {
	deadline := time.Now().Add(wait)
	logged := false
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("cannot listen on %s: %w", addr, err)
		}
		if !logged {
			slog.Info("waiting for the listen address to appear", "listen", addr, "error", err.Error())
			logged = true
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
