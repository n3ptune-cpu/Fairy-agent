package agent

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// WOLRequest is the POST /wol body (the panel's `wol:` entry of the sleeping host).
type WOLRequest struct {
	MAC       string  `json:"mac"`
	Broadcast *string `json:"broadcast"`
	Port      *int    `json:"port"`
	Password  *string `json:"password"`
}

// MagicPacket builds a Wake-on-LAN packet: 6 x 0xFF, the MAC 16 times, then the optional SecureOn password
// (6 bytes as aa:bb:cc:dd:ee:ff, or 4 bytes as a.b.c.d).
func MagicPacket(mac, password string) ([]byte, error) {
	if !macRe.MatchString(mac) {
		return nil, errors.New("mac must look like aa:bb:cc:dd:ee:ff")
	}
	hw, _ := hex.DecodeString(strings.NewReplacer(":", "", "-", "").Replace(mac))
	pkt := make([]byte, 0, 108)
	for i := 0; i < 6; i++ {
		pkt = append(pkt, 0xFF)
	}
	for i := 0; i < 16; i++ {
		pkt = append(pkt, hw...)
	}
	switch {
	case password == "":
	case macRe.MatchString(password):
		pw, _ := hex.DecodeString(strings.NewReplacer(":", "", "-", "").Replace(password))
		pkt = append(pkt, pw...)
	default:
		ip := net.ParseIP(password).To4()
		if ip == nil {
			return nil, errors.New("password must be 6 bytes (aa:bb:cc:dd:ee:ff) or 4 bytes (a.b.c.d)")
		}
		pkt = append(pkt, ip...)
	}
	return pkt, nil
}

// WOL is the Wake-on-LAN relay. Send is replaceable for tests.
type WOL struct {
	allowed map[string]bool
	Send    func(addr string, pkt []byte) error
}

// NewWOL returns the relay; allowed (MAC addresses) empty = any.
func NewWOL(allowed []string) *WOL {
	w := &WOL{allowed: map[string]bool{}, Send: sendUDP}
	for _, m := range allowed {
		w.allowed[normMAC(m)] = true
	}
	return w
}

func normMAC(m string) string { return strings.ToLower(strings.ReplaceAll(m, "-", ":")) }

func sendUDP(addr string, pkt []byte) error {
	c, err := net.Dial("udp4", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(pkt)
	return err
}

// broadcastOK accepts the limited broadcast address and private (LAN) IPv4 addresses only, so the relay cannot
// be used to send packets to the internet.
func broadcastOK(ip net.IP) bool {
	return ip.Equal(net.IPv4bcast) || ip.IsPrivate()
}

// Handle sends one magic packet and returns the HTTP status and body.
func (w *WOL) Handle(req WOLRequest) (int, map[string]any) {
	mac := normMAC(strings.TrimSpace(req.MAC))
	if len(w.allowed) > 0 && !w.allowed[mac] {
		return 400, map[string]any{"error": "this MAC address is not in wol.allowed_macs on the agent"}
	}
	pw := ""
	if req.Password != nil {
		pw = *req.Password
	}
	pkt, err := MagicPacket(mac, pw)
	if err != nil {
		return 400, map[string]any{"error": err.Error()}
	}
	port := 9
	if req.Port != nil {
		port = *req.Port
	}
	if port != 7 && port != 9 {
		return 400, map[string]any{"error": "port must be 7 or 9"}
	}
	bc := "255.255.255.255"
	if req.Broadcast != nil && *req.Broadcast != "" {
		bc = *req.Broadcast
	}
	ip := net.ParseIP(bc).To4()
	if ip == nil || !broadcastOK(ip) {
		return 400, map[string]any{"error": "broadcast must be 255.255.255.255 or a private IPv4 address"}
	}
	if err := w.Send(fmt.Sprintf("%s:%d", ip, port), pkt); err != nil {
		slog.Error("wol: send failed", "mac", mac, "error", err.Error())
		return 500, map[string]any{"error": "could not send the magic packet"}
	}
	slog.Info("wol: magic packet sent", "mac", mac, "broadcast", ip.String(), "port", port)
	var bcOut any
	if req.Broadcast != nil {
		bcOut = *req.Broadcast
	}
	return 200, map[string]any{"sent": true, "mac": mac, "broadcast": bcOut, "port": port, "bytes": len(pkt)}
}
