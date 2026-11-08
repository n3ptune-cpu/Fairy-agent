// Package ipmi talks to the board's BMC with raw IPMI commands: the sensor data repository (temperatures, fans,
// voltages) and Supermicro's OEM fan commands. The transport is either the ipmitool program (Linux in-band
// through /dev/ipmi0, or IPMI-over-LAN on any OS) or, on Windows, the Microsoft_IPMI WMI class of Windows' own
// built-in IPMI driver. fairy-agent never installs or loads a driver for this.
package ipmi

import (
	"context"
	"errors"
	"fmt"
)

// Transport sends one raw IPMI request to the BMC and returns the response data after the completion code.
// A non-zero completion code is returned as *CompletionError.
type Transport interface {
	Raw(ctx context.Context, netfn, cmd byte, data []byte) ([]byte, error)
	Close()
}

// CompletionError is a BMC answer with a non-zero completion code.
type CompletionError struct{ Code byte }

func (e *CompletionError) Error() string {
	if m, ok := completionText[e.Code]; ok {
		return fmt.Sprintf("BMC completion code 0x%02X (%s)", e.Code, m)
	}
	return fmt.Sprintf("BMC completion code 0x%02X", e.Code)
}

var completionText = map[byte]string{0xC0: "node busy", 0xC1: "invalid command", 0xC3: "timeout",
	0xC7: "request data length invalid", 0xC9: "parameter out of range", 0xCA: "cannot return requested length",
	0xCB: "not present", 0xCC: "invalid data field", 0xCE: "cannot respond", 0xD4: "insufficient privilege",
	0xD5: "not supported in present state", 0xFF: "unspecified error"}

// IsCompletion reports whether err is a BMC completion code equal to code.
func IsCompletion(err error, code byte) bool {
	var ce *CompletionError
	return errors.As(err, &ce) && ce.Code == code
}

// Network functions and commands used here (IPMI v2.0 and Supermicro OEM).
const (
	NetFnSensor  = 0x04
	NetFnStorage = 0x0A
	NetFnOEM     = 0x30

	CmdGetSensorReading = 0x2D
	CmdReserveSDR       = 0x22
	CmdGetSDR           = 0x23
	CmdSMCFanMode       = 0x45
	CmdSMCFanDuty       = 0x70
)

// Fan modes of Supermicro X9-X12 boards (raw 0x30 0x45).
var fanModes = map[byte]string{0: "standard", 1: "full", 2: "optimal", 3: "pue", 4: "heavyio"}

// ModeName returns the panel's name for a Supermicro fan mode byte.
func ModeName(b byte) string {
	if n, ok := fanModes[b]; ok {
		return n
	}
	return fmt.Sprintf("unknown(%d)", b)
}

// ModeByte returns the Supermicro byte for a mode name (standard, full, optimal, heavyio).
func ModeByte(name string) (byte, bool) {
	for b, n := range fanModes {
		if n == name && n != "pue" {
			return b, true
		}
	}
	return 0, false
}

// GetFanMode reads the Supermicro fan mode.
func GetFanMode(ctx context.Context, t Transport) (string, error) {
	r, err := t.Raw(ctx, NetFnOEM, CmdSMCFanMode, []byte{0x00})
	if err != nil {
		return "", err
	}
	if len(r) < 1 {
		return "", errors.New("short fan mode response")
	}
	return ModeName(r[0]), nil
}

// SetFanMode sets the Supermicro fan mode (the BMC resets manual duties when the mode changes).
func SetFanMode(ctx context.Context, t Transport, mode string) error {
	b, ok := ModeByte(mode)
	if !ok {
		return fmt.Errorf("unknown fan mode %q", mode)
	}
	_, err := t.Raw(ctx, NetFnOEM, CmdSMCFanMode, []byte{0x01, b})
	return err
}

// GetDuty reads a zone's duty cycle (percent). Zone 0 = CPU/system fans (FAN1-n), 1 = peripheral (FANA-).
func GetDuty(ctx context.Context, t Transport, zone byte) (int, error) {
	r, err := t.Raw(ctx, NetFnOEM, CmdSMCFanDuty, []byte{0x66, 0x00, zone})
	if err != nil {
		return 0, err
	}
	if len(r) < 1 {
		return 0, errors.New("short duty response")
	}
	return int(r[0]), nil
}

// SetDuty sets a zone's duty cycle (only honoured in "full" mode).
func SetDuty(ctx context.Context, t Transport, zone byte, percent int) error {
	if percent < 0 || percent > 100 {
		return fmt.Errorf("duty %d out of range", percent)
	}
	_, err := t.Raw(ctx, NetFnOEM, CmdSMCFanDuty, []byte{0x66, 0x01, zone, byte(percent)})
	return err
}
