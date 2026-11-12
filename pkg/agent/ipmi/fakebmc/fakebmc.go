// Package fakebmc is an in-memory Supermicro-like BMC for tests: an SDR repository, sensor readings and the
// OEM fan mode / duty commands, behind the ipmi.Transport interface.
package fakebmc

import (
	"context"
	"fmt"
	"sync"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
)

// BMC is the fake. Values are the raw readings Get Sensor Reading returns (0 = sensor reports "unavailable").
type BMC struct {
	mu      sync.Mutex
	Records [][]byte
	Values  map[byte]byte
	Mode    byte
	Duty    [2]byte
	Calls   int
	Fail    error // every request fails with this when set
	// Refuse maps a fan mode byte to the completion code the BMC answers when asked to set it (e.g. 2: 0xCC for
	// a board without "optimal", like the Enginetech EG320W-G20). Set it with RefuseMode.
	Refuse map[byte]byte
	// refuseDuty, when not 0, is the completion code the BMC answers when asked to set a duty (RefuseDuty).
	refuseDuty byte
	resv       byte
}

// FullSensor builds a Full Sensor Record (SDR type 0x01). analog: 0 unsigned, 2 two's complement.
func FullSensor(id uint16, num, typ byte, name string, m, b, rExp, bExp int, analog, upperCrit byte) []byte {
	body := make([]byte, 48-5)
	rec := append([]byte{byte(id), byte(id >> 8), 0x51, 0x01, 0}, body...)
	rec[5], rec[6], rec[7] = 0x20, 0x00, num
	rec[12] = typ
	rec[13] = 0x01 // threshold
	rec[18] = 0x10 // upper critical readable
	rec[20] = analog << 6
	rec[23] = 0 // linear
	rec[24], rec[25] = byte(m), byte((m>>8)&0x03)<<6
	rec[26], rec[27] = byte(b), byte((b>>8)&0x03)<<6
	rec[29] = byte(rExp&0x0F)<<4 | byte(bExp&0x0F)
	rec[37] = upperCrit
	rec[47] = 0xC0 | byte(len(name))
	rec = append(rec, []byte(name)...)
	rec[4] = byte(len(rec) - 5)
	return rec
}

// X11SCAF returns a fake with the sensors of a Supermicro X11SCA-F (CPU 45 °C, two fans, 12 V), mode optimal.
func X11SCAF() *BMC {
	return &BMC{Mode: 2, Duty: [2]byte{100, 100}, Records: [][]byte{
		FullSensor(0, 0x01, ipmi.TypeTemperature, "CPU Temp", 1, 0, 0, 0, 2, 100),
		FullSensor(1, 0x0B, ipmi.TypeTemperature, "PCH Temp", 1, 0, 0, 0, 2, 90),
		FullSensor(2, 0x41, ipmi.TypeFan, "FAN1", 100, 0, 0, 0, 0, 0),
		FullSensor(3, 0x42, ipmi.TypeFan, "FAN2", 100, 0, 0, 0, 0, 0), // empty header: reads unavailable
		FullSensor(4, 0x44, ipmi.TypeFan, "FANA", 100, 0, 0, 0, 0, 0),
		FullSensor(5, 0x30, ipmi.TypeVoltage, "12V", 6, 0, -2, 0, 0, 0),
		{6, 0, 0x51, 0x12, 3, 0, 0, 0}, // a management controller record: ignored
	}, Values: map[byte]byte{0x01: 45, 0x0B: 48, 0x41: 14, 0x44: 9, 0x30: 202}}
}

// SetRaw changes a sensor's raw reading.
func (b *BMC) SetRaw(num, v byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Values[num] = v
}

// RefuseDuty makes the BMC answer completion code cc when asked to set a fan duty (cc 0: accept it again).
// Reading a duty and the fan mode go on working.
func (b *BMC) RefuseDuty(cc byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refuseDuty = cc
}

// RefuseMode makes the BMC answer completion code cc when asked to set fan mode mode (cc 0: accept it again).
func (b *BMC) RefuseMode(mode, cc byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Refuse == nil {
		b.Refuse = map[byte]byte{}
	}
	if cc == 0 {
		delete(b.Refuse, mode)
		return
	}
	b.Refuse[mode] = cc
}

// State returns the fan mode byte and the duties.
func (b *BMC) State() (byte, [2]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Mode, b.Duty
}

// Close does nothing.
func (b *BMC) Close() {}

// Raw answers one request like a BMC.
func (b *BMC) Raw(_ context.Context, netfn, cmd byte, data []byte) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Calls++
	if b.Fail != nil {
		return nil, b.Fail
	}
	cc := func(c byte) error { return &ipmi.CompletionError{Code: c} }
	switch {
	case netfn == ipmi.NetFnStorage && cmd == ipmi.CmdReserveSDR:
		b.resv++
		return []byte{b.resv, 0}, nil
	case netfn == ipmi.NetFnStorage && cmd == ipmi.CmdGetSDR:
		if len(data) != 6 || data[0] != b.resv {
			return nil, cc(0xC5)
		}
		id := int(data[2]) | int(data[3])<<8
		if id >= len(b.Records) {
			return nil, cc(0xCB)
		}
		rec := b.Records[id]
		off, n := int(data[4]), int(data[5])
		if off+n > len(rec) {
			return nil, cc(0xCA)
		}
		next := id + 1
		if next >= len(b.Records) {
			next = 0xFFFF
		}
		return append([]byte{byte(next), byte(next >> 8)}, rec[off:off+n]...), nil
	case netfn == ipmi.NetFnSensor && cmd == ipmi.CmdGetSensorReading:
		v, ok := b.Values[data[0]]
		if !ok {
			return []byte{0, 0x60}, nil // scanning on, reading unavailable
		}
		return []byte{v, 0xC0}, nil
	case netfn == ipmi.NetFnOEM && cmd == ipmi.CmdSMCFanMode:
		if data[0] == 0 {
			return []byte{b.Mode}, nil
		}
		if c, ok := b.Refuse[data[1]]; ok {
			return nil, cc(c)
		}
		b.Mode = data[1]
		if b.Mode == 1 { // full speed resets duties to 100
			b.Duty = [2]byte{100, 100}
		}
		return nil, nil
	case netfn == ipmi.NetFnOEM && cmd == ipmi.CmdSMCFanDuty && data[0] == 0x66:
		z := data[2]
		if z > 1 {
			return nil, cc(0xCC)
		}
		if data[1] == 0 {
			return []byte{b.Duty[z]}, nil
		}
		if b.refuseDuty != 0 {
			return nil, cc(b.refuseDuty)
		}
		b.Duty[z] = data[3]
		return nil, nil
	}
	return nil, fmt.Errorf("fakebmc: unexpected request %02x %02x", netfn, cmd)
}
