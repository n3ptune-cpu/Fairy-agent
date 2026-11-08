package ipmi

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
)

// Sensor types (IPMI v2.0 table 42-3) fairy-agent reports.
const (
	TypeTemperature = 0x01
	TypeVoltage     = 0x02
	TypeFan         = 0x04
)

// Sensor is a threshold sensor from a Full Sensor Record (SDR type 0x01) with its conversion factors.
type Sensor struct {
	Number   byte
	Type     byte
	Name     string
	analog   byte // 0 unsigned, 1 one's complement, 2 two's complement, 3 no analog reading
	linear   byte
	m, b     int
	bExp     int
	rExp     int
	upperCrt *byte
}

func signExtend(v, bits int) int {
	if v&(1<<(bits-1)) != 0 {
		return v - (1 << bits)
	}
	return v
}

// ParseFullSensor parses one SDR record (header included). ok is false for other record types, sensors owned by
// another controller or LUN, and sensors without an analog reading.
func ParseFullSensor(rec []byte) (Sensor, bool) {
	if len(rec) < 48 || rec[3] != 0x01 {
		return Sensor{}, false
	}
	if rec[5] != 0x20 || rec[6]&0x03 != 0 { // owner: the BMC itself, LUN 0
		return Sensor{}, false
	}
	s := Sensor{Number: rec[7], Type: rec[12], analog: rec[20] >> 6, linear: rec[23] & 0x7F}
	if s.analog == 3 || s.linear != 0 {
		return Sensor{}, false
	}
	s.m = signExtend(int(rec[24])|int(rec[25]>>6)<<8, 10)
	s.b = signExtend(int(rec[26])|int(rec[27]>>6)<<8, 10)
	s.rExp = signExtend(int(rec[29]>>4), 4)
	s.bExp = signExtend(int(rec[29]&0x0F), 4)
	if rec[18]&0x10 != 0 { // upper critical threshold readable (reading mask byte 2, bit 4)
		v := rec[37]
		s.upperCrt = &v
	}
	n := int(rec[47] & 0x1F)
	if 48+n <= len(rec) {
		s.Name = strings.TrimSpace(strings.Trim(string(rec[48:48+n]), "\x00"))
	}
	if s.Name == "" {
		s.Name = "sensor " + strconv.Itoa(int(s.Number))
	}
	return s, true
}

// Convert turns a raw reading into the sensor's unit: y = (M*x + B*10^Bexp) * 10^Rexp.
func (s Sensor) Convert(raw byte) float64 {
	var x int
	switch s.analog {
	case 1:
		x = int(raw)
		if raw&0x80 != 0 {
			x = -int(^raw & 0x7F)
		}
	case 2:
		x = int(int8(raw))
	default:
		x = int(raw)
	}
	y := (float64(s.m)*float64(x) + float64(s.b)*math.Pow(10, float64(s.bExp))) * math.Pow(10, float64(s.rExp))
	return math.Round(y*1000) / 1000
}

// UpperCritical is the converted upper critical threshold, if the BMC publishes one.
func (s Sensor) UpperCritical() *float64 {
	if s.upperCrt == nil {
		return nil
	}
	v := s.Convert(*s.upperCrt)
	return &v
}

const (
	ccReservationCanceled = 0xC5
	ccCannotReturnLength  = 0xCA
)

// ReadSDR walks the BMC's sensor data repository and returns its temperature, voltage and fan sensors.
func ReadSDR(ctx context.Context, t Transport) ([]Sensor, error) {
	reserve := func() ([2]byte, error) {
		r, err := t.Raw(ctx, NetFnStorage, CmdReserveSDR, nil)
		if err != nil {
			return [2]byte{}, err
		}
		if len(r) < 2 {
			return [2]byte{}, errors.New("short SDR reservation")
		}
		return [2]byte{r[0], r[1]}, nil
	}
	res, err := reserve()
	if err != nil {
		return nil, err
	}
	chunk := byte(16)
	get := func(id uint16, off, n byte) ([]byte, uint16, error) {
		for try := 0; ; try++ {
			r, err := t.Raw(ctx, NetFnStorage, CmdGetSDR, []byte{res[0], res[1], byte(id), byte(id >> 8), off, n})
			if IsCompletion(err, ccReservationCanceled) && try < 3 {
				if res, err = reserve(); err != nil {
					return nil, 0, err
				}
				continue
			}
			if err != nil {
				return nil, 0, err
			}
			if len(r) < 2 {
				return nil, 0, errors.New("short SDR response")
			}
			return r[2:], uint16(r[0]) | uint16(r[1])<<8, nil
		}
	}
	var out []Sensor
	id := uint16(0)
	for count := 0; id != 0xFFFF && count < 1024; count++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		hdr, next, err := get(id, 0, 5)
		if err != nil {
			return out, err
		}
		if len(hdr) < 5 {
			return out, errors.New("short SDR header")
		}
		rec := append([]byte{}, hdr[:5]...)
		length := int(hdr[4])
		for off := 0; off < length; {
			n := min(int(chunk), length-off)
			part, _, err := get(id, byte(5+off), byte(n))
			if IsCompletion(err, ccCannotReturnLength) && chunk > 4 {
				chunk /= 2
				continue
			}
			if err != nil {
				return out, err
			}
			if len(part) == 0 {
				return out, errors.New("empty SDR chunk")
			}
			rec = append(rec, part...)
			off += len(part)
		}
		if s, ok := ParseFullSensor(rec); ok && (s.Type == TypeTemperature || s.Type == TypeVoltage || s.Type == TypeFan) {
			out = append(out, s)
		}
		if next == id {
			break
		}
		id = next
	}
	return out, nil
}

// Reading is one sensor's current value.
type Reading struct {
	Sensor Sensor
	Value  float64
}

// ReadSensors reads every sensor; sensors that are absent, disabled or unavailable (empty fan headers) are
// left out.
func ReadSensors(ctx context.Context, t Transport, sensors []Sensor) ([]Reading, error) {
	var out []Reading
	var firstErr error
	for _, s := range sensors {
		r, err := t.Raw(ctx, NetFnSensor, CmdGetSensorReading, []byte{s.Number})
		if err != nil {
			if firstErr == nil && !IsCompletion(err, 0xCB) {
				firstErr = err
			}
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			continue
		}
		if len(r) < 2 || r[1]&0x20 != 0 || r[1]&0x40 == 0 {
			continue
		}
		out = append(out, Reading{Sensor: s, Value: s.Convert(r[0])})
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}
