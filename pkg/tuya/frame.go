package tuya

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// Pack55AA builds a 3.3/3.4 frame: prefix, seqno, cmd, length (BE uint32) | payload | crc32 or hmac-sha256 | suffix.
func Pack55AA(seq, cmd uint32, payload, hmacKey []byte) []byte {
	endLen := 8
	if hmacKey != nil {
		endLen = 36
	}
	buf := make([]byte, 16, 16+len(payload)+endLen)
	binary.BigEndian.PutUint32(buf[0:], prefix55AA)
	binary.BigEndian.PutUint32(buf[4:], seq)
	binary.BigEndian.PutUint32(buf[8:], cmd)
	binary.BigEndian.PutUint32(buf[12:], uint32(len(payload)+endLen))
	buf = append(buf, payload...)
	if hmacKey != nil {
		buf = append(buf, hmacSHA256(hmacKey, buf)...)
	} else {
		buf = binary.BigEndian.AppendUint32(buf, crc32.ChecksumIEEE(buf))
	}
	return binary.BigEndian.AppendUint32(buf, suffix55AA)
}

// Pack6699 builds a 3.5 frame: prefix(4) unknown(2)=0 seqno(4) cmd(4) length(4) | iv(12) | AES-GCM(ciphertext) |
// tag(16) | suffix. The 14 header bytes after the prefix are the GCM additional data.
func Pack6699(seq, cmd uint32, payload, key, iv []byte) ([]byte, error) {
	if len(iv) != 12 {
		return nil, errors.New("tuya: iv must be 12 bytes")
	}
	hdr := make([]byte, 18)
	binary.BigEndian.PutUint32(hdr[0:], prefix6699)
	binary.BigEndian.PutUint16(hdr[4:], 0)
	binary.BigEndian.PutUint32(hdr[6:], seq)
	binary.BigEndian.PutUint32(hdr[10:], cmd)
	binary.BigEndian.PutUint32(hdr[14:], uint32(len(payload)+28))
	sealed, err := gcmSeal(key, iv, payload, hdr[4:])
	if err != nil {
		return nil, err
	}
	out := append(hdr, iv...)
	out = append(out, sealed...)
	return binary.BigEndian.AppendUint32(out, suffix6699), nil
}

// Message is a decoded frame.
type Message struct {
	Seq, Cmd, Retcode uint32
	Payload           []byte
	CRCGood           bool
	Prefix            uint32
}

// FrameLength returns the full length of the frame starting at data[0] (needs the header bytes), or 0.
func FrameLength(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, nil
	}
	switch binary.BigEndian.Uint32(data) {
	case prefix55AA:
		if len(data) < 16 {
			return 0, nil
		}
		n := binary.BigEndian.Uint32(data[12:])
		if n > maxPayload {
			return 0, ErrDecode
		}
		return 16 + int(n), nil
	case prefix6699:
		if len(data) < 18 {
			return 0, nil
		}
		n := binary.BigEndian.Uint32(data[14:])
		if n > maxPayload {
			return 0, ErrDecode
		}
		return 18 + int(n) + 4, nil
	}
	return 0, fmt.Errorf("%w: bad prefix", ErrDecode)
}

// Unpack decodes one frame. For 55AA frames the 4-byte return code is present in device replies (hasRetcode).
// key: HMAC key for 3.4 (nil = CRC32), GCM key for 6699 frames.
func Unpack(data, key []byte, hasRetcode bool) (Message, error) {
	total, err := FrameLength(data)
	if err != nil {
		return Message{}, err
	}
	if total == 0 || len(data) < total {
		return Message{}, fmt.Errorf("%w: short frame", ErrDecode)
	}
	pfx := binary.BigEndian.Uint32(data)
	if pfx == prefix55AA {
		m := Message{Prefix: pfx, Seq: binary.BigEndian.Uint32(data[4:]), Cmd: binary.BigEndian.Uint32(data[8:])}
		endLen := 8
		if key != nil {
			endLen = 36
		}
		retLen := 0
		if hasRetcode {
			retLen = 4
		}
		if total-16 < retLen+endLen {
			return Message{}, fmt.Errorf("%w: short frame", ErrDecode)
		}
		if retLen > 0 {
			m.Retcode = binary.BigEndian.Uint32(data[16:])
		}
		body := data[:total-endLen]
		m.Payload = append([]byte{}, data[16+retLen:total-endLen]...)
		mac := data[total-endLen : total-4]
		if key != nil {
			m.CRCGood = hmac.Equal(mac, hmacSHA256(key, body))
		} else {
			m.CRCGood = binary.BigEndian.Uint32(mac) == crc32.ChecksumIEEE(body)
		}
		return m, nil
	}
	// 6699
	m := Message{Prefix: pfx, Seq: binary.BigEndian.Uint32(data[6:]), Cmd: binary.BigEndian.Uint32(data[10:])}
	if total < 18+12+16+4 {
		return Message{}, fmt.Errorf("%w: short frame", ErrDecode)
	}
	iv := data[18:30]
	ctTag := data[30 : total-4]
	plain, err := gcmOpen(key, iv, ctTag, data[4:18])
	if err != nil {
		return Message{}, fmt.Errorf("%w: GCM authentication failed", ErrDecode)
	}
	m.CRCGood = true
	if hasRetcode && len(plain) >= 4 {
		m.Retcode = binary.BigEndian.Uint32(plain)
		plain = plain[4:]
	}
	m.Payload = plain
	return m, nil
}
