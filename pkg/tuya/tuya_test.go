package tuya

// Vectors generated with tinytuya (github.com/jasonacox/tinytuya, commit c0eb2ee) using its own
// XenonDevice._encode_message / pack_message and the pyca cryptography backend, with a fixed GCM IV
// "0123456789ab" and, for 3.4/3.5, a pretend-negotiated session key "sessionkey123456".
// Script: scratchpad/tuya_vec.py (not part of the repo).

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

const testKey = "0123456789abcdef"

var vectors = []struct {
	version string
	cmd     uint32
	payload string
	frame   string
	reply   string
}{
	{"3.3", 7, `{"dps":{"1":true}}`, "000055aa000000010000000700000037332e33000000000000000000000000c27ee03f8be481e63320de7dc6eb429664215f365b0dad6b2ac8fab15b1d40bda72fbba70000aa55", "000055aa000000070000000800000047332e33000000000000000000000000c27ee03f8be481e63320de7dc6eb4296aaaba1ebc64f5ff2f41a0467f52e726b79056e343821999dc6c527b3346c47152cd8b5f90000aa55"},
	{"3.4", 13, `{"dps":{"1":true}}`, "000055aa000000010000000d000000542373228832df8adf74c44d5c3ccf84bd4c103b57066f4329590590a54bd501d26e173b80301bc7e7e62260910b8e52260a3da9f565840d83894b0b7104cd3a500027c5303fd85fda7f0376853237f1dd0000aa55", "000055aa0000000700000008000000642373228832df8adf74c44d5c3ccf84bd4b9f342a0a8f242fd8d1862f2a464d47c541ad03b12dbaa024711c60431ade91c6183c5146832a009a9ba3f4e2391ddd1cf54db214ac72f57aabf1bc1e1c451f7f64b218a7b3a0eeaef4aff3cc87f90e0000aa55"},
	{"3.5", 13, `{"dps":{"1":true}}`, "000066990000000000010000000d0000003d303132333435363738396162c7c52aa2ef340ac079403533d7ef3939864eb00244880c2c3208fb5a72b49c79d8f3b62c0d53ad5eecb74966b649ea9b4200009966", "00006699000000000007000000080000005d303132333435363738396162f4eb1fa2dc1a3fc079403533d7ef3942a42ac00a44d6077d2110ba0c31e3c370d785fa793cd2efc7869c07c4ba095eb1f94c0c94323580f9294f372ee664b509a93d1953686346bdba7308ec531b53d7b200009966"},
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestDevice(t *testing.T, version string) *Device {
	t.Helper()
	d, err := NewDevice("bf0123456789abcdef", "127.0.0.1", testKey, version, 0)
	if err != nil {
		t.Fatal(err)
	}
	if version != "3.3" {
		d.session = []byte("sessionkey123456")
	}
	d.randIV = func() []byte { return []byte("0123456789ab") }
	return d
}

func TestEncodeMatchesTinytuya(t *testing.T) {
	for _, v := range vectors {
		d := newTestDevice(t, v.version)
		got, err := d.Encode(v.cmd, []byte(v.payload))
		if err != nil {
			t.Fatal(err)
		}
		if want := unhex(t, v.frame); !bytes.Equal(got, want) {
			t.Errorf("%s: frame mismatch\n got %x\nwant %x", v.version, got, want)
		}
	}
}

func TestDecodeReplyFromTinytuya(t *testing.T) {
	for _, v := range vectors {
		d := newTestDevice(t, v.version)
		var key []byte
		if v.version != "3.3" {
			key = d.key()
		}
		// tinytuya's pack_message adds a retcode only to 6699 frames.
		m, err := Unpack(unhex(t, v.reply), key, v.version == "3.5")
		if err != nil {
			t.Fatalf("%s: %v", v.version, err)
		}
		if !m.CRCGood || m.Cmd != 8 || m.Seq != 7 {
			t.Fatalf("%s: bad frame %+v", v.version, m)
		}
		out, err := d.DecodePayload(m.Payload)
		if err != nil {
			t.Fatalf("%s: %v", v.version, err)
		}
		dps, _ := out["dps"].(map[string]any)
		if dps["19"] != float64(1234) || dps["20"] != float64(2301) || dps["1"] != true {
			t.Errorf("%s: dps = %v", v.version, dps)
		}
	}
}

func TestTamperedFramesRejected(t *testing.T) {
	for _, v := range vectors {
		b := unhex(t, v.reply)
		b[20] ^= 0xff
		d := newTestDevice(t, v.version)
		var key []byte
		if v.version != "3.3" {
			key = d.key()
		}
		m, err := Unpack(b, key, v.version == "3.5")
		if err == nil && m.CRCGood {
			t.Errorf("%s: tampered frame accepted", v.version)
		}
	}
}

func TestSessionKey(t *testing.T) {
	local := make([]byte, 16)
	remote := make([]byte, 16)
	for i := range local {
		local[i] = byte(i)
		remote[i] = byte(16 + i)
	}
	k34, err := SessionKey([]byte(testKey), local, remote, false)
	if err != nil || hex.EncodeToString(k34) != "377222e061a924c591cd9c27ea163ed4" {
		t.Errorf("3.4 session key %x %v", k34, err)
	}
	k35, err := SessionKey([]byte(testKey), local, remote, true)
	if err != nil || hex.EncodeToString(k35) != "ed2fd40d0e642b26f836170ad08ba03d" {
		t.Errorf("3.5 session key %x %v", k35, err)
	}
}

func TestFrameLength(t *testing.T) {
	for _, v := range vectors {
		b := unhex(t, v.reply)
		n, err := FrameLength(b)
		if err != nil || n != len(b) {
			t.Errorf("%s: FrameLength = %d, %v (want %d)", v.version, n, err, len(b))
		}
	}
	if _, err := FrameLength([]byte{1, 2, 3, 4, 5}); err == nil {
		t.Error("bad prefix accepted")
	}
}

func TestQueryPayload33(t *testing.T) {
	d := newTestDevice(t, "3.3")
	cmd, p := d.queryPayload(timeAt(1700000000))
	if cmd != DPQuery || string(p) != `{"gwId":"bf0123456789abcdef","devId":"bf0123456789abcdef","uid":"bf0123456789abcdef","t":"1700000000"}` {
		t.Errorf("got %d %s", cmd, p)
	}
	d4 := newTestDevice(t, "3.4")
	if cmd, p := d4.queryPayload(timeAt(0)); cmd != DPQueryNew || string(p) != "{}" {
		t.Errorf("3.4 got %d %s", cmd, p)
	}
}

func timeAt(s int64) time.Time { return time.Unix(s, 0) }
