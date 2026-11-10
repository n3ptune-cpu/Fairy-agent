package enroll

// Fuzz targets from the independent review of the fixes: pairing v2 parsing.
// They run on their seeds with every `go test`; `go test -fuzz <name>` searches further.

import (
	"bytes"
	"encoding/json"
	"testing"
)

func reviewKey(t testing.TB) []byte {
	k, err := PairingKey("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// An answer body the panel reads (up to MaxAnswerBody): nothing but a box sealed with the key for this request
// opens, whatever the bytes are, and nothing panics.
func FuzzOpenAnswer(f *testing.F) {
	key := reviewKey(f)
	req, _ := newRequestV2(key, bytes.Repeat([]byte{7}, NonceSize))
	good, _ := sealAnswer(key, req, bytes.Repeat([]byte{9}, NonceSize), Response{Token: "t", AgentVersion: "1-a", Platform: "linux"})
	gb, _ := json.Marshal(good)
	f.Add(gb)
	f.Add([]byte(`{"v":2,"nonce":"","sealed":""}`))
	f.Add([]byte(`{"agent_version":"1","token":"clear","platform":"linux"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, body []byte) {
		resp, err := OpenAnswer(key, req, body)
		if err != nil {
			if resp.Token != "" || resp.ControlToken != "" {
				t.Fatalf("an error with tokens: %v %+v", err, resp)
			}
			return
		}
		// accepted: it must be the one sealed answer (same nonce and box), possibly re-spelled JSON
		var a AnswerV2
		if json.Unmarshal(body, &a) != nil || !bytes.Equal(a.Nonce, good.Nonce) || !bytes.Equal(a.Sealed, good.Sealed) || a.V != V2 {
			t.Fatalf("accepted an answer that is not the sealed one: %q", body)
		}
	})
}

// A request body as the agent decodes it: only a MAC made with the key passes.
func FuzzCheckRequestV2(f *testing.F) {
	key := reviewKey(f)
	req, _ := newRequestV2(key, bytes.Repeat([]byte{7}, NonceSize))
	gb, _ := json.Marshal(req)
	f.Add(gb)
	f.Add([]byte(`{"v":2,"nonce":"BwcHBwcHBwcHBwcHBwcHBw==","mac":""}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var r RequestV2
		if json.Unmarshal(body, &r) != nil {
			return
		}
		err := CheckRequestV2(key, r)
		if err == nil {
			want, _ := requestMAC(key, r.Nonce)
			if !bytes.Equal(want, r.MAC) || r.V != V2 || len(r.Nonce) != NonceSize {
				t.Fatalf("accepted %q", body)
			}
			if _, err := SealAnswer(key, r, Response{Token: "x"}); err != nil {
				t.Fatal(err)
			}
		}
	})
}
