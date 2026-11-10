package enroll

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// The worked example of the v2 documentation. The expected values were computed outside Go (HKDF and HMAC
// written out with hashlib, AES-GCM from Python's cryptography package), not copied from this package's output.
const (
	vecCode  = "MFRG-GZDF-MZTW-Q2LK-NNWG-23TP-OBYX-E43U"
	vecNp    = "000102030405060708090a0b0c0d0e0f"
	vecNa    = "101112131415161718191a1b1c1d1e1f"
	vecKey   = "4ae0aee44bee6373d4ad517659cf8102735277408b7c2f733f9500b6863f2c4c"
	vecMAC   = "2a7a5c08d3989ec4f8061faa45cb4a030a008d892099b259c7d144d6985850a8"
	vecReq   = `{"v":2,"nonce":"AAECAwQFBgcICQoLDA0ODw==","mac":"KnpcCNOYnsT4Bh+qRctKAwoAjYkgmbJZx9FE1phYUKg="}`
	vecPlain = `{"agent_version":"0.6.0","hostname":"nas","platform":"linux","features":{"power_control":true},"token":"read-token-0123456789abcdef","control_token":"control-token-0123456789abcdef"}`
	vecAns   = `{"v":2,"nonce":"EBESExQVFhcYGRobHB0eHw==","sealed":"aIWXC9ZjQNs2u6HqYy7efFCy6NLrmYix5lPM+jUAT2tw3JhohaaL6vD4Ses1OumkilPLRxzd25FU/15a6uP1AS1Zv8tcQfJFQAc0qrgyQpLAF3gS2KWfqxFbhxUZopr6qVnN4H7KP2f+g2o+3SjqV1m+7pb6+YUfuH46uBI3KglSitDRGmvM4He6ktQERQM7MyDSX826EnkDWz2XnQ4rw4hxSQDgI5/qqPXKDRQTbSc6ebo4Mrii8vs6wvY0znedLTVUbipC"}`
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vecResponse() Response {
	return Response{AgentVersion: "0.6.0", Hostname: "nas", Platform: "linux", Features: map[string]bool{"power_control": true},
		Token: "read-token-0123456789abcdef", ControlToken: "control-token-0123456789abcdef"}
}

// rfc5869 is HKDF-SHA256 written out with HMAC only, to check that v2.go computes what its comment says
// without going through crypto/hkdf.
func rfc5869(secret, salt []byte, info string, n int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	ext := hmac.New(sha256.New, salt)
	ext.Write(secret)
	prk := ext.Sum(nil)
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write([]byte(info))
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

func TestV2FixedVectors(t *testing.T) {
	key, err := PairingKey(vecCode)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key) != vecKey {
		t.Fatalf("K = %x", key)
	}
	// the same key for every spelling of the code
	if k2, _ := PairingKey(" mfrggzdfmztwq2lknnwg23tpobyxe43u\n"); !bytes.Equal(k2, key) {
		t.Fatalf("lower case, no dashes: %x", k2)
	}
	if want := rfc5869([]byte("MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U"), nil, "fairy-enroll-v2 key", 32); !bytes.Equal(key, want) {
		t.Fatalf("K is not HKDF(code, info key): %x", want)
	}
	np, na := unhex(t, vecNp), unhex(t, vecNa)
	req, err := newRequestV2(key, np)
	if err != nil {
		t.Fatal(err)
	}
	kreq := rfc5869(key, nil, "fairy-enroll-v2 request", 32)
	m := hmac.New(sha256.New, kreq)
	m.Write(np)
	if !bytes.Equal(req.MAC, m.Sum(nil)) || hex.EncodeToString(req.MAC) != vecMAC {
		t.Fatalf("mac = %x", req.MAC)
	}
	if b, _ := json.Marshal(req); string(b) != vecReq {
		t.Fatalf("request JSON: %s", b)
	}
	if err := CheckRequestV2(key, req); err != nil {
		t.Fatal(err)
	}
	ans, err := sealAnswer(key, req, na, vecResponse())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(ans)
	if string(body) != vecAns {
		t.Fatalf("answer JSON: %s", body)
	}
	// the sealed part by hand: AES-256-GCM under HKDF(K, salt Np|Na, info answer), AAD label|Np|Na
	okm := rfc5869(key, append(append([]byte{}, np...), na...), "fairy-enroll-v2 answer", 44)
	block, _ := aes.NewCipher(okm[:32])
	gcm, _ := cipher.NewGCM(block)
	aad := append(append([]byte("fairy-enroll-v2 answer"), np...), na...)
	plain, err := gcm.Open(nil, okm[32:], ans.Sealed, aad)
	if err != nil || string(plain) != vecPlain {
		t.Fatalf("sealed part by hand: %q %v", plain, err)
	}
	got, err := OpenAnswer(key, req, []byte(vecAns))
	if err != nil || got.Token != "read-token-0123456789abcdef" || got.ControlToken != "control-token-0123456789abcdef" ||
		got.AgentVersion != "0.6.0" || got.Hostname != "nas" || !got.Features["power_control"] {
		t.Fatalf("open: %+v %v", got, err)
	}
}

func v2Pair(t *testing.T) (key []byte, req RequestV2, body []byte) {
	t.Helper()
	code, err := NewCode()
	if err != nil {
		t.Fatal(err)
	}
	if key, err = PairingKey(code); err != nil {
		t.Fatal(err)
	}
	if req, err = NewRequestV2(key); err != nil {
		t.Fatal(err)
	}
	ans, err := SealAnswer(key, req, vecResponse())
	if err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(ans)
	return key, req, body
}

func TestV2RoundTrip(t *testing.T) {
	key, req, body := v2Pair(t)
	if len(key) != KeySize || req.V != V2 || len(req.Nonce) != NonceSize || len(req.MAC) != 32 {
		t.Fatalf("%d %+v", len(key), req)
	}
	got, err := OpenAnswer(key, req, body)
	if err != nil || got.Token != vecResponse().Token || got.ControlToken != vecResponse().ControlToken {
		t.Fatalf("%+v %v", got, err)
	}
	// nothing readable crosses: neither message contains a token, the key or the code's proof
	wire, _ := json.Marshal(req)
	wire = append(wire, body...)
	for _, secret := range []string{vecResponse().Token, vecResponse().ControlToken, hex.EncodeToString(key), "token"} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatalf("%q is readable on the wire: %s", secret, wire)
		}
	}
	// a Proxmox grant travels inside the sealed part too
	resp := vecResponse()
	resp.Proxmox = &ProxmoxGrant{TokenID: "fairy@pve!panel-n1", TokenSecret: "0b7c4e2a-1111-2222-3333-444455556666", CAPEM: strings.Repeat("A", 4000), Node: "n1"}
	ans, err := SealAnswer(key, req, resp)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ans)
	if got, err := OpenAnswer(key, req, b); err != nil || got.Proxmox == nil || got.Proxmox.TokenSecret != resp.Proxmox.TokenSecret || bytes.Contains(b, []byte("0b7c4e2a")) {
		t.Fatalf("%+v %v", got, err)
	}
	// the largest answer the agent seals fits in MaxAnswerBody; one byte more is not sealed at all
	resp.Proxmox.CAPEM = ""
	base, _ := json.Marshal(resp)
	resp.Proxmox.CAPEM = strings.Repeat("A", maxAnswerV2-gcmTagSize-len(base))
	ans, err = SealAnswer(key, req, resp)
	if err != nil || len(ans.Sealed) != maxAnswerV2 {
		t.Fatalf("largest answer: %d %v", len(ans.Sealed), err)
	}
	if b, _ = json.Marshal(ans); len(b) > MaxAnswerBody {
		t.Fatalf("largest answer body is %d bytes, MaxAnswerBody is %d", len(b), MaxAnswerBody)
	}
	if got, err := OpenAnswer(key, req, b); err != nil || len(got.Proxmox.CAPEM) != len(resp.Proxmox.CAPEM) {
		t.Fatalf("largest answer does not open: %v", err)
	}
	resp.Proxmox.CAPEM += "A"
	if _, err := SealAnswer(key, req, resp); err == nil {
		t.Fatal("an answer over the limit was sealed")
	}
	// every request and every answer is new
	req2, _ := NewRequestV2(key)
	ans2, _ := SealAnswer(key, req, vecResponse())
	ans3, _ := SealAnswer(key, req, vecResponse())
	if bytes.Equal(req.Nonce, req2.Nonce) || bytes.Equal(ans2.Nonce, ans3.Nonce) || bytes.Equal(ans2.Sealed, ans3.Sealed) {
		t.Fatal("nonces repeat")
	}
}

func TestV2RequestCheck(t *testing.T) {
	key, req, _ := v2Pair(t)
	other, _ := PairingKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err := CheckRequestV2(other, req); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("another code: %v", err)
	}
	if _, err := SealAnswer(other, req, vecResponse()); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("an answer was sealed for a request that does not check: %v", err)
	}
	flip := func(b []byte, i int) []byte { c := bytes.Clone(b); c[i] ^= 1; return c }
	for name, c := range map[string]struct {
		r    RequestV2
		want error
	}{
		"mac bit":       {RequestV2{V2, req.Nonce, flip(req.MAC, 0)}, ErrWrongCode},
		"mac last bit":  {RequestV2{V2, req.Nonce, flip(req.MAC, 31)}, ErrWrongCode},
		"nonce bit":     {RequestV2{V2, flip(req.Nonce, 5), req.MAC}, ErrWrongCode},
		"mac of zeros":  {RequestV2{V2, req.Nonce, make([]byte, 32)}, ErrWrongCode},
		"version 1":     {RequestV2{1, req.Nonce, req.MAC}, ErrNotV2},
		"version 3":     {RequestV2{3, req.Nonce, req.MAC}, ErrNotV2},
		"short nonce":   {RequestV2{V2, req.Nonce[:15], req.MAC}, ErrNotV2},
		"long nonce":    {RequestV2{V2, append(bytes.Clone(req.Nonce), 0), req.MAC}, ErrNotV2},
		"no nonce":      {RequestV2{V2, nil, req.MAC}, ErrNotV2},
		"short mac":     {RequestV2{V2, req.Nonce, req.MAC[:31]}, ErrNotV2},
		"no mac":        {RequestV2{V2, req.Nonce, nil}, ErrNotV2},
		"nonce as mac":  {RequestV2{V2, req.Nonce, append(bytes.Clone(req.Nonce), req.Nonce...)}, ErrWrongCode},
		"empty request": {RequestV2{}, ErrNotV2},
	} {
		if err := CheckRequestV2(key, c.r); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	for _, bad := range [][]byte{nil, {}, key[:31], append(bytes.Clone(key), 0)} {
		if err := CheckRequestV2(bad, req); !errors.Is(err, ErrBadKey) {
			t.Errorf("key of %d bytes: %v", len(bad), err)
		}
		if _, err := NewRequestV2(bad); !errors.Is(err, ErrBadKey) {
			t.Errorf("NewRequestV2 with a key of %d bytes: %v", len(bad), err)
		}
		if _, err := OpenAnswer(bad, req, nil); !errors.Is(err, ErrBadKey) {
			t.Errorf("OpenAnswer with a key of %d bytes: %v", len(bad), err)
		}
	}
	if _, err := PairingKey("nope"); err == nil {
		t.Fatal("a bad code got a key")
	}
}

// What the panel must refuse: every answer that is not the agent's sealed answer to this very request.
func TestV2AnswerRefused(t *testing.T) {
	key, req, body := v2Pair(t)
	var ans AnswerV2
	if err := json.Unmarshal(body, &ans); err != nil {
		t.Fatal(err)
	}
	enc := func(a AnswerV2) []byte { b, _ := json.Marshal(a); return b }
	flip := func(b []byte, i int) []byte { c := bytes.Clone(b); c[i] ^= 0x80; return c }

	// tampering: any single changed byte of the sealed part or of the agent's nonce
	for i := range ans.Sealed {
		if _, err := OpenAnswer(key, req, enc(AnswerV2{V2, ans.Nonce, flip(ans.Sealed, i)})); !errors.Is(err, ErrUnauthentic) {
			t.Fatalf("sealed byte %d changed: %v", i, err)
		}
	}
	for i := range ans.Nonce {
		if _, err := OpenAnswer(key, req, enc(AnswerV2{V2, flip(ans.Nonce, i), ans.Sealed})); !errors.Is(err, ErrUnauthentic) {
			t.Fatalf("nonce byte %d changed: %v", i, err)
		}
	}
	// replay: the agent's real answer to an EARLIER request of the same panel, same code
	req2, _ := NewRequestV2(key)
	if _, err := OpenAnswer(key, req2, body); !errors.Is(err, ErrUnauthentic) {
		t.Fatalf("an answer to another request opened: %v", err)
	}
	// impostor: someone without the code
	wrong, _ := PairingKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	forged, _ := SealAnswer(wrong, RequestV2{V2, req.Nonce, mustMAC(t, wrong, req.Nonce)}, Response{Token: "impostor", Platform: "linux"})
	v1, _ := json.Marshal(Response{AgentVersion: "0.5.3", Platform: "linux", Token: "impostor-token-0123456789", Features: map[string]bool{}})
	reqJSON, _ := json.Marshal(req)
	mixed := `{"v":2,"nonce":"` + b64(ans.Nonce) + `","token":"impostor","agent_version":"0.5.3","platform":"linux"}`
	for name, c := range map[string]struct {
		body []byte
		want error
	}{
		"sealed with another code":        {enc(forged), ErrUnauthentic},
		"v1 answer, tokens in clear":      {v1, ErrNotV2},
		"v1 fields beside v2 ones":        {[]byte(mixed), ErrNotV2},
		"the request sent back":           {reqJSON, ErrNotV2},
		"the request's mac as sealed":     {enc(AnswerV2{V2, req.Nonce, req.MAC}), ErrUnauthentic},
		"the panel's nonce sent back":     {enc(AnswerV2{V2, req.Nonce, ans.Sealed}), ErrUnauthentic},
		"random sealed":                   {enc(AnswerV2{V2, ans.Nonce, make([]byte, 80)}), ErrUnauthentic},
		"truncated sealed":                {enc(AnswerV2{V2, ans.Nonce, ans.Sealed[:len(ans.Sealed)-1]}), ErrUnauthentic},
		"sealed shorter than a tag":       {enc(AnswerV2{V2, ans.Nonce, ans.Sealed[:15]}), ErrNotV2},
		"sealed too large":                {enc(AnswerV2{V2, ans.Nonce, make([]byte, maxAnswerV2+1)}), ErrNotV2},
		"version 1":                       {enc(AnswerV2{1, ans.Nonce, ans.Sealed}), ErrNotV2},
		"version 3":                       {enc(AnswerV2{3, ans.Nonce, ans.Sealed}), ErrNotV2},
		"no version":                      {enc(AnswerV2{0, ans.Nonce, ans.Sealed}), ErrNotV2},
		"short agent nonce":               {enc(AnswerV2{V2, ans.Nonce[:8], ans.Sealed}), ErrNotV2},
		"no agent nonce":                  {enc(AnswerV2{V2, nil, ans.Sealed}), ErrNotV2},
		"empty body":                      {nil, ErrNotV2},
		"null":                            {[]byte("null"), ErrNotV2},
		"not JSON":                        {[]byte("<html>"), ErrNotV2},
		"an error answer":                 {[]byte(`{"error":"x","code":"bad_request"}`), ErrNotV2},
		"nonce not base64":                {[]byte(`{"v":2,"nonce":"!!","sealed":"AAAA"}`), ErrNotV2},
		"sealed of the right key, as hex": {[]byte(`{"v":2,"nonce":"` + b64(ans.Nonce) + `","sealed":"` + hex.EncodeToString(ans.Sealed) + `"}`), ErrUnauthentic},
	} {
		got, err := OpenAnswer(key, req, c.body)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if got.Token != "" || got.ControlToken != "" || got.AgentVersion != "" {
			t.Errorf("%s: a refused answer still returned %+v", name, got)
		}
	}
	// a request of another version or without a nonce opens nothing
	if _, err := OpenAnswer(key, RequestV2{V: 1, Nonce: req.Nonce}, body); !errors.Is(err, ErrNotV2) {
		t.Fatal(err)
	}
	if _, err := OpenAnswer(key, RequestV2{V: V2}, body); !errors.Is(err, ErrNotV2) {
		t.Fatal(err)
	}
	// and the untouched answer still opens
	if _, err := OpenAnswer(key, req, body); err != nil {
		t.Fatal(err)
	}
}

func mustMAC(t *testing.T, key, nonce []byte) []byte {
	t.Helper()
	m, err := requestMAC(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func b64(b []byte) string {
	j, _ := json.Marshal(b)
	return strings.Trim(string(j), `"`)
}

// The wire: field names are fixed, and an agent that only knows v1 reads a v2 request as "no proof" (400).
func TestV2WireShape(t *testing.T) {
	key, req, body := v2Pair(t)
	var m map[string]any
	b, _ := json.Marshal(req)
	if err := json.Unmarshal(b, &m); err != nil || len(m) != 3 || m["v"] != float64(2) || m["nonce"] == nil || m["mac"] == nil {
		t.Fatalf("request: %s", b)
	}
	var old Request
	if err := json.Unmarshal(b, &old); err != nil || old.Proof != "" {
		t.Fatalf("a v1 agent reads a proof out of a v2 request: %+v %v", old, err)
	}
	m = nil
	if err := json.Unmarshal(body, &m); err != nil || len(m) != 3 || m["v"] != float64(2) || m["nonce"] == nil || m["sealed"] == nil {
		t.Fatalf("answer: %s", body)
	}
	// a v1 panel reading a v2 answer finds no token in it
	var v1 Response
	if err := json.Unmarshal(body, &v1); err != nil || v1.Token != "" || v1.ControlToken != "" {
		t.Fatalf("%+v %v", v1, err)
	}
	_ = key
}

func TestStatePairVersion(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	key, _ := PairingKey(vecCode)
	base := State{Version: 1, Panel: "100.64.0.1", CreatedAt: now.Unix(), ExpiresAt: now.Add(TTL).Unix()}
	v1, v2, both, none := base, base, base, base
	v1.Verifier = "ab"
	v2.Key2 = hex.EncodeToString(key)
	both.Verifier, both.Key2 = "ab", v2.Key2
	if v1.PairVersion() != 1 || v2.PairVersion() != 2 || both.PairVersion() != 2 || none.PairVersion() != 0 {
		t.Fatal("PairVersion")
	}
	if !v1.Active(now) || !v2.Active(now) || none.Active(now) || v2.Active(now.Add(TTL)) {
		t.Fatal("Active")
	}
	if !strings.Contains(v2.Describe(now), "waiting for the panel") || none.Describe(now) != "no join code" {
		t.Fatal(v2.Describe(now), none.Describe(now))
	}
	if k, err := v2.PairingKey2(); err != nil || !bytes.Equal(k, key) {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "zz", v2.Key2[:62], v2.Key2 + "00"} {
		s := base
		s.Key2 = bad
		if _, err := s.PairingKey2(); !errors.Is(err, ErrBadKey) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	// the key is in the file as "key2" and nothing of v1 beside it
	b, _ := json.Marshal(v2)
	if !bytes.Contains(b, []byte(`"key2":"`+v2.Key2+`"`)) || bytes.Contains(b, []byte("verifier")) {
		t.Fatalf("%s", b)
	}
}
