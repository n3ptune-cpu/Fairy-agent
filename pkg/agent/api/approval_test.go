package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
)

func ip(i int) *int       { return &i }
func sp(s string) *string { return &s }

// vectorChallenge is the challenge of the published test vectors: the bytes first, first+1, ... (32 of them).
func vectorChallenge(first byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = first + byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// The machine ids of the published test vectors: 16 bytes in base64url (the form a machine makes up itself),
// and 16 bytes in hex (a form a panel may choose).
const (
	vectorMachineA = "EBESExQVFhcYGRobHB0eHw"           // the bytes 0x10 ... 0x1f
	vectorMachineB = "00112233445566778899aabbccddeeff" // the bytes 0x00 0x11 ... 0xff
)

// TestApprovalNonceVectors are the worked examples of the protocol description (part1-passkey-protocol.md):
// the panel's implementation must give the same nonces. They were also computed with an independent Python
// hashlib script.
func TestApprovalNonceVectors(t *testing.T) {
	a := MachineEntry{MachineID: vectorMachineA, Challenge: vectorChallenge(0x00), Request: "power action=shutdown delay_s=60"}
	b := MachineEntry{MachineID: vectorMachineB, Challenge: vectorChallenge(0x80), Request: "fan_set zone=0 percent=50"}
	if a.Challenge != "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" {
		t.Fatalf("vector challenge A = %s", a.Challenge)
	}
	if b.Challenge != "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8" {
		t.Fatalf("vector challenge B = %s", b.Challenge)
	}
	if id := base64.RawURLEncoding.EncodeToString([]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}); id != vectorMachineA {
		t.Fatalf("vector machine id A = %s", id)
	}
	aOnB := a
	aOnB.MachineID = vectorMachineB
	for _, c := range []struct {
		name    string
		entries []MachineEntry
		want    string
	}{
		{"one entry", []MachineEntry{a}, "iuzbNkchoxmnpwfVpzW2U6MBub-LzMt-A2XI8o5LAes"},
		{"two entries", []MachineEntry{a, b}, "MrQ7J0kZHsSvpcV4xJkpymWIwlm02CMZVJVGA_7jYhg"},
		{"two entries, other order", []MachineEntry{b, a}, "w6XDMvf0lQ47z2U8XxFGXFKfw2228j--NjgkS-oJvYw"},
		{"the first entry for the other machine", []MachineEntry{aOnB}, "f8xqscm9-nl4LOV17mn_6cgQPh7gPRgxEzPwPiX6a8A"},
	} {
		got, err := ApprovalNonce(c.entries)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: nonce %s, want %s", c.name, got, c.want)
		}
		if len(got) != 43 {
			t.Errorf("%s: nonce of %d characters", c.name, len(got))
		}
	}
}

// oldNonce is the nonce of the test build of 2026-11-11 (scheme 1): the same list without machine ids, under
// the domain "fairy-approval-v1". Kept here to show that no nonce of this version equals one of that build.
func oldNonce(entries []MachineEntry) string {
	h := sha256.New()
	h.Write([]byte("fairy-approval-v1"))
	h.Write([]byte{0})
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(entries)))
	h.Write(n[:])
	for _, e := range entries {
		c, _ := DecodeChallenge(e.Challenge)
		h.Write(c)
		binary.BigEndian.PutUint32(n[:], uint32(len(e.Request)))
		h.Write(n[:])
		h.Write([]byte(e.Request))
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// TestApprovalNonceIsNotTheOldOne: the nonce of scheme 1 for a list (which is what a token of the test build
// carries) is not the nonce of this version for that list, whatever machine id is written into it, also none.
func TestApprovalNonceIsNotTheOldOne(t *testing.T) {
	c := vectorChallenge(0x00)
	if got := oldNonce([]MachineEntry{{Challenge: c, Request: "power action=shutdown delay_s=60"}}); got != "iIJWRjPBb50gLAFJ9H9myD3VD4DyAz4P1gDUQvSpFfs" {
		t.Fatalf("the old nonce is not the published vector of scheme 1: %s", got)
	}
	trust := "trust_set hash=dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ"
	for _, e := range []MachineEntry{
		{vectorMachineA, c, "power action=shutdown delay_s=60"},
		{vectorMachineB, c, "apply_update"},
		{vectorMachineA, c, trust},
		{"", c, trust}, // the one entry that may have no machine id
	} {
		got, err := ApprovalNonce([]MachineEntry{e})
		if err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
		if got == oldNonce([]MachineEntry{e}) {
			t.Errorf("%+v: the nonce equals the old scheme's", e)
		}
	}
	// and the inputs differ before the first entry: the domain
	in, _ := nonceInput([]MachineEntry{{vectorMachineA, c, "apply_update"}})
	if !bytes.HasPrefix(in, []byte("fairy-approval-v2\x00")) || bytes.HasPrefix(in, []byte("fairy-approval-v1")) {
		t.Fatalf("nonce input begins %q", in[:18])
	}
}

// TestApprovalNonceIsUnambiguous: moving a byte from one part to the next, or splitting an entry, changes the
// nonce; nothing a request or a machine id may contain acts as a separator.
func TestApprovalNonceIsUnambiguous(t *testing.T) {
	c1, c2 := vectorChallenge(1), vectorChallenge(2)
	const m, m2 = vectorMachineA, vectorMachineB
	trust := "trust_set hash=dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ"
	seen := map[string]string{}
	for name, e := range map[string][]MachineEntry{
		"ab":      {{m, c1, "ab"}},
		"a,b":     {{m, c1, "a"}, {m, c2, "b"}},
		"abc":     {{m, c1, "abc"}},
		"ab c2":   {{m, c2, "ab"}},
		"ab,same": {{m, c1, "ab"}, {m, c2, "ab"}},
		"a b":     {{m, c1, "a b"}},
		"a  b":    {{m, c1, "a  b"}},
		// the machine id
		"ab, other machine":          {{m2, c1, "ab"}},
		"request/id: byte moved":     {{"A" + m, c1, "ab"}}, // against the next: the same bytes in a row, cut elsewhere
		"request/id: byte in front":  {{m, c1, "abA"}},
		"id one longer":              {{m + "A", c1, "ab"}},
		"two machines":               {{m, c1, "ab"}, {m2, c2, "ab"}},
		"two machines, ids swapped":  {{m2, c1, "ab"}, {m, c2, "ab"}},
		"trust_set with an id":       {{m, c1, trust}},
		"trust_set without":          {{"", c1, trust}},
		"trust_set without, and one": {{"", c1, trust}, {m, c2, "ab"}},
		"trust_set with, and one":    {{m, c1, trust}, {m, c2, "ab"}},
	} {
		n, err := ApprovalNonce(e)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if other, dup := seen[n]; dup {
			t.Errorf("%s and %s give the same nonce", name, other)
		}
		seen[n] = name
	}
}

// parseNonceInput reads the bytes ApprovalNonce hashes back into the list they were made from, without any
// knowledge but the description of the encoding. That it can always do so, and gets the same list, is what
// "two different lists never give the same input" means.
func parseNonceInput(in []byte) ([]MachineEntry, bool) {
	const domain = "fairy-approval-v2\x00"
	if !bytes.HasPrefix(in, []byte(domain)) {
		return nil, false
	}
	in = in[len(domain):]
	num := func() (int, bool) {
		if len(in) < 4 {
			return 0, false
		}
		n := binary.BigEndian.Uint32(in)
		in = in[4:]
		return int(n), n <= 1<<20
	}
	text := func() (string, bool) {
		n, ok := num()
		if !ok || len(in) < n {
			return "", false
		}
		s := string(in[:n])
		in = in[n:]
		return s, true
	}
	count, ok := num()
	if !ok {
		return nil, false
	}
	var out []MachineEntry
	for i := 0; i < count; i++ {
		if len(in) < 32 {
			return nil, false
		}
		e := MachineEntry{Challenge: base64.RawURLEncoding.EncodeToString(in[:32])}
		in = in[32:]
		if e.Request, ok = text(); !ok {
			return nil, false
		}
		if e.MachineID, ok = text(); !ok {
			return nil, false
		}
		out = append(out, e)
	}
	return out, len(in) == 0
}

// fuzzEntries makes a list of entries out of anything: challenges that are well-formed, and requests and
// machine ids cut from the fuzzer's bytes at the places the fuzzer chooses.
func fuzzEntries(data []byte, cuts []byte) []MachineEntry {
	var out []MachineEntry
	for i := 0; len(data) > 0 && i < MaxApprovalEntries+2; i++ {
		take := func(k int) string {
			n := 0
			if k < len(cuts) {
				n = int(cuts[k])
			}
			n = min(n, len(data))
			s := string(data[:n])
			data = data[n:]
			return s
		}
		var c [32]byte
		c[0], c[1] = byte(i), byte(i>>8)
		copy(c[2:], take(3*i))
		req, id := take(3*i+1), take(3*i+2)
		if len(cuts) > 0 && cuts[0]&1 == 1 {
			req = trustSetPrefix + req
		}
		out = append(out, MachineEntry{MachineID: id, Challenge: base64.RawURLEncoding.EncodeToString(c[:]), Request: req})
		if 3*i+2 >= len(cuts) {
			break
		}
	}
	return out
}

// FuzzApprovalNonce looks for two lists of entries with the same nonce input, the only way two different
// approvals could have the same nonce short of breaking SHA-256: whatever list the function accepts must be
// read back from the bytes it hashes, entry by entry, by a reader that knows only the description. And it
// looks for a list that is accepted although an entry has no machine id (only the first-time set may), or a
// machine id that is not one.
func FuzzApprovalNonce(f *testing.F) {
	f.Add([]byte("power action=shutdown delay_s=60"+vectorMachineA), []byte{0, 32, 22})
	f.Add([]byte("hash=dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ"), []byte{1, 48, 0})
	f.Add([]byte("apply_update"+vectorMachineB+"xfan_mode mode=full"+vectorMachineA), []byte{0, 12, 32, 1, 18, 22})
	f.Add([]byte("ab"+vectorMachineA+"A"), []byte{0, 2, 23})
	f.Add([]byte("abA"+vectorMachineA), []byte{0, 3, 22})
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, data, cuts []byte) {
		list := fuzzEntries(data, cuts)
		in, err := nonceInput(list)
		nonce, err2 := ApprovalNonce(list)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("nonceInput: %v, ApprovalNonce: %v", err, err2)
		}
		if err != nil {
			return
		}
		if len(nonce) != 43 {
			t.Fatalf("nonce %q", nonce)
		}
		for _, e := range list {
			if e.MachineID == "" && !strings.HasPrefix(e.Request, "trust_set ") {
				t.Fatalf("accepted an entry without a machine id: %+v", e)
			}
			if e.MachineID != "" && CheckMachineID(e.MachineID) != nil {
				t.Fatalf("accepted the machine id %q", e.MachineID)
			}
		}
		back, ok := parseNonceInput(in)
		if !ok || !slices.Equal(back, list) {
			t.Fatalf("the nonce input does not read back as the list it was made from:\n%+v\n%+v", list, back)
		}
	})
}

func TestCheckMachineID(t *testing.T) {
	for _, ok := range []string{vectorMachineA, vectorMachineB, strings.Repeat("a", MinMachineID), strings.Repeat("Z", MaxMachineID),
		"0123456789-_ABCDEFGHIJ", "3f6c0c0e00004000800000000000000000000000000000000000000000000000",
		"3f6c0c0e-0000-4000-8000-000000000000"} { // "-" is in the alphabet: a UUID in its usual form is a valid id
		if err := CheckMachineID(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for name, bad := range map[string]string{
		"empty":           "",
		"one short":       strings.Repeat("a", MinMachineID-1),
		"one long":        strings.Repeat("a", MaxMachineID+1),
		"very long":       strings.Repeat("a", 4096),
		"a space":         "EBESExQVFhcYGRob B0eHw",
		"a newline":       "EBESExQVFhcYGRobHB0eH\n",
		"padding":         "EBESExQVFhcYGRobHB0eH=",
		"standard base64": "EBESExQVFhcYGRobHB0e+/",
		"a dot":           "EBESExQVFhcYGRobHB0e.w",
		"a NUL":           "EBESExQVFhcYGRobHB0e\x00w",
		"non-ASCII":       "EBESExQVFhcYGRobHB0eHé",
	} {
		if err := CheckMachineID(bad); err == nil {
			t.Errorf("%s: %q accepted", name, bad)
		}
	}
}

func TestApprovalNonceRefuses(t *testing.T) {
	ok := vectorChallenge(0)
	const m = vectorMachineA
	many := make([]MachineEntry, MaxApprovalEntries+1)
	for i := range many {
		many[i] = MachineEntry{m, vectorChallenge(byte(i)), "apply_update"}
	}
	for name, e := range map[string][]MachineEntry{
		"empty list":          nil,
		"too many":            many,
		"short challenge":     {{m, ok[:42], "apply_update"}},
		"long challenge":      {{m, ok + "A", "apply_update"}},
		"padded challenge":    {{m, ok[:42] + "=", "apply_update"}},
		"standard alphabet":   {{m, strings.Repeat("+", 43), "apply_update"}},
		"stray bits":          {{m, ok[:42] + "9", "apply_update"}}, // the last character carries 4 bits that must be 0
		"line break inside":   {{m, ok[:20] + "\n" + ok[21:], "apply_update"}},
		"line break for bits": {{m, ok[:42] + "\n", "apply_update"}},
		"challenge twice":     {{m, ok, "apply_update"}, {m, ok, "fan_mode mode=full"}},
		"empty request":       {{m, ok, ""}},
		"long request":        {{m, ok, strings.Repeat("a", MaxApprovalRequest+1)}},
		"newline in request":  {{m, ok, "apply_update\n"}},
		"NUL in request":      {{m, ok, "apply\x00update"}},
		"non-ASCII in reques": {{m, ok, "apply_updaté"}},
		// the machine id: every entry has one
		"no machine id":                   {{"", ok, "apply_update"}},
		"no machine id, power":            {{"", ok, "power action=shutdown delay_s=60"}},
		"no machine id in the second":     {{m, ok, "apply_update"}, {"", vectorChallenge(1), "apply_update"}},
		"no machine id, trust_set no gap": {{"", ok, "trust_set"}}, // not the first-time set's text: that has a space and a hash
		"no machine id, trust_setx":       {{"", ok, "trust_setx hash=A"}},
		"short machine id":                {{m[:MinMachineID-1], ok, "apply_update"}},
		"long machine id":                 {{strings.Repeat("a", MaxMachineID+1), ok, "apply_update"}},
		"machine id with a space":         {{"EBESExQVFhcYGRob B0eHw", ok, "apply_update"}},
		"machine id with a newline":       {{m + "\n", ok, "apply_update"}},
		"short machine id on trust_set":   {{"abc", ok, "trust_set hash=dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ"}},
	} {
		if n, err := ApprovalNonce(e); err == nil {
			t.Errorf("%s: accepted, nonce %s", name, n)
		}
	}
	if _, err := ApprovalNonce(many[:MaxApprovalEntries]); err != nil {
		t.Errorf("%d entries: %v", MaxApprovalEntries, err)
	}
	if _, err := ApprovalNonce([]MachineEntry{{"", ok, "trust_set hash=dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ"}}); err != nil {
		t.Errorf("the proof of a first-time set that proposes no machine id: %v", err)
	}
}

func TestCanonicalRequest(t *testing.T) {
	for _, c := range []struct {
		r    ApprovalRequest
		want string
	}{
		{ApprovalRequest{Verb: "fan_set", Zone: ip(0), Percent: ip(50)}, "fan_set zone=0 percent=50"},
		{ApprovalRequest{Verb: "fan_set", Zone: ip(1), Percent: ip(100)}, "fan_set zone=1 percent=100"},
		{ApprovalRequest{Verb: "fan_mode", Mode: sp("heavyio")}, "fan_mode mode=heavyio"},
		{ApprovalRequest{Verb: "power", Action: sp("shutdown"), DelayS: ip(60)}, "power action=shutdown delay_s=60"},
		{ApprovalRequest{Verb: "power", Action: sp("sleep"), DelayS: ip(86400)}, "power action=sleep delay_s=86400"},
		{ApprovalRequest{Verb: "apply_update"}, "apply_update"},
		{ApprovalRequest{Verb: "trust_set", TrustHash: sp("dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ")}, "trust_set hash=dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ"},
	} {
		got, err := c.r.Canonical()
		if err != nil || got != c.want {
			t.Errorf("%+v: %q, %v; want %q", c.r, got, err, c.want)
		}
		if len(got) > MaxApprovalRequest {
			t.Errorf("%q is longer than an entry may be", got)
		}
	}
	for name, r := range map[string]ApprovalRequest{
		"no verb":              {},
		"unknown verb":         {Verb: "fan_auto"},
		"read verb":            {Verb: "status"},
		"cancel":               {Verb: "power", Action: sp("cancel")},
		"cancel with delay":    {Verb: "power", Action: sp("cancel"), DelayS: ip(60)},
		"power without delay":  {Verb: "power", Action: sp("shutdown")},
		"power without action": {Verb: "power", DelayS: ip(60)},
		"unknown action":       {Verb: "power", Action: sp("hibernate"), DelayS: ip(60)},
		"action with space":    {Verb: "power", Action: sp("shutdown delay_s=1"), DelayS: ip(60)},
		"negative delay":       {Verb: "power", Action: sp("reboot"), DelayS: ip(-1)},
		"huge delay":           {Verb: "power", Action: sp("reboot"), DelayS: ip(86401)},
		"zone 2":               {Verb: "fan_set", Zone: ip(2), Percent: ip(50)},
		"percent 101":          {Verb: "fan_set", Zone: ip(0), Percent: ip(101)},
		"fan_set without zone": {Verb: "fan_set", Percent: ip(50)},
		"fan_set with mode":    {Verb: "fan_set", Zone: ip(0), Percent: ip(50), Mode: sp("full")},
		"unknown mode":         {Verb: "fan_mode", Mode: sp("silent")},
		"mode with equals":     {Verb: "fan_mode", Mode: sp("full percent=1")},
		"fan_mode with zone":   {Verb: "fan_mode", Mode: sp("full"), Zone: ip(0)},
		"update with a field":  {Verb: "apply_update", DelayS: ip(1)},
		"update with a hash":   {Verb: "apply_update", TrustHash: sp("dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ")},
		"trust_set, no hash":   {Verb: "trust_set"},
		"trust_set, a field":   {Verb: "trust_set", TrustHash: sp("dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ"), DelayS: ip(1)},
		"hash too short":       {Verb: "trust_set", TrustHash: sp("dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXp")},
		"hash too long":        {Verb: "trust_set", TrustHash: sp("dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQA")},
		"hash padded":          {Verb: "trust_set", TrustHash: sp("dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXp=")},
		"hash with a space":    {Verb: "trust_set", TrustHash: sp("dRtwOuCOmn_fN8xutDqtl ZabcZQcFGbT4ShJzPoXpQ")},
		"hash with a newline":  {Verb: "trust_set", TrustHash: sp("dRtwOuCOmn_fN8xutDqtl\nZabcZQcFGbT4ShJzPoXp")},
		"hash, plain base64":   {Verb: "trust_set", TrustHash: sp("dRtwOuCOmn/fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ")},
		"hash with stray bits": {Verb: "trust_set", TrustHash: sp("dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpR")},
		"hash of an action":    {Verb: "power", Action: sp("shutdown"), DelayS: ip(60), TrustHash: sp("dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ")},
	} {
		if got, err := r.Canonical(); err == nil {
			t.Errorf("%s: canonical form %q", name, got)
		}
	}
}

// vectorModulus is the "n" of the published trust hash vectors: 256 bytes, byte i = (first + step*i) mod 256,
// in base64url without padding. (Not a real RSA modulus; first >= 128 and an odd last byte make it one the
// value checks accept, so the vector can be used as a whole request body.)
func vectorModulus(first, step int) string {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(first + step*i)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// vectorTrust is the proposed trust of the published vectors, with one key and one user and with two of each.
func vectorTrust() (one, two TrustInit) {
	k1 := TrustKey{Kty: "RSA", Kid: "abc123", Alg: "RS256", N: vectorModulus(128, 3), E: "AQAB"}
	k2 := TrustKey{Kty: "RSA", Kid: "next-key", Alg: "RS256", N: vectorModulus(255, -2), E: "AQAB"}
	one = TrustInit{Issuer: "https://id.example.org", ClientID: "3f6c0c0e-0000-4000-8000-000000000000",
		Keys: []TrustKey{k1}, Users: []string{"11111111-2222-4333-8444-555555555555"}}
	two = TrustInit{Issuer: one.Issuer, ClientID: one.ClientID, Keys: []TrustKey{k1, k2},
		Users: []string{"11111111-2222-4333-8444-555555555555", "user-b"}}
	return one, two
}

// TestTrustHashVectors are the worked examples of the protocol description (part1-passkey-protocol.md, section
// 6.2): the panel's implementation must give the same hashes. They were also computed with an independent
// Python hashlib script.
func TestTrustHashVectors(t *testing.T) {
	one, two := vectorTrust()
	if n := one.Keys[0].N; len(n) != 342 || !strings.HasPrefix(n, "gIOGiYyPkpWYm56h") || !strings.HasSuffix(n, "5xdHd6fQ") {
		t.Fatalf("vector modulus 1 = %s", n)
	}
	if n := two.Keys[1].N; len(n) != 342 || !strings.HasPrefix(n, "__37-ff18_Hv7evp") || !strings.HasSuffix(n, "sJBwUDAQ") {
		t.Fatalf("vector modulus 2 = %s", n)
	}
	swapKeys, swapUsers, slash := two, two, one
	swapKeys.Keys = []TrustKey{two.Keys[1], two.Keys[0]}
	swapUsers.Users = []string{two.Users[1], two.Users[0]}
	slash.Issuer += "/"
	withUse, withProof := one, one
	withUse.Keys = []TrustKey{one.Keys[0]}
	withUse.Keys[0].Use = "sig"
	withProof.Approval = &Approval{Token: "x", Entries: []MachineEntry{{Challenge: vectorChallenge(0), Request: "y"}}}
	withID := one
	withID.MachineID = vectorMachineA
	for _, c := range []struct {
		name string
		in   TrustInit
		want string
	}{
		{"one key, one user", one, "dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ"},
		{"two keys, two users", two, "e778SBt_90yBRtGMhF_KR8mLGBMsZXr_NypZnETljAE"},
		{"the keys in the other order", swapKeys, "2TNOVELbekzaS5Pl4-s5zUYxWvSs-EHAsTHHJkR6BCE"},
		{"the users in the other order", swapUsers, "P23yiKxxpRQrQ-oXDqJCfWNms527gd8ZKP3xtuWcMDo"},
		{"the issuer with a trailing slash", slash, "qdHOQEj89t-ZvuxetnIT7sxSZgUnKAUoWgGsms9QjIM"},
		{"a key's use is not part of it", withUse, "dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ"},
		{"the approval sent with it is not part of it", withProof, "dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ"},
		{"the machine id sent with it is not part of it", withID, "dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ"},
	} {
		if got := TrustHash(c.in); got != c.want {
			t.Errorf("%s: trust hash %s, want %s", c.name, got, c.want)
		}
	}
	// the request and the nonce of a list with challenge A for the first vector
	req := TrustSetRequest(one)
	canon, err := req.Canonical()
	if err != nil || canon != "trust_set hash=dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ" || len(canon) != 58 {
		t.Fatalf("request %q, %v", canon, err)
	}
	// with the machine id the set proposes in its entry, and with none (the machine picks one)
	if nonce, err := ApprovalNonce([]MachineEntry{{MachineID: vectorMachineA, Challenge: vectorChallenge(0x00), Request: canon}}); err != nil ||
		nonce != "Nw43E0SfBmQd6YKupw1cRh0KU6h0UIifvU7Vc-fHqxE" {
		t.Errorf("nonce %s, %v", nonce, err)
	}
	if nonce, err := ApprovalNonce([]MachineEntry{{Challenge: vectorChallenge(0x00), Request: canon}}); err != nil ||
		nonce != "M2GarW3FdkX-h16yfmWNrfED-jLx9xQpKa3ZKQ7pN3c" {
		t.Errorf("nonce without a machine id %s, %v", nonce, err)
	}
}

// TestTrustHashIsUnambiguous: moving a byte from one value to the next, or a value from one list to the
// other, changes the hash.
func TestTrustHashIsUnambiguous(t *testing.T) {
	k := func(kid, n string) TrustKey { return TrustKey{Kty: "RSA", Kid: kid, Alg: "RS256", N: n, E: "AQAB"} }
	seen := map[string]string{}
	for name, in := range map[string]TrustInit{
		"base":               {Issuer: "https://a", ClientID: "bc", Keys: []TrustKey{k("k", "nn")}, Users: []string{"u", "v"}},
		"issuer/client":      {Issuer: "https://ab", ClientID: "c", Keys: []TrustKey{k("k", "nn")}, Users: []string{"u", "v"}},
		"kid/n":              {Issuer: "https://a", ClientID: "bc", Keys: []TrustKey{k("kn", "n")}, Users: []string{"u", "v"}},
		"users joined":       {Issuer: "https://a", ClientID: "bc", Keys: []TrustKey{k("k", "nn")}, Users: []string{"uv"}},
		"users split":        {Issuer: "https://a", ClientID: "bc", Keys: []TrustKey{k("k", "nn")}, Users: []string{"u", "v", ""}},
		"no users":           {Issuer: "https://a", ClientID: "bc", Keys: []TrustKey{k("k", "nn")}},
		"no keys":            {Issuer: "https://a", ClientID: "bc", Users: []string{"u", "v"}},
		"key twice":          {Issuer: "https://a", ClientID: "bc", Keys: []TrustKey{k("k", "nn"), k("k", "nn")}, Users: []string{"u", "v"}},
		"other alg":          {Issuer: "https://a", ClientID: "bc", Keys: []TrustKey{{Kty: "RSA", Kid: "k", Alg: "RS512", N: "nn", E: "AQAB"}}, Users: []string{"u", "v"}},
		"other exponent":     {Issuer: "https://a", ClientID: "bc", Keys: []TrustKey{{Kty: "RSA", Kid: "k", Alg: "RS256", N: "nn", E: "Aw"}}, Users: []string{"u", "v"}},
		"a user as a key id": {Issuer: "https://a", ClientID: "bc", Keys: []TrustKey{k("u", "nn")}, Users: []string{"k", "v"}},
		"empty":              {},
	} {
		h := TrustHash(in)
		if len(h) != 43 {
			t.Errorf("%s: hash of %d characters", name, len(h))
		}
		if other, dup := seen[h]; dup {
			t.Errorf("%s and %s have the same trust hash", name, other)
		}
		seen[h] = name
	}
}

// vectorTag is a well-formed tag for the tests of the request text: the 16 bytes first, first+1, ...
func vectorTag(first byte) string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = first + byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// TestSocketTagVectors are worked examples of the tag of a socket: the panel never computes a tag (it copies
// the one the machine shows), but a second implementation, or a reviewer with another tool, must get the same.
// The values were computed with an independent Python hashlib script.
func TestSocketTagVectors(t *testing.T) {
	for _, c := range []struct{ source, socket, name, entity, want string }{
		{"desk-bar", "ch1", "Channel 1", "switch.desk_bar_socket_1", "RPOoLy2ZT8y1WE61UayT2w"},
		{"desk-bar", "ch2", "Channel 2", "switch.desk_bar_socket_2", "7DQdZz8fAGeJXjSXc0mtCA"},
		{"a", "b", "", "", "DmuqP2ZGxLYUyygt6H8MGA"},
		{"desk-bar", "ch1", "Left monitor ☀", "switch.desk_bar_socket_1", "kho1A8vGMOQeEj3VZ-z0ww"},
	} {
		got := SocketTag(c.source, c.socket, c.name, c.entity)
		if got != c.want {
			t.Errorf("SocketTag(%q, %q, %q, %q) = %s, want %s", c.source, c.socket, c.name, c.entity, got, c.want)
		}
		if err := CheckSocketTag(got); err != nil || len(got) != SocketTagLen {
			t.Errorf("the tag %q is not one a request may carry: %v", got, err)
		}
	}
}

// The tag is another one as soon as one of its four parts is: the source, the socket, the name or the entity.
// And no part can be moved into its neighbour (every part has its length in front).
func TestSocketTagChangesWithEveryPart(t *testing.T) {
	base := [4]string{"desk-bar", "ch1", "Channel 1", "switch.desk_bar_socket_1"}
	tag := func(p [4]string) string { return SocketTag(p[0], p[1], p[2], p[3]) }
	seen := map[string]string{tag(base): "the socket itself"}
	try := func(what string, p [4]string) {
		t.Helper()
		got := tag(p)
		if other, dup := seen[got]; dup {
			t.Errorf("%s has the tag of %s", what, other)
		}
		seen[got] = what
	}
	for i, name := range []string{"source", "socket", "name", "entity"} {
		p := base
		p[i] += "x"
		try("another "+name, p)
		p = base
		p[i] = ""
		try("an empty "+name, p)
	}
	// the same bytes, cut at another place
	try("a character moved from the source to the socket", [4]string{"desk-ba", "rch1", base[2], base[3]})
	try("a character moved from the socket to the name", [4]string{base[0], "ch", "1Channel 1", base[3]})
	try("a character moved from the name to the entity", [4]string{base[0], base[1], "Channel ", "1switch.desk_bar_socket_1"})
	try("name and entity swapped", [4]string{base[0], base[1], base[3], base[2]})
	try("source and socket swapped", [4]string{base[1], base[0], base[2], base[3]})
	if tag(base) != tag(base) {
		t.Error("the same socket has two tags")
	}
}

// The exact bytes of the request "socket_set ...", for on and for off, and everything that has no such text.
func TestCanonicalSocketSet(t *testing.T) {
	tag := vectorTag(0x40)
	if tag != "QEFCQ0RFRkdISUpLTE1OTw" {
		t.Fatalf("vector tag = %s", tag)
	}
	long40, long16 := strings.Repeat("s", MaxSocketSource), strings.Repeat("k", MaxSocketID)
	for _, c := range []struct {
		r    ApprovalRequest
		want string
	}{
		{SocketSetRequest("desk-bar", "ch1", "off", tag), "socket_set source=desk-bar socket=ch1 to=off tag=QEFCQ0RFRkdISUpLTE1OTw"},
		{SocketSetRequest("desk-bar", "ch1", "on", tag), "socket_set source=desk-bar socket=ch1 to=on tag=QEFCQ0RFRkdISUpLTE1OTw"},
		{SocketSetRequest("0", "0", "on", tag), "socket_set source=0 socket=0 to=on tag=QEFCQ0RFRkdISUpLTE1OTw"},
		{SocketSetRequest(long40, long16, "off", tag), "socket_set source=" + long40 + " socket=" + long16 + " to=off tag=QEFCQ0RFRkdISUpLTE1OTw"},
	} {
		got, err := c.r.Canonical()
		if err != nil || got != c.want {
			t.Errorf("%q, %v; want %q", got, err, c.want)
		}
		if len(got) > MaxApprovalRequest {
			t.Errorf("%q is longer than an entry may be (%d bytes)", got, len(got))
		}
		if _, err := ApprovalNonce([]MachineEntry{{MachineID: vectorMachineA, Challenge: vectorChallenge(1), Request: got}}); err != nil {
			t.Errorf("%q cannot be an entry: %v", got, err)
		}
	}
	// the longest text there is: 116 bytes, as the limits' comment says
	if longest, _ := SocketSetRequest(long40, long16, "off", tag).Canonical(); len(longest) != 116 {
		t.Errorf("the longest socket_set text is %d bytes, want 116", len(longest))
	}
	for name, r := range map[string]ApprovalRequest{
		"toggle":                    SocketSetRequest("desk-bar", "ch1", "toggle", tag),
		"to in capitals":            SocketSetRequest("desk-bar", "ch1", "OFF", tag),
		"to empty":                  SocketSetRequest("desk-bar", "ch1", "", tag),
		"to with a second field":    SocketSetRequest("desk-bar", "ch1", "on tag=x", tag),
		"to as a run names it":      SocketSetRequest("desk-bar", "ch1", "-", tag),
		"a source of 41 characters": SocketSetRequest(long40+"s", "ch1", "off", tag),
		"a socket of 17 characters": SocketSetRequest("desk-bar", long16+"k", "off", tag),
		"an empty source":           SocketSetRequest("", "ch1", "off", tag),
		"an empty socket":           SocketSetRequest("desk-bar", "", "off", tag),
		"a source with a space":     SocketSetRequest("desk bar", "ch1", "off", tag),
		"a source with an equals":   SocketSetRequest("desk=bar", "ch1", "off", tag),
		"a source in capitals":      SocketSetRequest("Desk-Bar", "ch1", "off", tag),
		"a source that starts -":    SocketSetRequest("-desk", "ch1", "off", tag),
		"a socket that starts -":    SocketSetRequest("desk-bar", "-1", "off", tag),
		"a socket with a slash":     SocketSetRequest("desk-bar", "ch/1", "off", tag),
		"a socket with a dot":       SocketSetRequest("desk-bar", "switch.x", "off", tag),
		"a socket with a newline":   SocketSetRequest("desk-bar", "ch1\n", "off", tag),
		"a tag of 21 characters":    SocketSetRequest("desk-bar", "ch1", "off", tag[:21]),
		"a tag of 23 characters":    SocketSetRequest("desk-bar", "ch1", "off", tag+"A"),
		"a tag with padding":        SocketSetRequest("desk-bar", "ch1", "off", tag[:21]+"="),
		"a tag with a space":        SocketSetRequest("desk-bar", "ch1", "off", tag[:10]+" "+tag[11:]),
		"a tag in plain base64":     SocketSetRequest("desk-bar", "ch1", "off", tag[:10]+"/"+tag[11:]),
		"a tag with stray bits":     SocketSetRequest("desk-bar", "ch1", "off", tag[:21]+"x"),
		"no tag":                    {Verb: "socket_set", Source: sp("desk-bar"), Socket: sp("ch1"), To: sp("off")},
		"no to":                     {Verb: "socket_set", Source: sp("desk-bar"), Socket: sp("ch1"), Tag: sp(tag)},
		"no socket":                 {Verb: "socket_set", Source: sp("desk-bar"), To: sp("off"), Tag: sp(tag)},
		"no source":                 {Verb: "socket_set", Socket: sp("ch1"), To: sp("off"), Tag: sp(tag)},
		"nothing":                   {Verb: "socket_set"},
		"with a delay":              {Verb: "socket_set", Source: sp("desk-bar"), Socket: sp("ch1"), To: sp("off"), Tag: sp(tag), DelayS: ip(0)},
		"with a run":                {Verb: "socket_set", Source: sp("desk-bar"), Socket: sp("ch1"), To: sp("off"), Tag: sp(tag), Run: sp("0123456789abcdef")},
		"with an action":            {Verb: "socket_set", Source: sp("desk-bar"), Socket: sp("ch1"), To: sp("off"), Tag: sp(tag), Action: sp("shutdown")},
		"a power request, a socket": {Verb: "power", Action: sp("shutdown"), DelayS: ip(60), Socket: sp("ch1")},
		"a fan request with a tag":  {Verb: "fan_mode", Mode: sp("full"), Tag: sp(tag)},
		"an update with a source":   {Verb: "apply_update", Source: sp("desk-bar")},
		"a run_go with a source":    {Verb: "run_go", Run: sp("0123456789abcdef"), To: sp("-"), ShutdownDelayS: ip(30), WithinS: ip(600), Source: sp("desk-bar")},
		"the verb plug_switch":      {Verb: "plug_switch", Source: sp("desk-bar"), Socket: sp("ch1"), To: sp("off"), Tag: sp(tag)},
		"the verb socket_toggle":    {Verb: "socket_toggle", Source: sp("desk-bar"), Socket: sp("ch1"), Tag: sp(tag)},
	} {
		if got, err := r.Canonical(); err == nil {
			t.Errorf("%s: canonical form %q", name, got)
		}
	}
	// the sentence for a verb nobody knows is the one of v0.8.0, byte for byte, also now
	_, err := ApprovalRequest{Verb: "socket_toggle"}.Canonical()
	if err == nil || err.Error() != "verb must be fan_set, fan_mode, power, apply_update or trust_set" {
		t.Errorf("an unknown verb is answered %v", err)
	}
	// a socket_set text is never read as a run request
	if r, err := ParseRunRequest("socket_set source=desk-bar socket=ch1 to=off tag=" + tag); err == nil {
		t.Errorf("ParseRunRequest read a socket_set text: %+v", r)
	}
}

// FuzzCanonicalSocketSet: whatever four values get a text, the text is at most MaxApprovalRequest bytes of
// printable ASCII, can be an entry, and reads back as exactly those four values: the verb and four fields,
// split at single spaces, each "name=value" in the fixed order. So no value can smuggle a second field in, and
// two different requests never have one text.
func FuzzCanonicalSocketSet(f *testing.F) {
	tag := vectorTag(0x40)
	f.Add("desk-bar", "ch1", "off", tag)
	f.Add("desk-bar", "ch1", "on", tag)
	f.Add("desk-bar", "ch1", "toggle", tag)
	f.Add("desk bar", "ch1 to=on", "off tag="+tag, tag)
	f.Add("", "", "", "")
	f.Add("a", "b", "on", tag[:21]+"x")
	f.Add("desk-bar\x00", "ch1\n", "on\r", tag+"=")
	f.Fuzz(func(t *testing.T, source, socket, to, tag string) {
		text, err := SocketSetRequest(source, socket, to, tag).Canonical()
		if err != nil {
			return
		}
		if len(text) > MaxApprovalRequest {
			t.Fatalf("%q is %d bytes", text, len(text))
		}
		parts := strings.Split(text, " ")
		if len(parts) != 5 || parts[0] != ApproveSocketSet || parts[1] != "source="+source || parts[2] != "socket="+socket ||
			parts[3] != "to="+to || parts[4] != "tag="+tag {
			t.Fatalf("%q does not read back as (%q, %q, %q, %q)", text, source, socket, to, tag)
		}
		if strings.Count(text, "=") != 4 {
			t.Fatalf("%q has a value with an equals sign", text)
		}
		if to != SocketOn && to != SocketOff {
			t.Fatalf("%q: a direction that is neither on nor off", text)
		}
		if _, err := ApprovalNonce([]MachineEntry{{MachineID: vectorMachineA, Challenge: vectorChallenge(1), Request: text}}); err != nil {
			t.Fatalf("%q cannot be an entry: %v", text, err)
		}
	})
}
