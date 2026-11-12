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
