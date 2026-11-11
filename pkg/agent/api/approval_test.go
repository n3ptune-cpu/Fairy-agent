package api

import (
	"encoding/base64"
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

// TestApprovalNonceVectors are the worked examples of the protocol description (part1-passkey-protocol.md):
// the panel's implementation must give the same three nonces.
func TestApprovalNonceVectors(t *testing.T) {
	a := ApprovalEntry{Challenge: vectorChallenge(0x00), Request: "power action=shutdown delay_s=60"}
	b := ApprovalEntry{Challenge: vectorChallenge(0x80), Request: "fan_set zone=0 percent=50"}
	if a.Challenge != "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" {
		t.Fatalf("vector challenge A = %s", a.Challenge)
	}
	if b.Challenge != "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8" {
		t.Fatalf("vector challenge B = %s", b.Challenge)
	}
	for _, c := range []struct {
		name    string
		entries []ApprovalEntry
		want    string
	}{
		{"one entry", []ApprovalEntry{a}, "iIJWRjPBb50gLAFJ9H9myD3VD4DyAz4P1gDUQvSpFfs"},
		{"two entries", []ApprovalEntry{a, b}, "DQDax65TnNgoLbC3-4jWKUMPNImUsC8GzmuOlb6Y1DQ"},
		{"two entries, other order", []ApprovalEntry{b, a}, "7ccQOntkRjlIF_95rwZ_Frf5s9ueuvVLigbjdltx1Po"},
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

// TestApprovalNonceIsUnambiguous: moving a byte from one part to the next, or splitting an entry, changes the
// nonce; nothing a request may contain acts as a separator.
func TestApprovalNonceIsUnambiguous(t *testing.T) {
	c1, c2 := vectorChallenge(1), vectorChallenge(2)
	seen := map[string]string{}
	for name, e := range map[string][]ApprovalEntry{
		"ab":      {{c1, "ab"}},
		"a,b":     {{c1, "a"}, {c2, "b"}},
		"abc":     {{c1, "abc"}},
		"ab c2":   {{c2, "ab"}},
		"ab,same": {{c1, "ab"}, {c2, "ab"}},
		"a b":     {{c1, "a b"}},
		"a  b":    {{c1, "a  b"}},
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

func TestApprovalNonceRefuses(t *testing.T) {
	ok := vectorChallenge(0)
	many := make([]ApprovalEntry, MaxApprovalEntries+1)
	for i := range many {
		many[i] = ApprovalEntry{vectorChallenge(byte(i)), "apply_update"}
	}
	for name, e := range map[string][]ApprovalEntry{
		"empty list":          nil,
		"too many":            many,
		"short challenge":     {{ok[:42], "apply_update"}},
		"long challenge":      {{ok + "A", "apply_update"}},
		"padded challenge":    {{ok[:42] + "=", "apply_update"}},
		"standard alphabet":   {{strings.Repeat("+", 43), "apply_update"}},
		"stray bits":          {{ok[:42] + "9", "apply_update"}}, // the last character carries 4 bits that must be 0
		"line break inside":   {{ok[:20] + "\n" + ok[21:], "apply_update"}},
		"line break for bits": {{ok[:42] + "\n", "apply_update"}},
		"challenge twice":     {{ok, "apply_update"}, {ok, "fan_mode mode=full"}},
		"empty request":       {{ok, ""}},
		"long request":        {{ok, strings.Repeat("a", MaxApprovalRequest+1)}},
		"newline in request":  {{ok, "apply_update\n"}},
		"NUL in request":      {{ok, "apply\x00update"}},
		"non-ASCII in reques": {{ok, "apply_updaté"}},
	} {
		if n, err := ApprovalNonce(e); err == nil {
			t.Errorf("%s: accepted, nonce %s", name, n)
		}
	}
	if _, err := ApprovalNonce(many[:MaxApprovalEntries]); err != nil {
		t.Errorf("%d entries: %v", MaxApprovalEntries, err)
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
	withProof.Approval = &Approval{Token: "x", Entries: []ApprovalEntry{{Challenge: vectorChallenge(0), Request: "y"}}}
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
	if nonce, err := ApprovalNonce([]ApprovalEntry{{Challenge: vectorChallenge(0x00), Request: canon}}); err != nil ||
		nonce != "iFRKUeYLgHVi_6skMmsg1vyhKKuVnD00CPc6y7pAAY0" {
		t.Errorf("nonce %s, %v", nonce, err)
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
