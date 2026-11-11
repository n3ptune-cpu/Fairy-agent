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
	} {
		if got, err := r.Canonical(); err == nil {
			t.Errorf("%s: canonical form %q", name, got)
		}
	}
}
