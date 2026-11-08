package enroll

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestCode(t *testing.T) {
	c, err := NewCode()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$`).MatchString(c) {
		t.Fatalf("code %q", c)
	}
	n, err := Normalize(" " + strings.ToLower(c) + " ")
	if err != nil || n != strings.ReplaceAll(c, "-", "") || Group(n) != c {
		t.Fatalf("normalize: %q %v", n, err)
	}
	c2, _ := NewCode()
	if c2 == c {
		t.Fatal("two codes are the same")
	}
	for _, bad := range []string{"", "ABCD", strings.Repeat("A", 31), strings.Repeat("1", 32), c + "AAAA"} {
		if _, err := Normalize(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestProofAndCheck(t *testing.T) {
	c, _ := NewCode()
	p1, err := Proof(c)
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := Proof(strings.ToLower(strings.ReplaceAll(c, "-", "")))
	if p1 != p2 || len(p1) != 64 || strings.Contains(p1, strings.ReplaceAll(c, "-", "")) {
		t.Fatalf("proof: %q %q", p1, p2)
	}
	v := Verifier(p1)
	if !Check(p1, v) || Check(p2+"0", v) || Check("", v) || Check(p1, "zz") || Check(p1, "") {
		t.Fatal("check")
	}
	other, _ := NewCode()
	po, _ := Proof(other)
	if Check(po, v) {
		t.Fatal("another code passes")
	}
	if _, err := Proof("nope"); err == nil {
		t.Fatal("bad code got a proof")
	}
}

func TestState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pairing.json")
	if _, err := ReadState(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	s := State{Version: 1, Verifier: "ab", Panel: "100.64.0.1", CreatedAt: now.Unix(), ExpiresAt: now.Add(TTL).Unix()}
	if err := WriteState(path, s); err != nil {
		t.Fatal(err)
	}
	got, err := ReadState(path)
	if err != nil || got != s {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if !got.Active(now) || got.Active(now.Add(TTL)) {
		t.Fatal("active window")
	}
	if !strings.Contains(got.Describe(now), "waiting for the panel") || !strings.Contains(got.Describe(now.Add(TTL)), "expired") {
		t.Fatal(got.Describe(now))
	}
	got.Closed = "paired"
	if got.Active(now) || !strings.Contains(got.Describe(now), "paired") {
		t.Fatal("closed state still active")
	}
	if st, _ := os.Stat(path); st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("mode %v", st.Mode())
	}
}
