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

// I36: the clean-up step used to accept codes that then could never pair (33, 35 or 38 characters, a line break
// inside, letters outside ASCII that upper-case into A-Z). Whatever Normalize accepts is now exactly 32
// characters A-Z / 2-7.
func TestNormalizeIsStrict(t *testing.T) {
	c := "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U" // 20 bytes "abcdefghijklmnopqrst"
	for _, ok := range []string{c, Group(c), strings.ToLower(Group(c)), "  " + Group(c) + "\r\n", "\t" + c + "\n", strings.ReplaceAll(Group(c), "-", " "),
		c + "\u00a0", "\u2003" + c} {
		n, err := Normalize(ok)
		if err != nil || n != c {
			t.Errorf("%q: %q %v", ok, n, err)
		}
	}
	for _, bad := range []string{
		c + "A", c + "AAA", c + "AAAAAA", c + "AA", c + c, // 33, 35, 38, 34, 64 characters
		c[:10] + "\n" + c[10:], c[:10] + "\r\n" + c[10:], c[:16] + "\n", // a line break inside, or too short with one
		"\u017f" + c[1:], "\u0131" + c[1:], "\u212a" + c[1:], // long s, dotless i, Kelvin sign: not ASCII
		c[:31] + "\u00e9", c[:31] + "=", c[:31] + "1", c[:31] + "8", c[:31] + "0", c[:5] + "=" + c[5:], c[:31] + "_", c[:31],
		c[:8] + "\x00" + c[8:], c[:8] + "\u00a0" + c[8:], c[:8] + "\u2003" + c[8:], strings.Repeat("-", 40), "\xff" + c[1:],
	} {
		if n, err := Normalize(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, n)
		}
		if _, err := Proof(bad); err == nil {
			t.Errorf("%q got a proof", bad)
		}
	}
}

func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U", "mfrg-gzdf-mztw-q2lk-nnwg-23tp-obyx-e43u\n", "", "AAAA\nAAAA", "\u017fAAA"} {
		f.Add(s)
	}
	ok := regexp.MustCompile(`^[A-Z2-7]{32}$`)
	f.Fuzz(func(t *testing.T, s string) {
		n, err := Normalize(s)
		if err != nil {
			return
		}
		if !ok.MatchString(n) {
			t.Fatalf("%q normalised to %q", s, n)
		}
		if again, err := Normalize(Group(n)); err != nil || again != n {
			t.Fatalf("not stable: %q -> %q -> %q %v", s, n, again, err)
		}
	})
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
