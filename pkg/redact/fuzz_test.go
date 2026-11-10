package redact

// Fuzz targets from the independent review of the fixes: the command-line filter.
// They run on their seeds with every `go test`; `go test -fuzz <name>` searches further.

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Whatever the arguments are: no panic, the result is at most maxLen characters, the work is bounded, and a
// Fairy join code or a secret given as --password=... / FAIRY_JOIN_CODE=... never comes through.
func FuzzArgs(f *testing.F) {
	const code = "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567"
	f.Add("fairy-agent", "join", "--code", "x", "--panel 100.64.0.1")
	f.Add("sh", "install.sh", "--join", "y", "")
	f.Add("curl", "-u", "admin:", "https://a:b@c/d?token=", "-H Authorization: Bearer ")
	f.Add("mysql", "-p", "", "-uroot", "db")
	f.Fuzz(func(t *testing.T, a, b, c, d, e string) {
		const secret = "S3cr3tValue9"
		args := []string{a, b, "--password=" + secret, c, code, d, "FAIRY_JOIN_CODE=" + code, e}
		start := time.Now()
		out := Args(args, 300)
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("%v for %d bytes", el, len(a)+len(b)+len(c)+len(d)+len(e))
		}
		if n := utf8.RuneCountInString(out); n > 300 {
			t.Fatalf("%d characters", n)
		}
		if strings.Contains(out, secret) {
			t.Fatalf("--password=VALUE came through: %q <- %q", out, args)
		}
		if strings.Contains(out, code) || strings.Contains(out, strings.ReplaceAll(code, "-", "")) {
			t.Fatalf("the join code came through: %q <- %q", out, args)
		}
		_ = Cmdline(strings.Join(args, " "), 300)
	})
}
