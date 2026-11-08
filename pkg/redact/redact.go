// Package redact removes secrets from process command lines before they leave the agent.
package redact

import (
	"regexp"
	"unicode/utf8"
)

const secretWords = `(?:password|passwd|pass|pwd|token|secret|api[-_]?key|apikey|access[-_]?key|private[-_]?key|key|auth|credentials?)`

var rules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// --password=x, -token x, --api-key=x (a value starting with "-" is the next flag, not a secret)
	{regexp.MustCompile(`(?i)(--?[\w-]*` + secretWords + `[\w-]*)(=|\s+)([^\s-]\S*)`), "${1}${2}***"},
	// FOO_TOKEN=x, password=x, key=x (env-style / query-style)
	{regexp.MustCompile(`(?i)\b([\w.-]*` + secretWords + `[\w.-]*)=([^\s&]+)`), "${1}=***"},
	// scheme://user:pass@host
	{regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+):[^@\s/]+@`), "${1}:***@"},
	// Authorization: Bearer xyz / Basic xyz
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`), "${1} ***"},
}

// Cmdline redacts secrets and truncates to maxLen characters (with an ellipsis).
func Cmdline(cmd string, maxLen int) string {
	for _, r := range rules {
		cmd = r.re.ReplaceAllString(cmd, r.repl)
	}
	if maxLen <= 0 {
		maxLen = 200
	}
	if utf8.RuneCountInString(cmd) <= maxLen {
		return cmd
	}
	return string([]rune(cmd)[:maxLen-1]) + "…"
}
