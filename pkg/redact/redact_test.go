package redact

import (
	"strings"
	"testing"
)

func TestCmdlineRedaction(t *testing.T) {
	cases := [][2]string{
		{"mysql -u root --password=hunter2 -h db", "hunter2"},
		{"app --token abc123 --verbose", "abc123"},
		{"API_KEY=xyz123 ./run.sh", "xyz123"},
		{"curl https://bob:s3cr3t@example.com/x", "s3cr3t"},
		{"curl -H 'Authorization: Bearer eyJabc.def'", "eyJabc"},
		{"rclone sync --s3-secret-access-key AKIAXYZ remote:", "AKIAXYZ"},
		{"llama-server -m /models/qwen3-30b-a3b-q4_k_m.gguf -ngl 99 --split-mode layer -c 32768 --host 100.64.0.12 --port 8080 --api-key sk-live-123", "sk-live-123"},
		{"app --token --password secret", "secret"}, // a flag value never swallows the next secret flag
	}
	for _, c := range cases {
		red := Cmdline(c[0], 200)
		if strings.Contains(red, c[1]) || !strings.Contains(red, "***") {
			t.Errorf("%q -> %q", c[0], red)
		}
	}
	if got := Cmdline("llama-server -m /models/q.gguf -ngl 99 --split-mode layer --port 8080 --api-key sk-1", 200); got !=
		"llama-server -m /models/q.gguf -ngl 99 --split-mode layer --port 8080 --api-key ***" {
		t.Fatal(got)
	}
	if got := Cmdline("app --token -v", 200); got != "app --token -v" {
		t.Fatal(got)
	}
	if n := len([]rune(Cmdline(strings.Repeat("x", 500), 200))); n != 200 {
		t.Fatal(n)
	}
}
