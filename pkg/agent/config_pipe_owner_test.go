package agent

import (
	"path/filepath"
	"testing"
)

// require_helper_pipe_owner (Windows): off unless config.yaml switches it on. Off, the agent only reports a
// helper pipe with an unexpected owner; on, it refuses it (pkg/helper/winpipe, OwnerCheck, where both modes
// are tested).
func TestRequireHelperPipeOwnerIsOffByDefault(t *testing.T) {
	for body, want := range map[string]bool{
		"":                                   false,
		"listen: 100.64.0.10:9101\n":         false,
		"require_helper_pipe_owner: false\n": false,
		"require_helper_pipe_owner: true\n":  true,
	} {
		cfg, err := Parse([]byte(body), filepath.Join(t.TempDir(), "config.yaml"))
		if err != nil || cfg.RequireHelperPipeOwner != want {
			t.Errorf("%q: %v, err %v, want %v", body, cfg != nil && cfg.RequireHelperPipeOwner, err, want)
		}
	}
	if _, err := Parse([]byte("require_helper_pipe_owner: maybe\n"), "config.yaml"); err == nil {
		t.Error("a value that is neither true nor false was accepted")
	}
}
