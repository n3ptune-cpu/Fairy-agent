package collect

import (
	"os"
	"strings"
	"sync"
)

var (
	secretMu    sync.Mutex
	secretNames = map[string]bool{}
)

// HideEnv marks environment variables (tokens, device passwords) that child processes must not inherit.
func HideEnv(names ...string) {
	secretMu.Lock()
	defer secretMu.Unlock()
	for _, n := range names {
		secretNames[strings.ToUpper(n)] = true
	}
}

// minimalEnv is this process's environment without the agent's secrets, for nvidia-smi and other helpers.
func minimalEnv() []string {
	secretMu.Lock()
	defer secretMu.Unlock()
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		ku := strings.ToUpper(k)
		if strings.HasPrefix(ku, "FAIRY_") || secretNames[ku] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// MinimalEnv is the environment for helper processes (exported for the IPMI transports).
func MinimalEnv() []string { return minimalEnv() }
