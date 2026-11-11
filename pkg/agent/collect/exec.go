package collect

import (
	"context"
	"os"
	"os/exec"
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

// Command is exec.CommandContext with MinimalEnv as the program's environment: what the running agent and the
// helper use to start a system program (systemctl, busctl, PowerShell), so that none of them is handed the
// device secrets of env_file or a FAIRY_ variable. Everything else of the environment is passed on.
func Command(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = minimalEnv()
	return cmd
}
