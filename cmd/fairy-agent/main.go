// Command fairy-agent reports this machine's metrics to the Fairy panel. See AGENT.md.
//
//	fairy-agent run [--config path]        serve (also what the Windows service and the systemd unit run)
//	fairy-agent install [--config path] [--account LocalService|LocalSystem]   Windows: install the service
//	fairy-agent uninstall                  Windows: remove the service (config and tokens stay)
//	fairy-agent check-config [--config path]
//	fairy-agent gen-token                  print a new random token (for the token files)
//	fairy-agent apply-update [--config path]  install the release the agent staged (run by the updater, see AGENT.md)
//	fairy-agent setup-self-update          Windows: give the service the rights self-update needs
//	fairy-agent version
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

// Set by the release workflow with -ldflags "-X main.version=... -X main.releaseKey=...". releaseKey is the
// base64 ed25519 public key that signs releases; without it the agent refuses to update itself.
var (
	version    = "dev"
	releaseKey = ""
)

const usage = `fairy-agent: reports this machine's metrics to the Fairy panel (see AGENT.md)

  fairy-agent run [--config PATH]           run in the foreground (the service and systemd unit run this)
  fairy-agent install [--config PATH] [--account LocalService|LocalSystem]
                                            Windows: install and configure the "fairy-agent" service
  fairy-agent uninstall                     Windows: remove the service (config and tokens are kept)
  fairy-agent check-config [--config PATH]  check config.yaml and the token files, then exit
  fairy-agent gen-token                     print a new random token
  fairy-agent apply-update [--config PATH]  install the update the agent staged (started by the panel's
                                            Update button through fairy-agent-update.service / the service)
  fairy-agent setup-self-update             Windows: give the service the rights self-update needs
  fairy-agent version
`

func main() {
	if isService() { // started by the Windows service manager
		os.Exit(runService())
	}
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", agent.DefaultConfigPath(), "path of config.yaml")
	account := fs.String("account", "LocalService", "Windows service account: LocalService or LocalSystem")
	switch cmd {
	case "run":
		_ = fs.Parse(args)
		os.Exit(runForeground(*cfgPath))
	case "install":
		_ = fs.Parse(args)
		if err := install(*cfgPath, *account); err != nil {
			fmt.Fprintln(os.Stderr, "install failed:", err)
			os.Exit(1)
		}
	case "uninstall":
		_ = fs.Parse(args)
		if err := uninstall(); err != nil {
			fmt.Fprintln(os.Stderr, "uninstall failed:", err)
			os.Exit(1)
		}
	case "check-config":
		_ = fs.Parse(args)
		cfg, err := agent.Load(*cfgPath)
		if err == nil {
			_, err = agent.LoadEnvFile(cfg.EnvFile)
		}
		if err == nil {
			_, err = cfg.LoadTokens()
		}
		if err == nil {
			_, err = agent.NewRelay(cfg.PowerSources, cfg.UPS)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "config problem:", err)
			os.Exit(1)
		}
		fmt.Println("config OK:", *cfgPath)
	case "gen-token":
		tok, err := newToken()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(tok)
	case "apply-update":
		_ = fs.Parse(args)
		os.Exit(applyUpdate(*cfgPath))
	case "setup-self-update":
		_ = fs.Parse(args)
		if err := setupSelfUpdate(*cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "setup-self-update failed:", err)
			os.Exit(1)
		}
	case "version", "--version", "-v":
		signed := "signed-release key: none (local build, no self-update)"
		if releaseKey != "" {
			signed = "signed-release key: built in"
		}
		fmt.Println("fairy-agent", version, runtime.GOOS+"/"+runtime.GOARCH, "-", signed)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// newToken is 32 random bytes, base64url (43 characters).
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// tune keeps the agent small: it never needs more than two threads or much heap.
func tune() {
	runtime.GOMAXPROCS(min(2, runtime.NumCPU()))
	debug.SetGCPercent(50)
	debug.SetMemoryLimit(24 << 20)
	lowerPriority()
}

// setupLogging logs to the configured file (Windows default) and, when interactive, to stderr.
func setupLogging(cfg *agent.Config, interactive bool) (io.Closer, error) {
	var w io.Writer = os.Stderr
	var closer io.Closer
	if cfg.LogFile != "" {
		f, err := agent.OpenLog(cfg.LogFile, 5<<20)
		if err != nil {
			return nil, fmt.Errorf("log_file: %w", err)
		}
		closer = f
		w = f
		if interactive {
			w = io.MultiWriter(f, os.Stderr)
		}
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})))
	return closer, nil
}

// serve loads the config and runs the agent until ctx ends.
func serve(ctx context.Context, cfgPath string, interactive bool) error {
	tune()
	cfg, err := agent.Load(cfgPath)
	if err != nil {
		return err
	}
	closer, err := setupLogging(cfg, interactive)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer.Close()
	}
	if err := agent.Run(ctx, cfg, agent.Build{Version: version, ReleaseKey: releaseKey}); err != nil {
		slog.Error("fairy-agent cannot run", "error", err.Error())
		return err
	}
	return nil
}

func runForeground(cfgPath string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, cfgPath, true); err != nil {
		fmt.Fprintln(os.Stderr, "fairy-agent:", err)
		return 1
	}
	return 0
}

// applyUpdate installs the staged release: verify again, swap, restart, health-check, roll back on failure.
func applyUpdate(cfgPath string) int {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "apply-update runs as root from fairy-agent-update.service (the agent starts it); see AGENT.md")
		return 1
	}
	cfg, err := agent.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy-agent apply-update:", err)
		return 1
	}
	closer, err := setupLogging(cfg, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy-agent apply-update:", err)
		return 1
	}
	if closer != nil {
		defer closer.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	slog.Warn("apply-update: starting", "installed", version)
	if err := agent.ApplyUpdate(ctx, cfg, version, releaseKey); err != nil {
		fmt.Fprintln(os.Stderr, "fairy-agent apply-update:", err)
		return 1
	}
	return 0
}
