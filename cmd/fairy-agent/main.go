// Command fairy-agent reports this machine's metrics to the Fairy panel. See AGENT.md.
//
//	fairy-agent run [--config path]        serve (also what the Windows service and the systemd unit run)
//	fairy-agent install [--config path] [--helper]   Windows: install the service (and the elevated helper)
//	fairy-agent uninstall                  Windows: remove the service (config and tokens stay)
//	fairy-agent check-config [--config path]
//	fairy-agent config get|set|show ...      read or change one setting of config.yaml (set: root / Administrator)
//	fairy-agent join (--code-stdin | --code CODE) --panel IP [--pair-v2] [...]  the machine side of the panel's Add host (the installer runs it)
//	fairy-agent pair-status                is the panel paired yet (0 yes, 3 waiting, 1 no code / expired)
//	fairy-agent verify-release DIR         check a downloaded release's signature and hashes (the installer)
//	fairy-agent gen-token                  print a new random token (for the token files)
//	fairy-agent update [--check] [--yes] [--force]  install the latest signed release by hand (root / Administrator)
//	fairy-agent apply-update [--config path]  install the release the agent staged (run by the updater, see AGENT.md)
//	fairy-agent fans-auto                  hand the fans back to the BMC's automatic mode (systemd runs it after the agent ends)
//	fairy-agent setup-self-update [--helper]  Windows: move to NT SERVICE\fairy-agent, permissions, updater, helper
//	fairy-agent helper-status              Windows: the helper service and what it serves
//	fairy-agent remove-helper              Windows: remove the helper service
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
  fairy-agent install [--config PATH] [--helper]
                                            Windows: install the "fairy-agent" service (account
                                            NT SERVICE\fairy-agent); --helper also installs the elevated
                                            fairy-agent-helper service (Core Temp, IPMI, fans, power control).
                                            --account LocalSystem still works: it now means --helper
  fairy-agent uninstall                     Windows: remove the service (config and tokens are kept)
  fairy-agent check-config [--config PATH]  check config.yaml and the token files, then exit
  fairy-agent config get <setting> | set <setting> <value> | show  [--config PATH]
                                            read or change config.yaml (keeps its comments; set checks the
                                            result like check-config, needs root / Administrator), e.g.
                                            fairy-agent config set fan_control.auto_mode standard
  fairy-agent secret set NAME [--config PATH]
                                            store a password (e.g. a BMC's) in env_file; asks for it (no echo)
                                            or reads one line from stdin, never from the command line
  fairy-agent bmc-relay add --id ID --host IP --username USER --password-env NAME [--cipher-suite N] ...
                                            add a BMC power-on relay target (see AGENT.md)
  fairy-agent join (--code-stdin | --code CODE) --panel IP [--pair-v2] [--power-control] [--self-update] [--wol]
                   [--ups] [--ups-name NAME] [--coretemp] [--ipmi] [--proxmox]
                                            the machine side of the panel's "Add host" (install.sh / install.ps1
                                            run it): tokens, the chosen features, the one-time join code.
                                            --code-stdin reads the code from the first line of standard input;
                                            without it and --code, the code is taken from the environment
                                            variable FAIRY_JOIN_CODE. A code given with --code can be read by
                                            every local user while join runs.
                                            --pair-v2: the agent answers the panel encrypted, and only a panel
                                            that proves it has this code (the panel's command says when)
  fairy-agent pair-status                   has the panel paired yet (exit 0 yes, 3 still waiting, 1 no)
  fairy-agent verify-release DIR            check SHA256SUMS' signature and the files in DIR (installers)
  fairy-agent gen-token                     print a new random token
  fairy-agent update [--check] [--yes] [--force] [--config PATH]
                                            install the latest signed release now (root / Administrator):
                                            download, verify, swap (keeps .old), restart, roll back on failure
  fairy-agent apply-update [--config PATH]  install the update the agent staged (started by the panel's
                                            Update button through fairy-agent-update.service (Linux) or the
                                            fairy-agent-update service (Windows))
  fairy-agent fans-auto                     with fan control on: hand the fans back to the BMC's automatic mode if
                                            a fixed speed may be set (what the agent does itself when it stops).
                                            Linux: fairy-agent.service runs it after the agent has ended for any
                                            reason (ExecStopPost). No options: it reads the installed config.yaml
  fairy-agent setup-self-update [--helper]  Windows (Administrator), safe to run again: moves the agent to its
                                            own account NT SERVICE\fairy-agent (from LocalService or LocalSystem),
                                            sets the folder permissions, the fairy-agent-update service, and the
                                            fairy-agent-helper service when config.yaml needs it (or --helper)
  fairy-agent helper-status                 Windows (Administrator): accounts of both services, is the helper
                                            running, what it serves (exit 0 running, 3 not running)
  fairy-agent remove-helper                 Windows (Administrator): stop (fans back to the BMC) and remove the
                                            helper service
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
	account := fs.String("account", "", "deprecated: LocalSystem now means --helper")
	withHelper := fs.Bool("helper", false, "Windows: install the elevated fairy-agent-helper service")
	check := fs.Bool("check", false, "update: only show the installed and the latest version")
	yes := fs.Bool("yes", false, "update: do not ask before installing")
	force := fs.Bool("force", false, "update: also reinstall the same version or install an older one")
	switch cmd {
	case "run":
		_ = fs.Parse(args)
		os.Exit(runForeground(*cfgPath))
	case "install":
		_ = fs.Parse(args)
		if err := install(*cfgPath, *account, *withHelper); err != nil {
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
			err = checkConfig(cfg)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "config problem:", err)
			os.Exit(1)
		}
		fmt.Println("config OK:", *cfgPath)
	case "config":
		os.Exit(configCmd(args, os.Stdout, os.Stderr))
	case "secret":
		os.Exit(secretCmd(args, os.Stdin, os.Stdout, os.Stderr))
	case "bmc-relay":
		os.Exit(bmcRelayCmd(args, os.Stdout, os.Stderr))
	case "join":
		os.Exit(joinCmd(args, os.Stdout, os.Stderr))
	case "pair-status":
		os.Exit(pairStatus(args, os.Stdout, os.Stderr))
	case "verify-release":
		os.Exit(verifyRelease(args, os.Stdout, os.Stderr))
	case "gen-token":
		tok, err := newToken()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(tok)
	case "update":
		_ = fs.Parse(args)
		os.Exit(localUpdate(*cfgPath, *check, *yes, *force))
	case "apply-update":
		_ = fs.Parse(args)
		os.Exit(applyUpdate(*cfgPath))
	case "fans-auto":
		os.Exit(fansAutoCmd(args, os.Stdout, os.Stderr))
	case "setup-self-update":
		_ = fs.Parse(args)
		if err := setup(*cfgPath, *withHelper, true); err != nil {
			fmt.Fprintln(os.Stderr, "setup-self-update failed:", err)
			os.Exit(1)
		}
	case "helper-status":
		os.Exit(helperStatus())
	case "remove-helper":
		if err := removeHelper(); err != nil {
			fmt.Fprintln(os.Stderr, "remove-helper failed:", err)
			os.Exit(1)
		}
	case "helper":
		fmt.Fprintln(os.Stderr, "fairy-agent helper runs only as the fairy-agent-helper Windows service (Start-Service fairy-agent-helper)")
		os.Exit(2)
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
	// one message at most 30 times a minute (repeats are counted, not written): nothing can flood the log
	slog.SetDefault(slog.New(agent.RateLimitLog(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}), 30)))
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
	checkProgramFolder()
	// Windows: a LocalSystem service moves itself to NT SERVICE\fairy-agent (built before Run, which clears
	// the update stage the migration looks at)
	mig := newMigrator(cfgPath, cfg)
	// Windows: NT SERVICE\fairy-agent reads performance counters only as a member of Performance Monitor Users
	go counterAccessKick(ctx)
	if err := agent.Run(ctx, cfg, agent.Build{Version: version, ReleaseKey: releaseKey, Migration: mig}); err != nil {
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return applyUpdateCtx(ctx, cfgPath)
}

func applyUpdateCtx(ctx context.Context, cfgPath string) int {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "apply-update runs as root from fairy-agent-update.service (the agent starts it); see AGENT.md")
		return 1
	}
	cfg, err := agent.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy-agent apply-update:", err)
		return 1
	}
	if p := agent.InstallerLogPath(cfg); p != "" {
		cfg.LogFile = p // Windows: LocalSystem writes only where the agent's account cannot change anything
	}
	closer, err := setupLogging(cfg, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy-agent apply-update:", err)
		return 1
	}
	if closer != nil {
		defer closer.Close()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	// Windows: the agent moved its service to NT SERVICE\fairy-agent and started this service to restart and
	// check it; that is all this run does (the state file is administrators-only)
	if handled, code := superviseMigration(ctx, cfg, cfgPath); handled {
		return code
	}
	// Windows, nothing staged: the agent asked for its account to read performance counters (counterAccessKick)
	if handled, code := counterAccessRun(ctx, cfg); handled {
		return code
	}
	slog.Warn("apply-update: starting", "installed", version)
	if err := agent.ApplyUpdate(ctx, cfg, version, releaseKey); err != nil {
		fmt.Fprintln(os.Stderr, "fairy-agent apply-update:", err)
		return 1
	}
	return 0
}

// fansAutoCmd is `fairy-agent fans-auto`. It does one fixed thing and takes no arguments at all: no path, mode
// or program a caller writes on the command line can reach the BMC or be run. It always reads the installed
// config.yaml (the one place the agent's own settings are).
func fansAutoCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "fairy-agent fans-auto takes no arguments (it reads "+agent.DefaultConfigPath()+")")
		return 2
	}
	// Windows, typed by an administrator: config.yaml names the BMC and the secrets file; see adminDataDirTrusted
	if err := adminDataDirTrusted(agent.DefaultConfigPath()); err != nil {
		fmt.Fprintln(stderr, "fairy-agent fans-auto:", err)
		return 1
	}
	return fansAuto(agent.DefaultConfigPath(), stdout, stderr)
}

// fansAuto hands the fans of the agent configured in cfgPath back to the BMC's automatic mode (agent.FansAuto).
func fansAuto(cfgPath string, stdout, stderr io.Writer) int {
	cfg, err := agent.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "fairy-agent fans-auto:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*agent.FanStopLimit)
	defer cancel()
	mode, done, err := agent.FansAuto(ctx, cfg)
	switch {
	case err != nil:
		fmt.Fprintln(stderr, "fairy-agent fans-auto: could not hand the fans back to the BMC:", err)
		return 1
	case !done:
		fmt.Fprintln(stdout, "fan control is not switched on in config.yaml: nothing to do")
	default:
		fmt.Fprintln(stdout, "fans are in the BMC's mode:", mode)
	}
	return 0
}

// localUpdate is `fairy-agent update`: like the panel's Update button, run by hand on the machine.
func localUpdate(cfgPath string, check, yes, force bool) int {
	if !check && runtime.GOOS == "linux" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "fairy-agent update must run as root (it replaces the binary and restarts fairy-agent); --check works as any user")
		return 1
	}
	// Windows: this runs as Administrator and config.yaml decides which repository is asked and which token
	// file is read to check the restarted agent. A config.yaml that someone else could have written is not
	// read at all (the same check as the updater service and apply-update; see adminDataDirTrusted).
	if err := adminDataDirTrusted(cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "fairy-agent update:", err)
		return 1
	}
	cfg, err := agent.Load(cfgPath)
	if err != nil {
		cfg = nil // no or unreadable config: official repository, service-only health check
		if !check {
			fmt.Fprintln(os.Stderr, "note:", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	cli, err := agent.NewUpdateCLI(ctx, cfg, version, releaseKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy-agent update:", err)
		return 1
	}
	cli.Check, cli.Yes, cli.Force = check, yes, force
	if err := cli.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "fairy-agent update:", err)
		return 1
	}
	return 0
}
