package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/configedit"
)

const configUsage = `usage:
  fairy-agent config get <setting> [--config PATH]          the value the agent uses (default if not set)
  fairy-agent config set <setting> <value> [--config PATH]  change config.yaml (root / Administrator)
  fairy-agent config show [--config PATH]                   every setting with the value the agent uses
Settings are written with dots, e.g. fan_control.auto_mode; lists as "a, b" or [a, b].
`

// checkConfig is check-config's test of a loaded config: the env file, the tokens and the relayed devices.
func checkConfig(cfg *agent.Config) error {
	if _, err := agent.LoadEnvFile(cfg.EnvFile); err != nil {
		return err
	}
	if _, err := cfg.LoadTokens(); err != nil {
		return err
	}
	_, err := agent.NewRelay(cfg.PowerSources, cfg.UPS)
	return err
}

// configNotes are what check-config says about a config that loads but will not do what its owner expects.
func configNotes(cfg *agent.Config) []string {
	var notes []string
	for _, id := range cfg.BMCRelay.RedfishWithoutFingerprint() {
		notes = append(notes, "note: bmc_relay target "+id+" has no tls_fingerprint. The agent sends the BMC's user name and password only to "+
			"the certificate named there, so nothing is sent to this BMC yet. Ask for it once (the panel's power-on through the BMC): "+
			"the answer names the fingerprint the BMC shows. Compare it with the certificate in the BMC's own web interface, then set "+
			"tls_fingerprint for this target in config.yaml and restart the agent. (A target that worked before this version keeps working: "+
			"its certificate was learned then.)")
	}
	return notes
}

// splitConfigArgs takes --config PATH (or --config=PATH, -config) from anywhere in args.
func splitConfigArgs(args []string) (pos []string, cfgPath string, err error) {
	cfgPath = agent.DefaultConfigPath()
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return append(pos, args[i+1:]...), cfgPath, nil
		case a == "--config" || a == "-config":
			if i+1 >= len(args) {
				return nil, "", errors.New("--config needs a path")
			}
			cfgPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--config=") || strings.HasPrefix(a, "-config="):
			_, cfgPath, _ = strings.Cut(a, "=")
		default:
			pos = append(pos, a)
		}
	}
	return pos, cfgPath, nil
}

func restartHint() string {
	if runtime.GOOS == "windows" {
		return "Restart-Service fairy-agent"
	}
	return "systemctl restart fairy-agent"
}

// configCmd is `fairy-agent config ...`; it returns the exit code.
func configCmd(args []string, stdout, stderr io.Writer) int {
	pos, cfgPath, err := splitConfigArgs(args)
	if err != nil || len(pos) == 0 {
		if err != nil {
			fmt.Fprintln(stderr, err)
		}
		fmt.Fprint(stderr, configUsage)
		return 2
	}
	switch {
	case pos[0] == "show" && len(pos) == 1:
		cfg, err := agent.Load(cfgPath)
		if err != nil {
			fmt.Fprintln(stderr, "config problem:", err)
			return 1
		}
		fmt.Fprintln(stdout, "#", cfgPath, "(values the agent uses; defaults included)")
		for _, s := range configedit.Settings() {
			fmt.Fprintf(stdout, "%s: %s\n", s.Key, configedit.Effective(cfg, s))
		}
		return 0
	case pos[0] == "get" && len(pos) == 2:
		s, err := configedit.Lookup(pos[1])
		if err != nil && !strings.Contains(err.Error(), "edit config.yaml") {
			fmt.Fprintln(stderr, err)
			return 1
		}
		cfg, err := agent.Load(cfgPath)
		if err != nil {
			fmt.Fprintln(stderr, "config problem:", err)
			return 1
		}
		fmt.Fprintln(stdout, configedit.Effective(cfg, s))
		return 0
	case pos[0] == "set" && len(pos) == 3:
		// Windows: nothing is changed in a folder or a config.yaml that someone other than administrators and
		// SYSTEM could have written (adminDataDirTrusted). Here and not in configSet: join calls configSet
		// after it has made this check itself.
		if err := adminDataDirTrusted(cfgPath); err != nil {
			fmt.Fprintln(stderr, "fairy-agent config set:", err)
			return 1
		}
		if err := configSet(cfgPath, pos[1], pos[2], stdout); err != nil {
			fmt.Fprintln(stderr, "fairy-agent config set:", err)
			return 1
		}
		return 0
	}
	fmt.Fprint(stderr, configUsage)
	return 2
}

func configSet(cfgPath, key, raw string, stdout io.Writer) error {
	s, err := configedit.Lookup(key)
	if err != nil {
		return err
	}
	v, err := configedit.ParseValue(s, raw)
	if err != nil {
		return err
	}
	if !isAdmin() {
		if runtime.GOOS == "windows" {
			return errors.New("run it in an Administrator PowerShell (config.yaml is writable only by administrators)")
		}
		return errors.New("run it as root (sudo fairy-agent config set ...)")
	}
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	after, old, had, err := configedit.Edit(before, s, v)
	if err != nil {
		return err
	}
	text, _ := configedit.Render(v)
	if string(after) == string(before) {
		fmt.Fprintf(stdout, "%s is already %s in %s; nothing changed\n", key, text, cfgPath)
		return nil
	}
	// the same checks as check-config, on the new text, before anything is written
	cfg, err := agent.Parse(after, cfgPath)
	if err != nil {
		return fmt.Errorf("not changed, the result would be invalid: %w", err)
	}
	if err := checkConfig(cfg); err != nil {
		prev, perr := agent.Parse(before, cfgPath)
		if perr == nil && checkConfig(prev) == nil {
			return fmt.Errorf("not changed, the agent could not start with it: %w", err)
		}
		fmt.Fprintln(stdout, "note: config.yaml already had this problem before the change:", err)
	}
	if err := configedit.WriteFile(cfgPath, after); err != nil {
		return fmt.Errorf("writing %s: %w", cfgPath, err)
	}
	if !had {
		old = "not set"
		if def, err := agent.Parse(nil, cfgPath); err == nil {
			old += ", default " + configedit.Effective(def, s)
		}
	}
	fmt.Fprintf(stdout, "%s: %s -> %s\nwritten: %s (checked like check-config)\nrestart the agent to use it: %s\n",
		key, old, text, cfgPath, restartHint())
	return nil
}
