package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/configedit"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

// `fairy-agent join`: the machine side of the panel's "Add host", run by install.sh / install.ps1 (root /
// Administrator) after the service is installed. It
//   - writes a starter config.yaml and the read / control tokens when they are missing (never replaces them),
//   - switches on the features the panel's dialog asked for, through the same checked edit as `config set`,
//   - stores the join code's verifier, its expiry and the panel's address in the pairing state,
//
// and prints no secret. The running agent then answers the panel's POST /pair once (see pkg/agent/pairing.go).

type joinOpts struct {
	code, panel, cfgPath, stateDir, upsName string
	powerControl, selfUpdate, wol, ups      bool
	coreTemp, ipmi                          bool
}

var upsNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func parseJoin(args []string, stderr io.Writer) (joinOpts, error) {
	var o joinOpts
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.code, "code", "", "the join code shown by the panel's Add host dialog")
	fs.StringVar(&o.panel, "panel", "", "the panel's Tailscale IP address (only it may pair)")
	fs.StringVar(&o.cfgPath, "config", agent.DefaultConfigPath(), "path of config.yaml")
	fs.StringVar(&o.stateDir, "state-dir", "", "folder of the pairing state (default: the agent's state folder)")
	fs.BoolVar(&o.powerControl, "power-control", false, "allow shutdown / reboot from the panel")
	fs.BoolVar(&o.selfUpdate, "self-update", false, "allow the panel's Update button")
	fs.BoolVar(&o.wol, "wol", false, "relay Wake-on-LAN packets for the panel")
	fs.BoolVar(&o.ups, "ups", false, "read the UPS of the local NUT server (127.0.0.1:3493) and pass it on")
	fs.StringVar(&o.upsName, "ups-name", "", "only this UPS of the local NUT server (implies --ups)")
	fs.BoolVar(&o.coreTemp, "coretemp", false, "Windows: CPU core temperatures and watts from Core Temp")
	fs.BoolVar(&o.ipmi, "ipmi", false, "BMC sensors over IPMI (Supermicro)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected %q", fs.Arg(0))
	}
	if o.code == "" || o.panel == "" {
		return o, errors.New("--code and --panel are required (copy the whole command from the panel's Add host dialog)")
	}
	if _, err := enroll.Normalize(o.code); err != nil {
		return o, err
	}
	if ip := net.ParseIP(o.panel); ip == nil || ip.To4() == nil {
		return o, errors.New("--panel must be the panel's Tailscale IPv4 address, e.g. 100.88.109.47")
	}
	if o.upsName != "" {
		if !upsNameRe.MatchString(o.upsName) {
			return o, errors.New("--ups-name: letters, digits, _ . - only (the name in `upsc -l`)")
		}
		o.ups = true
	}
	if o.stateDir == "" {
		cfg := &agent.Config{}
		if c, err := agent.Parse(nil, o.cfgPath); err == nil {
			cfg = c
		}
		o.stateDir = filepath.Dir(agent.PairingPath(cfg))
	}
	return o, nil
}

func joinCmd(args []string, stdout, stderr io.Writer) int {
	o, err := parseJoin(args, stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "fairy-agent join:", err)
		}
		return 2
	}
	if !isAdmin() {
		fmt.Fprintln(stderr, "fairy-agent join: run it as root / in an Administrator PowerShell (the installer does)")
		return 1
	}
	if err := join(o, stdout); err != nil {
		fmt.Fprintln(stderr, "fairy-agent join:", err)
		return 1
	}
	return 0
}

func join(o joinOpts, out io.Writer) error {
	dir := filepath.Dir(o.cfgPath)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("%s does not exist: install the agent first (install.sh / install.ps1 do)", dir)
	}
	created, err := writeNew(o.cfgPath, []byte(starterConfig()))
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintln(out, "wrote a starter", o.cfgPath)
	}
	for _, name := range []string{"token", "control-token"} {
		tok, err := newToken()
		if err != nil {
			return err
		}
		p := filepath.Join(dir, name)
		created, err := writeNew(p, []byte(tok+lineEnd()))
		if err != nil {
			return err
		}
		if created {
			fmt.Fprintln(out, "created", p)
		}
	}
	set := func(key, value string) error { return configSet(o.cfgPath, key, value, io.Discard) }
	type opt struct {
		on       bool
		key, msg string
	}
	for _, x := range []opt{{o.powerControl, "power_control.enabled", "shutdown / reboot from the panel"},
		{o.selfUpdate, "self_update.enabled", "self-update (the panel's Update button)"},
		{o.wol, "wol.enabled", "Wake-on-LAN relay"},
		{o.coreTemp, "sensors.coretemp", "Core Temp readings"},
		{o.ipmi, "ipmi.enabled", "BMC sensors"}} {
		if !x.on {
			continue
		}
		if err := set(x.key, "true"); err != nil {
			return fmt.Errorf("%s: %w", x.key, err)
		}
		fmt.Fprintln(out, "on:", x.msg)
	}
	if o.ups {
		if err := addLocalUPS(o.cfgPath, o.upsName); err != nil {
			if !errors.Is(err, configedit.ErrListNotEmpty) {
				return err
			}
			fmt.Fprintln(out, "ups: config.yaml already lists UPSes; left as it is")
		} else {
			fmt.Fprintln(out, "on: UPS from the local NUT server", o.upsName)
		}
	}
	cfg, err := agent.Load(o.cfgPath)
	if err == nil {
		err = checkConfig(cfg)
	}
	if err != nil {
		return fmt.Errorf("config check: %w", err)
	}
	if err := prepareStateDir(o.stateDir); err != nil {
		return fmt.Errorf("state folder %s: %w", o.stateDir, err)
	}
	proof, _ := enroll.Proof(o.code)
	now := time.Now()
	st := enroll.State{Version: 1, Verifier: enroll.Verifier(proof), Panel: o.panel, CreatedAt: now.Unix(),
		ExpiresAt: now.Add(enroll.TTL).Unix()}
	path := filepath.Join(o.stateDir, "pairing.json")
	if err := enroll.WriteState(path, st); err != nil {
		return err
	}
	if err := handOver(path); err != nil {
		return err
	}
	fmt.Fprintf(out, "join code stored: the panel (%s) can pair until %s\n", o.panel, time.Unix(st.ExpiresAt, 0).Format("15:04"))
	return nil
}

// addLocalUPS adds the local NUT server to an empty `ups:` list (read-only, no login: like `upsc`).
func addLocalUPS(cfgPath, upsName string) error {
	item := []configedit.KV{{Key: "id", Value: "local-ups"}, {Key: "type", Value: "nut"}, {Key: "host", Value: "127.0.0.1"}}
	if upsName != "" {
		item = append(item, configedit.KV{Key: "ups", Value: []string{upsName}})
	}
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	after, err := configedit.AddDevice(before, "ups", item)
	if err != nil {
		return err
	}
	cfg, err := agent.Parse(after, cfgPath)
	if err == nil {
		err = checkConfig(cfg)
	}
	if err != nil {
		return fmt.Errorf("ups: not changed, the result would be invalid: %w", err)
	}
	return configedit.WriteFile(cfgPath, after)
}

// writeNew creates a file that does not exist yet (0640 on Linux, owner root, the folder's group).
func writeNew(path string, data []byte) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	return true, secureNew(path)
}

func hashFile(path string) ([32]byte, error) {
	var sum [32]byte
	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, release.MaxAssetSize+1)); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// pairStatus is `fairy-agent pair-status`: 0 paired, 3 still waiting, 1 anything else.
func pairStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair-status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", agent.DefaultConfigPath(), "path of config.yaml")
	stateDir := fs.String("state-dir", "", "folder of the pairing state")
	if fs.Parse(args) != nil {
		return 2
	}
	path := agent.PairingPath(&agent.Config{})
	if c, err := agent.Parse(nil, *cfgPath); err == nil {
		path = agent.PairingPath(c)
	}
	if *stateDir != "" {
		path = filepath.Join(*stateDir, "pairing.json")
	}
	st, err := enroll.ReadState(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stdout, "no join code (add the host in the panel: Add host)")
		} else {
			fmt.Fprintln(stderr, "fairy-agent pair-status:", err)
		}
		return 1
	}
	now := time.Now()
	fmt.Fprintln(stdout, st.Describe(now))
	switch {
	case st.Closed == "paired":
		return 0
	case st.Active(now):
		return 3
	}
	return 1
}

// verifyRelease is `fairy-agent verify-release DIR`: the installer's signature check of a downloaded release
// (SHA256SUMS signed with the release key built into this binary, then every listed file present in DIR).
func verifyRelease(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: fairy-agent verify-release DIR   (DIR holds SHA256SUMS, SHA256SUMS.sig, VERSION and the downloads)")
		return 2
	}
	dir := args[0]
	key, err := release.ParsePublicKey(releaseKey)
	if err != nil {
		fmt.Fprintln(stderr, "fairy-agent verify-release: this build has no release key, so it cannot check signatures")
		return 3
	}
	read := func(n string) []byte {
		if err != nil {
			return nil
		}
		var b []byte
		b, err = release.ReadStaged(filepath.Join(dir, n), 1<<20)
		return b
	}
	sums, sig, ver := read(release.SumsFile), read(release.SigFile), read(release.VersionFile)
	if err != nil {
		fmt.Fprintln(stderr, "fairy-agent verify-release:", err)
		return 1
	}
	ch, err := release.VerifyFiles(key, release.AgentProgram, sums, sig, ver)
	if err != nil {
		fmt.Fprintln(stderr, "fairy-agent verify-release:", err)
		return 1
	}
	var checked []string
	for name, want := range ch.Sums {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil || name == release.VersionFile {
			continue
		}
		if got, err := hashFile(p); err != nil || got != want {
			fmt.Fprintf(stderr, "fairy-agent verify-release: %s does not match its %s line %v\n", name, release.SumsFile, err)
			return 1
		}
		checked = append(checked, name)
	}
	if len(checked) == 0 {
		fmt.Fprintln(stderr, "fairy-agent verify-release: none of the files listed in SHA256SUMS is in", dir)
		return 1
	}
	fmt.Fprintf(stdout, "release %s: signature OK, checked %s\n", ch.Version, strings.Join(checked, ", "))
	return 0
}
