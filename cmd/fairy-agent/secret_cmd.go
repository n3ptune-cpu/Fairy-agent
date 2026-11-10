package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/configedit"
)

const secretUsage = `usage:
  fairy-agent secret set NAME [--config PATH]   store a password (e.g. a BMC's) in the agent's env_file;
                                                 asks for the value (or reads one line from stdin), never
                                                 takes it on the command line (root / Administrator)
`

var secretNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// secretCmd is `fairy-agent secret set NAME`.
func secretCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	pos, cfgPath, err := splitConfigArgs(args)
	if err != nil || len(pos) != 2 || pos[0] != "set" {
		fmt.Fprint(stderr, secretUsage)
		return 2
	}
	// Windows: config.yaml names the file the secret is written to; one that someone else could have written
	// is not followed (adminDataDirTrusted). Checked before the value is asked for.
	if err := adminDataDirTrusted(cfgPath); err != nil {
		fmt.Fprintln(stderr, "fairy-agent secret set:", err)
		return 1
	}
	if err := secretSet(cfgPath, pos[1], stdin, stdout); err != nil {
		fmt.Fprintln(stderr, "fairy-agent secret set:", err)
		return 1
	}
	return 0
}

func secretSet(cfgPath, name string, stdin io.Reader, stdout io.Writer) error {
	if !secretNameRe.MatchString(name) || strings.HasPrefix(strings.ToUpper(name), "FAIRY_") {
		return errors.New("NAME must be letters, digits and _ (not starting with FAIRY_), e.g. BMC_SERVER_PASSWORD")
	}
	if !isAdmin() {
		return errors.New("run it as root / in an Administrator PowerShell (the secrets file is theirs)")
	}
	cfg, err := agent.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config problem: %w", err)
	}
	value, err := readSecretValue(name, stdin, stdout)
	if err != nil {
		return err
	}
	path := cfg.EnvFile
	setEnvFile := path == ""
	if setEnvFile {
		path = filepath.Join(cfg.Dir(), "secrets.env")
	}
	if err := writeSecret(path, name, value); err != nil {
		return err
	}
	if setEnvFile {
		if err := configSet(cfgPath, "env_file", path, io.Discard); err != nil {
			return fmt.Errorf("%s written to %s, but env_file could not be set in config.yaml: %w", name, path, err)
		}
		fmt.Fprintf(stdout, "env_file set to %s in %s\n", path, cfgPath)
	}
	fmt.Fprintf(stdout, "%s written to %s (the value is not shown)\nrestart the agent to use it: %s\n", name, path, restartHint())
	return nil
}

// readSecretValue asks for the value without echo on a terminal, else reads one line from stdin.
func readSecretValue(name string, stdin io.Reader, stdout io.Writer) (string, error) {
	var v string
	if f, ok := stdin.(*os.File); ok && isTerminal(f) {
		fmt.Fprintf(stdout, "value for %s (not shown): ", name)
		b, err := readHidden(f)
		fmt.Fprintln(stdout)
		if err != nil {
			return "", err
		}
		v = b
	} else {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		v = line
	}
	v = strings.TrimRight(v, "\r\n")
	switch {
	case v == "":
		return "", errors.New("empty value: nothing written")
	case strings.ContainsAny(v, "\r\n\x00"):
		return "", errors.New("the value must be one line")
	case strings.TrimSpace(v) != v:
		return "", errors.New("the value must not start or end with spaces (env_file trims them)")
	}
	return v, nil
}

// writeSecret sets NAME=value in the env file (other lines kept), replacing the file atomically with tight
// permissions: Linux 0640 root:<the config folder's group>; Windows SYSTEM and Administrators full control, the
// service read-only, nobody else.
func writeSecret(path, name, value string) error {
	var lines []string
	if b, err := os.ReadFile(path); err == nil {
		lines = strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	out, done := []string{}, false
	for _, l := range lines {
		k, _, ok := strings.Cut(strings.TrimSpace(l), "=")
		k = strings.TrimSpace(strings.TrimPrefix(k, "export "))
		if ok && k == name {
			if !done {
				out = append(out, name+"="+value)
				done = true
			}
			continue
		}
		out = append(out, l)
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	if !done {
		if len(out) == 0 {
			out = append(out, "# secrets for fairy-agent (env_file): KEY=value, one per line. Written by `fairy-agent secret set`.")
		}
		out = append(out, name+"="+value)
	}
	data := strings.Join(out, lineEnd()) + lineEnd()
	tmp := path + ".tmp" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(tmp, []byte(data), 0o600); err != nil {
		return err
	}
	if err := secureSecretFile(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("permissions of %s: %w", tmp, err)
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(path) // rename does not replace on every Windows file system
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

const bmcAddUsage = `usage:
  fairy-agent bmc-relay add --id ID (--host IP | --url https://IP) --username USER --password-env NAME
                            [--backend ipmitool|redfish] [--cipher-suite N] [--ipmitool-path PATH]
                            [--tls-fingerprint SHA256] [--config PATH]
      adds the first BMC power-on relay target and sets bmc_relay.enabled (root / Administrator); the password
      itself goes in with: fairy-agent secret set NAME
`

// bmcRelayCmd is `fairy-agent bmc-relay add ...`.
func bmcRelayCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "add" {
		fmt.Fprint(stderr, bmcAddUsage)
		return 2
	}
	fs := flag.NewFlagSet("bmc-relay add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", agent.DefaultConfigPath(), "path of config.yaml")
	id := fs.String("id", "", "target id, e.g. server-bmc")
	host := fs.String("host", "", "ipmitool: the BMC's IP")
	u := fs.String("url", "", "redfish: https://<BMC IP>")
	user := fs.String("username", "", "BMC account")
	pwEnv := fs.String("password-env", "", "name of the password in env_file")
	backend := fs.String("backend", "", "ipmitool | redfish")
	cipher := fs.Int("cipher-suite", -1, "ipmitool -C (0-17)")
	ipmitool := fs.String("ipmitool-path", "", "full path of ipmitool")
	fp := fs.String("tls-fingerprint", "", "redfish: SHA-256 of the BMC's certificate")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	item := []configedit.KV{{Key: "id", Value: *id}}
	for _, kv := range []struct{ k, v string }{{"backend", *backend}, {"host", *host}, {"url", *u}, {"username", *user},
		{"password_env", *pwEnv}, {"ipmitool_path", *ipmitool}, {"tls_fingerprint", *fp}} {
		if kv.v != "" {
			item = append(item, configedit.KV{Key: kv.k, Value: kv.v})
		}
	}
	if *cipher >= 0 {
		item = append(item, configedit.KV{Key: "cipher_suite", Value: *cipher})
	}
	if err := adminDataDirTrusted(*cfgPath); err != nil { // Windows: see adminDataDirTrusted
		fmt.Fprintln(stderr, "fairy-agent bmc-relay add:", err)
		return 1
	}
	if err := bmcRelayAdd(*cfgPath, item, stdout); err != nil {
		fmt.Fprintln(stderr, "fairy-agent bmc-relay add:", err)
		return 1
	}
	return 0
}

func bmcRelayAdd(cfgPath string, item []configedit.KV, stdout io.Writer) error {
	if !isAdmin() {
		return errors.New("run it as root / in an Administrator PowerShell")
	}
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	after, err := configedit.AddDevice(before, "bmc_relay.targets", item)
	if err != nil {
		return fmt.Errorf("%w (a second target: edit config.yaml by hand)", err)
	}
	s, _ := configedit.Lookup("bmc_relay.enabled")
	if after, _, _, err = configedit.Edit(after, s, true); err != nil {
		return err
	}
	cfg, err := agent.Parse(after, cfgPath)
	if err == nil {
		err = checkConfig(cfg)
	}
	if err != nil {
		return fmt.Errorf("not changed, the result would be invalid: %w", err)
	}
	if err := configedit.WriteFile(cfgPath, after); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "bmc_relay target added and bmc_relay.enabled: true in %s\nrestart the agent to use it: %s\n", cfgPath, restartHint())
	return nil
}
