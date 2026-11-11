// Package agent is fairy-agent: a small HTTP server that answers the Fairy panel's agent requests (/metrics,
// /processes, and, only when the owner turns them on, fan control, power actions and Wake-on-LAN).
//
// The wire format is the panel's agent contract (in github.com/n3ptune-cpu/Fairy-dashboard:
// internal/normalise/agent.go, internal/poller/httpbackend.go, internal/web/api_fan.go, internal/powerctl, and
// internal/agentcontract, which runs the panel against this package): GET requests carry the read token, POST
// requests the control token, both as "Authorization: Bearer <token>".
package agent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

// DefaultPort is the agent's TCP port (the panel's example config uses http://<tailscale ip>:9101).
const DefaultPort = 9101

// MinTokenLen is the panel's minimum agent token length.
const MinTokenLen = 24

// Config is config.yaml.
type Config struct {
	// Listen is host:port. Empty = this machine's Tailscale IPv4 address on DefaultPort; the agent refuses to
	// start when it cannot find exactly one. 0.0.0.0 / [::] need AllowAllInterfaces.
	Listen             string `yaml:"listen"`
	AllowAllInterfaces bool   `yaml:"allow_all_interfaces"`
	// OnlyFromPanel (off by default) accepts connections only from the address of the panel that paired with
	// this agent (Add host) and from this machine itself; everybody else is hung up on before a byte is read.
	// An agent with no panel address on record (never paired through Add host, or its last join code expired
	// or was closed) then accepts this machine only, until it is paired: the setting fails closed.
	OnlyFromPanel bool `yaml:"only_from_panel"`
	// RequireHelperPipeOwner (Windows; off by default in this release): the agent uses the helper's pipe only
	// when the pipe belongs to SYSTEM or Administrators. Off: another owner is only reported in the log.
	RequireHelperPipeOwner bool `yaml:"require_helper_pipe_owner"`

	// Tokens: the panel's token_env (read) and control_token_env (control) values. FAIRY_AGENT_TOKEN and
	// FAIRY_AGENT_CONTROL_TOKEN in the environment win over the files.
	TokenFile        string `yaml:"token_file"`
	ControlTokenFile string `yaml:"control_token_file"`
	// EnvFile holds KEY=value secrets for relayed devices (password_env names).
	EnvFile string `yaml:"env_file"`
	// LogFile: Windows default C:\ProgramData\fairy-agent\logs\agent.log; Linux default "" = stderr (journal).
	LogFile string `yaml:"log_file"`

	// HideHostDetails sends no hostname, a generic OS name and no hardware block.
	HideHostDetails bool `yaml:"hide_host_details"`

	Processes    ProcessesConfig    `yaml:"processes"`
	GPU          GPUConfig          `yaml:"gpu"`
	Sensors      SensorsConfig      `yaml:"sensors"`
	IPMI         IPMIConfig         `yaml:"ipmi"`
	FanControl   FanConfig          `yaml:"fan_control"`
	PowerControl PowerControlConfig `yaml:"power_control"`
	WOL          WOLConfig          `yaml:"wol"`
	SelfUpdate   SelfUpdateConfig   `yaml:"self_update"`
	BMCRelay     BMCRelayConfig     `yaml:"bmc_relay"`

	// ControlRatePerMin limits POST requests (fan, power, Wake-on-LAN, self-update) for the whole agent.
	ControlRatePerMin int `yaml:"control_rate_per_min"`

	// PowerSources / UPS: devices on this machine's LAN that the agent reads and relays to the panel (same
	// entries as the panel's power_sources / ups, secrets by env var name). SystemHint "self" links a power
	// source to this agent's host.
	PowerSources []map[string]any `yaml:"power_sources"`
	UPS          []map[string]any `yaml:"ups"`

	path    string
	ignored []string
}

// ProcessesConfig is the process list (the panel's Processes tab).
type ProcessesConfig struct {
	Enabled *bool `yaml:"enabled"` // default true
	Cmdline *bool `yaml:"cmdline"` // default true: command lines (Linux, redacted) / program paths (Windows)
	// NeverOpen (Windows): program names the agent never opens a handle to, not even to read their CPU time
	// (e.g. a game's anti-cheat-protected executable). They are listed by name only.
	NeverOpen []string `yaml:"never_open"`
}

// GPUConfig is the NVIDIA reader.
type GPUConfig struct {
	NvidiaSMI string  `yaml:"nvidia_smi"` // "auto" (default), "off", or the path to nvidia-smi
	AMDGPU    string  `yaml:"amdgpu"`     // Linux: "auto" (default: on when an amdgpu card exists) or "off"
	Windows   string  `yaml:"windows"`    // Windows: "auto" (default: AMD / Intel / other GPUs from Windows' own counters) or "off"
	AMDADL    string  `yaml:"amd_adl"`    // Windows: "auto" (default: Radeon temperature / watts from AMD's ADL, if installed) or "off"
	IntervalS float64 `yaml:"interval_s"` // default 2
}

// SensorsConfig is the OS temperature sources.
type SensorsConfig struct {
	ACPIThermal *bool `yaml:"acpi_thermal"` // Windows: ACPI thermal zones via PDH (default true)
	// CoreTemp (Windows): read CPU core temperatures and package watts from Core Temp's shared memory when the
	// Core Temp program is running (default false). The agent loads no driver; Core Temp's own one does.
	CoreTemp bool `yaml:"coretemp"`
}

// IPMIConfig is the BMC connection (Supermicro boards and others).
type IPMIConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Transport string `yaml:"transport"` // wmi (Windows default) | ipmitool (Linux default)
	Ipmitool  string `yaml:"ipmitool"`  // path, default: /usr/bin/ipmitool or PATH
	// IPMI-over-LAN (ipmitool only): BMC address, user and the env var with its password.
	Host        string `yaml:"host"`
	Username    string `yaml:"username"`
	PasswordEnv string `yaml:"password_env"`
	// Sensors reports the BMC's temperatures, fans and voltages in /metrics (default true).
	Sensors         *bool   `yaml:"sensors"`
	SensorIntervalS float64 `yaml:"sensor_interval_s"` // default 10
}

// FanConfig is BMC fan control (vendor supermicro: X9-X12 boards such as the X11SCA-F).
type FanConfig struct {
	Enabled  bool    `yaml:"enabled"`
	Vendor   string  `yaml:"vendor"`     // supermicro
	MinDuty  int     `yaml:"min_duty"`   // lowest manual duty accepted (default and minimum 30)
	MaxTempC float64 `yaml:"max_temp_c"` // watchdog: at or above this (CPU) temperature fans go to 100 % (default 80)
	AutoMode string  `yaml:"auto_mode"`  // the BMC mode that counts as "not overridden" (default optimal)
}

// PowerControlConfig is remote shutdown / reboot.
type PowerControlConfig struct {
	Enabled   bool `yaml:"enabled"`
	MinDelayS int  `yaml:"min_delay_s"` // default and minimum 10
}

// WOLConfig is the Wake-on-LAN relay.
type WOLConfig struct {
	Enabled     bool     `yaml:"enabled"`
	AllowedMACs []string `yaml:"allowed_macs"` // empty = any MAC
}

// SelfUpdateConfig lets the panel's Update button make this agent install the latest signed Fairy-agent
// release from GitHub (POST /update with the control token). Nothing is ever installed on its own.
type SelfUpdateConfig struct {
	Enabled bool `yaml:"enabled"`
	// Repo is the GitHub repository ("owner/name") whose latest release is installed; only for forks. Releases
	// must still be signed with the key built into this binary.
	Repo string `yaml:"repo"`
}

// DefaultConfigPath is where install and run look for config.yaml.
func DefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(ProgramData(), "fairy-agent", "config.yaml")
	}
	return "/etc/fairy-agent/config.yaml"
}

// ProgramData is %ProgramData% (C:\ProgramData).
func ProgramData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

// Dir is the folder of config.yaml.
func (c *Config) Dir() string { return filepath.Dir(c.path) }

// Path is the config file's path.
func (c *Config) Path() string { return c.path }

// Ignored is one line for each entry of config.yaml that an earlier version used and this one leaves out: a
// power_sources entry of type tuya, which is no longer supported. Such an entry never stops the agent from
// starting. Parse takes it out of PowerSources, so nothing else sees it; Run writes these lines to the log and
// check-config prints them.
func (c *Config) Ignored() []string { return c.ignored }

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// ProcessesEnabled reports whether /processes answers.
func (c *Config) ProcessesEnabled() bool { return boolOr(c.Processes.Enabled, true) }

// CmdlineEnabled reports whether process command lines are sent.
func (c *Config) CmdlineEnabled() bool { return boolOr(c.Processes.Cmdline, true) }

// IPMISensors reports whether BMC sensors go into /metrics.
func (c *Config) IPMISensors() bool { return c.IPMI.Enabled && boolOr(c.IPMI.Sensors, true) }

// ControlEnabled reports whether any POST feature is on (then a control token is required).
func (c *Config) ControlEnabled() bool {
	return c.FanControl.Enabled || c.PowerControl.Enabled || c.WOL.Enabled || c.SelfUpdate.Enabled || c.BMCRelay.Enabled
}

var (
	macRe     = regexp.MustCompile(`^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$`)
	envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Parse reads and checks a config file's contents (unknown keys are errors).
func Parse(data []byte, path string) (*Config, error) {
	c := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) { // an empty file is an empty config
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.path = path
	c.PowerSources, c.ignored = power.DropRemoved(c.PowerSources)
	c.defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Load reads config.yaml.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config: %w", err)
	}
	return Parse(b, path)
}

func (c *Config) defaults() {
	dir := c.Dir()
	if c.TokenFile == "" {
		c.TokenFile = filepath.Join(dir, "token")
	}
	if c.ControlTokenFile == "" {
		c.ControlTokenFile = filepath.Join(dir, "control-token")
	}
	if c.LogFile == "" && runtime.GOOS == "windows" {
		c.LogFile = filepath.Join(dir, "logs", "agent.log")
	}
	if c.GPU.NvidiaSMI == "" {
		c.GPU.NvidiaSMI = "auto"
	}
	if c.GPU.AMDGPU == "" {
		c.GPU.AMDGPU = "auto"
	}
	if c.GPU.AMDADL == "" {
		c.GPU.AMDADL = "auto"
	}
	if c.GPU.Windows == "" {
		c.GPU.Windows = "auto"
	}
	if c.GPU.IntervalS == 0 {
		c.GPU.IntervalS = 2
	}
	if c.IPMI.Transport == "" {
		c.IPMI.Transport = "ipmitool"
		if runtime.GOOS == "windows" && c.IPMI.Host == "" {
			c.IPMI.Transport = "wmi"
		}
	}
	if c.IPMI.SensorIntervalS == 0 {
		c.IPMI.SensorIntervalS = 10
	}
	if c.FanControl.Vendor == "" {
		c.FanControl.Vendor = "supermicro"
	}
	if c.FanControl.MinDuty == 0 {
		c.FanControl.MinDuty = 30
	}
	if c.FanControl.MaxTempC == 0 {
		c.FanControl.MaxTempC = 80
	}
	if c.FanControl.AutoMode == "" {
		c.FanControl.AutoMode = "optimal"
	}
	if c.PowerControl.MinDelayS == 0 {
		c.PowerControl.MinDelayS = 10
	}
	if c.ControlRatePerMin == 0 {
		c.ControlRatePerMin = 12
	}
	if c.SelfUpdate.Repo == "" {
		c.SelfUpdate.Repo = release.AgentRepo
	}
}

// Validate checks the settings; every problem is reported at once.
func (c *Config) Validate() error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if c.Listen != "" {
		host, port, err := net.SplitHostPort(c.Listen)
		if err != nil || port == "" {
			add("listen must be host:port, e.g. 100.64.0.10:%d", DefaultPort)
		} else {
			ip := net.ParseIP(host)
			switch {
			case host == "" || (ip != nil && ip.IsUnspecified()):
				if !c.AllowAllInterfaces {
					add("listen %s would accept connections on every network; use the Tailscale address, or set allow_all_interfaces: true if you really mean it", c.Listen)
				}
			case ip == nil:
				add("listen must use an IP address, not a host name")
			}
		}
	}
	if c.GPU.AMDGPU != "auto" && c.GPU.AMDGPU != "off" {
		add("gpu.amdgpu must be auto or off")
	}
	if c.GPU.Windows != "auto" && c.GPU.Windows != "off" {
		add("gpu.windows must be auto or off")
	}
	if c.GPU.AMDADL != "auto" && c.GPU.AMDADL != "off" {
		add("gpu.amd_adl must be auto or off")
	}
	c.BMCRelay.validate(func(s string) { add("%s", s) })
	// Number ranges are written as "not inside the range": a comparison with NaN is never true, so
	// "below the minimum or above the maximum" would let `.nan` through.
	if !(c.GPU.IntervalS >= 1 && c.GPU.IntervalS <= 60) {
		add("gpu.interval_s must be 1-60")
	}
	if c.IPMI.Ipmitool != "" && collect.ExecPathProblem(c.IPMI.Ipmitool, runtime.GOOS == "windows") != "" {
		add("ipmi.ipmitool must be an absolute local path")
	}
	if n := c.GPU.NvidiaSMI; n != "auto" && n != "off" && collect.ExecPathProblem(n, runtime.GOOS == "windows") != "" {
		add("gpu.nvidia_smi must be auto, off or an absolute local path")
	}
	switch c.IPMI.Transport {
	case "ipmitool":
	case "wmi":
		if runtime.GOOS != "windows" {
			add("ipmi.transport wmi is only available on Windows")
		}
		if c.IPMI.Host != "" {
			add("ipmi.host (IPMI over LAN) needs transport: ipmitool")
		}
	default:
		add("ipmi.transport must be wmi or ipmitool")
	}
	if c.IPMI.Host != "" {
		if net.ParseIP(c.IPMI.Host) == nil {
			add("ipmi.host must be the BMC's IP address")
		}
		if c.IPMI.Username == "" || !envNameRe.MatchString(c.IPMI.PasswordEnv) {
			add("ipmi.host needs username and password_env (the name of an env var holding the BMC password)")
		}
	}
	if !(c.IPMI.SensorIntervalS >= 2 && c.IPMI.SensorIntervalS <= 300) {
		add("ipmi.sensor_interval_s must be 2-300")
	}
	if c.Sensors.CoreTemp && runtime.GOOS != "windows" {
		add("sensors.coretemp is only available on Windows (Linux reads CPU temperatures from hwmon already)")
	}
	if c.FanControl.Enabled {
		if !c.IPMI.Enabled {
			add("fan_control needs ipmi.enabled: true")
		}
		if c.FanControl.Vendor != "supermicro" {
			add("fan_control.vendor must be supermicro")
		}
	}
	if !(c.FanControl.MinDuty >= 30 && c.FanControl.MinDuty <= 100) {
		add("fan_control.min_duty must be 30-100 (fans are never set below 30 %%)")
	}
	if !(c.FanControl.MaxTempC >= 50 && c.FanControl.MaxTempC <= 95) { // .nan here would switch the fan watchdog off
		add("fan_control.max_temp_c must be 50-95")
	}
	switch c.FanControl.AutoMode {
	case "standard", "optimal", "heavyio":
	default:
		add("fan_control.auto_mode must be standard, optimal or heavyio")
	}
	if !(c.PowerControl.MinDelayS >= 10 && c.PowerControl.MinDelayS <= 3600) {
		add("power_control.min_delay_s must be 10-3600")
	}
	for _, m := range c.WOL.AllowedMACs {
		if !macRe.MatchString(m) {
			add("wol.allowed_macs: %q is not a MAC address", m)
		}
	}
	if !release.ValidRepo(c.SelfUpdate.Repo) {
		add("self_update.repo must be a GitHub repository name like %s (not a URL)", release.AgentRepo)
	}
	if c.SelfUpdate.Enabled && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		add("self_update is only available on Linux and Windows")
	}
	if !(c.ControlRatePerMin >= 1 && c.ControlRatePerMin <= 60) {
		add("control_rate_per_min must be 1-60")
	}
	for _, n := range c.Processes.NeverOpen {
		if strings.TrimSpace(n) == "" || strings.ContainsAny(n, `\/`) {
			add("processes.never_open: give program names like game.exe, not paths")
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s: %s", c.path, strings.Join(errs, "; "))
	}
	return nil
}

// Tokens are the read token and the control token ("" when no control feature is on).
type Tokens struct {
	Read, Control string
}

func readSecretFile(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o007 != 0 {
		return "", fmt.Errorf("%s is readable by every user on this machine: chmod 0640 (owner root, group of the agent) or 0600", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// LoadTokens reads the tokens from the environment or the token files and checks them.
func (c *Config) LoadTokens() (Tokens, error) {
	var t Tokens
	get := func(env, file, what string, required bool) (string, error) {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v, nil
		}
		v, err := readSecretFile(file)
		if err != nil {
			if !required && errors.Is(err, os.ErrNotExist) {
				return "", nil
			}
			if errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("%s: put it in %s (or the %s environment variable)", what, file, env)
			}
			return "", fmt.Errorf("%s: %w", what, err)
		}
		return v, nil
	}
	var err error
	if t.Read, err = get("FAIRY_AGENT_TOKEN", c.TokenFile, "read token", true); err != nil {
		return t, err
	}
	if len(t.Read) < MinTokenLen {
		return t, fmt.Errorf("read token must be at least %d characters", MinTokenLen)
	}
	if !c.ControlEnabled() {
		return t, nil
	}
	if t.Control, err = get("FAIRY_AGENT_CONTROL_TOKEN", c.ControlTokenFile, "control token (fan, power, Wake-on-LAN or self-update is enabled)", true); err != nil {
		return t, err
	}
	if len(t.Control) < MinTokenLen {
		return t, fmt.Errorf("control token must be at least %d characters", MinTokenLen)
	}
	if t.Control == t.Read {
		return t, errors.New("the control token must differ from the read token")
	}
	return t, nil
}

// LoadEnvFile sets KEY=value lines from the env file (variables already set win) and returns their names.
func LoadEnvFile(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("env_file: %w", err)
	}
	var names []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(strings.TrimPrefix(k, "export "))
		if !ok || !envNameRe.MatchString(k) {
			return nil, fmt.Errorf("env_file line %d: expected KEY=value", n)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		names = append(names, k)
		if _, set := os.LookupEnv(k); !set {
			_ = os.Setenv(k, v)
		}
	}
	return names, nil
}
