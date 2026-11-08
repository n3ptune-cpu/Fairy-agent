package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
)

// StartupWait is how long the agent waits at start for its listen address (Tailscale coming up after boot).
const StartupWait = 3 * time.Minute

func nvidiaPath(c GPUConfig) (string, error) {
	switch c.NvidiaSMI {
	case "off":
		return "", nil
	case "auto":
		return collect.FindNvidiaSMI(), nil
	}
	if !filepath.IsAbs(c.NvidiaSMI) {
		return "", errors.New("gpu.nvidia_smi must be auto, off or an absolute path")
	}
	if _, err := os.Stat(c.NvidiaSMI); err != nil {
		return "", fmt.Errorf("gpu.nvidia_smi: %w", err)
	}
	return c.NvidiaSMI, nil
}

func ipmitoolPath(c IPMIConfig) (string, error) {
	if c.Ipmitool != "" {
		if !filepath.IsAbs(c.Ipmitool) {
			return "", errors.New("ipmi.ipmitool must be an absolute path")
		}
		return c.Ipmitool, nil
	}
	for _, p := range []string{"/usr/bin/ipmitool", "/usr/sbin/ipmitool", "/usr/local/bin/ipmitool"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if p, err := exec.LookPath("ipmitool"); err == nil {
		return p, nil
	}
	return "", errors.New("ipmitool not found: install it (apt install ipmitool) or set ipmi.ipmitool")
}

// IPMITransport builds the configured IPMI transport.
func IPMITransport(c IPMIConfig) (ipmi.Transport, error) {
	if c.Transport == "wmi" {
		return ipmi.NewWMI(5 * time.Minute)
	}
	path, err := ipmitoolPath(c)
	if err != nil {
		return nil, err
	}
	t := &ipmi.Ipmitool{Path: path, Host: c.Host, Username: c.Username, Env: collect.MinimalEnv(), SysAttr: collect.LowPriority()}
	if c.Host != "" {
		if t.Password = os.Getenv(c.PasswordEnv); t.Password == "" {
			return nil, fmt.Errorf("ipmi.password_env: env var %s is not set", c.PasswordEnv)
		}
	}
	return t, nil
}

// Run starts every part of the agent and serves until ctx ends.
func Run(ctx context.Context, cfg *Config, version string) error {
	names, err := LoadEnvFile(cfg.EnvFile)
	if err != nil {
		return err
	}
	collect.HideEnv(names...)
	if cfg.IPMI.PasswordEnv != "" {
		collect.HideEnv(cfg.IPMI.PasswordEnv)
	}
	tokens, err := cfg.LoadTokens()
	if err != nil {
		return err
	}
	relay, err := NewRelay(cfg.PowerSources, cfg.UPS)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	d := Deps{Collector: collect.NewSystem(), Relay: relay, Version: version}
	if cfg.Sensors.CoreTemp {
		d.Collector = collect.WithCoreTemp(d.Collector)
	}
	if p, err := nvidiaPath(cfg.GPU); err != nil {
		return err
	} else if p != "" {
		nv := collect.NewNvidiaSMI(p, time.Duration(cfg.GPU.IntervalS*float64(time.Second)))
		go nv.Run(ctx)
		d.GPU = nv
		slog.Info("NVIDIA GPUs via nvidia-smi", "path", p)
	}
	if cfg.GPU.AMDGPU == "auto" && runtime.GOOS == "linux" {
		if amd := collect.NewAMDGPU("/sys", time.Duration(cfg.GPU.IntervalS*float64(time.Second))); amd != nil {
			d.GPU = CombineGPUs(d.GPU, amd)
			slog.Info("AMD GPUs via amdgpu sysfs", "cards", amd.Cards())
		}
	}
	var a *Agent
	if cfg.IPMI.Enabled {
		t, err := IPMITransport(cfg.IPMI)
		if err != nil {
			return err
		}
		defer t.Close()
		d.BMC = NewBMC(t, time.Duration(cfg.IPMI.SensorIntervalS*float64(time.Second)))
		go d.BMC.Run(ctx)
		if cfg.FanControl.Enabled {
			d.Fan = NewFan(t, d.BMC, cfg.FanControl, func() []collect.Temp { return a.LocalTemps() })
			go d.Fan.RunWatchdog(ctx)
		}
	}
	if cfg.PowerControl.Enabled {
		d.Power = NewPower(SystemPower(), cfg.PowerControl.MinDelayS)
	}
	if cfg.WOL.Enabled {
		d.WOL = NewWOL(cfg.WOL.AllowedMACs)
	}
	if !relay.Empty() {
		go relay.Run(ctx)
	}
	a = New(cfg, tokens, d)

	addr, err := ListenAddr(ctx, cfg, StartupWait)
	if err != nil {
		return err
	}
	ln, err := Listen(ctx, addr, StartupWait)
	if err != nil {
		return err
	}
	var on []string
	for name, ok := range map[string]bool{"processes": cfg.ProcessesEnabled(), "fan_control": d.Fan != nil,
		"power_control": d.Power != nil, "wol_relay": d.WOL != nil, "ipmi": d.BMC != nil, "gpu": d.GPU != nil,
		"coretemp": cfg.Sensors.CoreTemp} {
		if ok {
			on = append(on, name)
		}
	}
	slices.Sort(on)
	slog.Info("fairy-agent listening", "version", version, "listen", ln.Addr().String(), "features", strings.Join(on, ","))
	srv := a.Server()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	_ = srv.Shutdown(sctx)
	slog.Info("fairy-agent stopped")
	return nil
}
