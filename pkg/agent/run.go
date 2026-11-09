package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

// StartupWait is how long the agent waits at start for its listen address (Tailscale coming up after boot, or
// on Windows without "Run unattended" only after someone signs in): as long as it takes. The service keeps
// running meanwhile and the log says once a minute that it waits.
const StartupWait = WaitForever

func nvidiaPath(c GPUConfig) (string, error) {
	switch c.NvidiaSMI {
	case "off":
		return "", nil
	case "auto":
		return collect.FindNvidiaSMI(), nil
	}
	if collect.ExecPathProblem(c.NvidiaSMI, runtime.GOOS == "windows") != "" {
		return "", errors.New("gpu.nvidia_smi must be auto, off or an absolute local path")
	}
	if _, err := os.Stat(c.NvidiaSMI); err != nil {
		return "", fmt.Errorf("gpu.nvidia_smi: %w", err)
	}
	if err := collect.TrustedExecutable(c.NvidiaSMI); err != nil {
		return "", fmt.Errorf("gpu.nvidia_smi: not used: %w", err)
	}
	return c.NvidiaSMI, nil
}

func ipmitoolPath(c IPMIConfig) (string, error) {
	if c.Ipmitool != "" {
		if collect.ExecPathProblem(c.Ipmitool, runtime.GOOS == "windows") != "" {
			return "", errors.New("ipmi.ipmitool must be an absolute local path")
		}
		if err := collect.TrustedExecutable(c.Ipmitool); err != nil {
			return "", fmt.Errorf("ipmi.ipmitool: not used: %w", err)
		}
		return c.Ipmitool, nil
	}
	p, err := collect.FindIpmitool()
	if err != nil {
		return "", fmt.Errorf("%w (ipmi.ipmitool)", err)
	}
	return p, nil
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

// Build describes the running binary (set at build time with -ldflags).
type Build struct {
	Version    string
	ReleaseKey string // base64 ed25519 public key of signed releases; "" in local builds (no self-update)
}

// Run starts every part of the agent and serves until ctx ends.
func Run(ctx context.Context, cfg *Config, b Build) error {
	version := b.Version
	names, err := LoadEnvFile(cfg.EnvFile)
	if err != nil {
		return err
	}
	collect.HideEnv(names...)
	for _, t := range cfg.BMCRelay.Targets {
		collect.HideEnv(t.PasswordEnv)
	}
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
	// Windows: the elevated helper (fairy-agent-helper) does what this low-rights account may not. When it is
	// installed, Core Temp, IPMI through Windows, fans and power go through it; when it is not, the agent tries
	// them itself as before (an installation not yet moved to NT SERVICE\fairy-agent still has its old rights).
	helper := systemHelper(cfg)
	viaHelper := helper != nil && helper.Installed()
	if helper != nil {
		d.Helper = helper
		go helper.Run(ctx)
		if viaHelper && tokens.Control == "" {
			// /helper/stop and /helper/start use the control token even when no other control feature is on
			if v, err := readSecretFile(cfg.ControlTokenFile); err == nil && len(v) >= MinTokenLen && v != tokens.Read {
				tokens.Control = v
			}
		}
		if !viaHelper && NeedsHelper(cfg) {
			slog.Warn("config.yaml uses Core Temp, IPMI or power control, which need the fairy-agent-helper service; it is not installed, so the agent tries them with its own rights. Install it: " + HelperSetupHint)
		}
	}
	if cfg.Sensors.CoreTemp {
		if viaHelper {
			d.Collector = collect.WithCoreTempReader(d.Collector, helper.CoreTempRead)
			d.HelperSources = append(d.HelperSources, api.FeatureCoreTemp)
		} else {
			d.Collector = collect.WithCoreTemp(d.Collector)
		}
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
	if cfg.GPU.Windows == "auto" && runtime.GOOS == "windows" {
		// AMD, Intel and other cards from Windows' own GPU counters (NVIDIA ones stay with nvidia-smi)
		if wg := collect.NewWinGPU(time.Duration(cfg.GPU.IntervalS*float64(time.Second)), d.GPU != nil, cfg.GPU.AMDADL == "auto"); wg != nil {
			d.GPU = CombineGPUs(d.GPU, wg)
			slog.Info("GPUs via Windows (DXGI + GPU counters)", "adapters", wg.Names(), "amd_adl", wg.AMDCards())
		}
	}
	if d.GPU != nil && cfg.GPU.Windows == "auto" && runtime.GOOS == "windows" && cfg.ProcessesEnabled() {
		// per-process GPU memory for every card from Windows' own counter (nvidia-smi has none under WDDM)
		if pm := collect.NewProcGPU(); pm != nil {
			d.GPU = WithProcessGPUMemory(d.GPU, pm)
		}
	}
	var a *Agent
	interval := time.Duration(cfg.IPMI.SensorIntervalS * float64(time.Second))
	switch {
	case cfg.IPMI.Enabled && viaHelper && cfg.IPMI.Transport == "wmi":
		hs := helper.Sensors(interval)
		go hs.Run(ctx)
		d.BMC = hs
		d.HelperSources = append(d.HelperSources, api.FeatureIPMI)
		if cfg.FanControl.Enabled { // the helper runs the watchdog itself
			d.Fan = helper.Fan(cfg.FanControl)
			d.HelperSources = append(d.HelperSources, api.FeatureFans)
		}
	case cfg.IPMI.Enabled:
		t, err := IPMITransport(cfg.IPMI)
		if err != nil {
			return err
		}
		defer t.Close()
		bmc := NewBMC(t, interval)
		go bmc.Run(ctx)
		d.BMC = bmc
		if cfg.FanControl.Enabled {
			fan := NewFan(t, bmc, cfg.FanControl, func() []collect.Temp { return a.LocalTemps() })
			go fan.RunWatchdog(ctx)
			d.Fan = fan
		}
	}
	if cfg.PowerControl.Enabled {
		if viaHelper {
			d.Power = NewPower(helper.Power(), cfg.PowerControl.MinDelayS)
			d.HelperSources = append(d.HelperSources, api.FeaturePower)
		} else {
			d.Power = NewPower(SystemPower(), cfg.PowerControl.MinDelayS)
		}
	}
	if cfg.WOL.Enabled {
		d.WOL = NewWOL(cfg.WOL.AllowedMACs)
	}
	if cfg.BMCRelay.Enabled {
		d.BMCRelay = NewBMCRelay(cfg.BMCRelay, filepath.Join(filepath.Dir(PairingPath(cfg)), "bmc-pins.json"))
		slog.Info("BMC power-on relay", "targets", d.BMCRelay.Targets())
	}
	if cfg.SelfUpdate.Enabled {
		o, err := DefaultUpdaterOptions(cfg, version, b.ReleaseKey)
		if err != nil {
			return err
		}
		if viaHelper { // the helper may start the updater when this account's own start right is missing
			apply := o.Apply
			o.Apply = func(ctx context.Context) error {
				err := apply(ctx)
				if err != nil && isAccessDenied(err) {
					if herr := helper.ApplyUpdate(ctx); herr == nil {
						return nil
					}
				}
				return err
			}
		}
		d.Updater = NewUpdater(o)
		if st := d.Updater.Status(); st.State == "unavailable" {
			slog.Warn("self_update is enabled but cannot work", "reason", st.Message)
		} else if st.Last != nil {
			slog.Info("self-update: last result", "ok", st.Last.OK, "message", st.Last.Message)
		}
		if o.StageDir != "" {
			_ = clearDir(o.StageDir) // a stage left from the last update is not needed any more
		}
	}
	if !relay.Empty() {
		go relay.Run(ctx)
	}
	pairPath := PairingPath(cfg)
	d.Pairer = NewPairer(pairPath, cfg.LoadTokens, func() enroll.Response { return a.PairInfo() })
	if st, err := enroll.ReadState(pairPath); err == nil && st.Active(time.Now()) {
		slog.Info("waiting for the panel to pair (Add host)", "panel", st.Panel, "until", time.Unix(st.ExpiresAt, 0).Format(time.RFC3339))
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
		"self_update": d.Updater != nil, "helper": viaHelper,
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
