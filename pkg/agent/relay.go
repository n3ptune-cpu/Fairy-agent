package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/ups"
)

// Relay reads plugs, BMC power and UPSes on this machine's network with the device code the panel uses too
// (pkg/power, pkg/ups, pkg/devices) and reports them in /metrics `power_sources` and `ups`. The
// device credentials stay on this machine.
type Relay struct {
	sources []relaySource
	upses   []*ups.Source

	mu      sync.Mutex
	rows    map[string]map[string]any // power source id -> row
	upsRows map[string][]map[string]any
}

type relaySource struct {
	src  power.Source
	hint string
}

// NewRelay validates the agent's power_sources and ups entries (type "agent" makes no sense here).
func NewRelay(sources, upsCfg []map[string]any) (*Relay, error) {
	r := &Relay{rows: map[string]map[string]any{}, upsRows: map[string][]map[string]any{}}
	seen := map[string]bool{}
	for _, raw := range sources {
		raw = maps.Clone(raw)
		hint, _ := raw["system_hint"].(string)
		delete(raw, "system_hint")
		if t, _ := raw["type"].(string); t == "agent" {
			return nil, fmt.Errorf("power_sources: type agent is for the panel, not the agent")
		}
		s, err := power.Build(raw, nil)
		if err != nil {
			return nil, err
		}
		if seen[s.Info().ID] {
			return nil, fmt.Errorf("power source %s: duplicate id", s.Info().ID)
		}
		seen[s.Info().ID] = true
		r.sources = append(r.sources, relaySource{src: s, hint: hint})
	}
	for _, raw := range upsCfg {
		u, err := ups.Build(raw)
		if err != nil {
			return nil, err
		}
		r.upses = append(r.upses, u)
	}
	return r, nil
}

// Empty reports whether nothing is configured.
func (r *Relay) Empty() bool { return r == nil || (len(r.sources) == 0 && len(r.upses) == 0) }

func interval(s power.Source) time.Duration {
	iv := s.DefaultInterval()
	if p := s.Info().Interval; p != nil {
		iv = *p
	}
	iv = max(iv, s.FloorInterval())
	if !(iv >= 1 && iv <= 300) { // never a NaN or zero pause between polls (power.Build refuses such an interval)
		iv = min(max(s.DefaultInterval(), 1), 300)
	}
	return time.Duration(iv * float64(time.Second))
}

// Run polls every device in its own loop until ctx ends.
func (r *Relay) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, s := range r.sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.loopSource(ctx, s)
		}()
	}
	for _, u := range r.upses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.loopUPS(ctx, u)
		}()
	}
	wg.Wait()
	for _, s := range r.sources {
		s.src.Close()
	}
}

func (r *Relay) loopSource(ctx context.Context, s relaySource) {
	iv := interval(s.src)
	for ctx.Err() == nil {
		r.PollSource(ctx, s, min(iv, 10*time.Second))
		select {
		case <-ctx.Done():
			return
		case <-time.After(iv):
		}
	}
}

// PollSource reads one device and stores its row (exported for tests through PollOnce).
func (r *Relay) PollSource(ctx context.Context, s relaySource, timeout time.Duration) {
	b := s.src.Info()
	row := map[string]any{"id": b.ID, "name": b.DisplayName(), "type": b.Type, "ok": false, "watts": nil,
		"voltage": nil, "current": nil, "energy_kwh_total": nil, "system_hint": nil, "error": nil}
	if s.hint != "" {
		row["system_hint"] = s.hint
	}
	cctx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	readings, err := s.src.Read(cctx, timeout)
	cancel()
	switch {
	case err != nil:
		row["error"] = devices.Describe(err)
	case len(readings) == 0:
		row["error"] = "no reading"
	default:
		row["ok"] = true
		var w float64
		hasW := false
		for _, rd := range readings {
			if rd.Watts != nil {
				w += *rd.Watts
				hasW = true
			}
		}
		// Checked after the sum as well: each reading can be a possible number and the total not. A total that
		// is not one stays unknown (null), because one such number would make the whole /metrics answer fail.
		if hasW && devices.Finite(w) {
			row["watts"] = w
		}
		first := readings[0]
		if v := devices.Num(first.Voltage); v != nil {
			row["voltage"] = *v
		}
		if c := devices.Num(first.Current); c != nil && len(readings) == 1 {
			row["current"] = *c
		}
		if e := devices.Num(first.EnergyKWhTotal); e != nil && len(readings) == 1 {
			row["energy_kwh_total"] = *e
		}
	}
	r.mu.Lock()
	r.rows[b.ID] = row
	r.mu.Unlock()
}

func (r *Relay) loopUPS(ctx context.Context, u *ups.Source) {
	for ctx.Err() == nil {
		r.PollUPS(ctx, u)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// PollUPS reads one upsd.
func (r *Relay) PollUPS(ctx context.Context, u *ups.Source) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	rows, err := u.Read(cctx, 4*time.Second)
	cancel()
	if err != nil {
		msg := devices.Describe(err)
		rows = []map[string]any{{"name": "upsd", "ok": false, "error": msg, "flags": []string{}}}
	}
	// A row that cannot be written as JSON would fail the whole /metrics answer, and an empty one would make
	// its UPS silently drop out of it: both become a failed row the panel shows.
	for i, row := range rows {
		if _, err := json.Marshal(row); err != nil || len(row) == 0 {
			name, _ := row["name"].(string)
			if name == "" {
				name = "upsd"
			}
			rows[i] = map[string]any{"name": name, "ok": false, "error": "ups reports impossible values", "flags": []string{}}
		}
	}
	r.mu.Lock()
	r.upsRows[u.ID] = rows
	r.mu.Unlock()
}

// PollOnce reads every device once (first report, tests).
func (r *Relay) PollOnce(ctx context.Context) {
	if r == nil {
		return
	}
	var wg sync.WaitGroup
	for _, s := range r.sources {
		wg.Add(1)
		go func() { defer wg.Done(); r.PollSource(ctx, s, min(interval(s.src), 10*time.Second)) }()
	}
	for _, u := range r.upses {
		wg.Add(1)
		go func() { defer wg.Done(); r.PollUPS(ctx, u) }()
	}
	wg.Wait()
}

// Rows returns the latest power source rows and UPS rows, in config order.
func (r *Relay) Rows() ([]map[string]any, []map[string]any) {
	ps, us := []map[string]any{}, []map[string]any{}
	if r == nil {
		return ps, us
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sources {
		if row, ok := r.rows[s.src.Info().ID]; ok {
			ps = append(ps, row)
		}
	}
	for _, u := range r.upses {
		us = append(us, r.upsRows[u.ID]...)
	}
	return ps, us
}
