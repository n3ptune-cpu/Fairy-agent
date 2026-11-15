package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
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

	// pause waits d between two readings of a source and reports whether ctx is still alive. nil: the clock
	// (pauseFor). Tests put their own here to see the waits without waiting.
	pause func(ctx context.Context, d time.Duration) bool
}

type relaySource struct {
	src  power.Source
	hint string
}

// hintText is a system_hint as a text, for an entry with sockets. A text is itself. A bare number or true/false
// is the text of the value YAML read (123 is "123", true is "true"; a number is the number, so 007 is "7" and
// 0x10 is "16"): a machine whose name is digits only may be written without quotes. No value (the member is
// not there, or is null) is "". ok is false for what has no text form: a list, a map, a date.
func hintText(v any) (text string, ok bool) {
	switch v := v.(type) {
	case nil:
		return "", true
	case string:
		return v, true
	case bool, int, int64, uint64, float64:
		return fmt.Sprint(v), true
	}
	return "", false
}

// NewRelay validates the agent's power_sources and ups entries (type "agent" makes no sense here).
//
// system_hint is no member of a device's own settings: it is taken out of the entry here and kept beside it.
// On an entry without sockets it is what the panel links the plug by and nothing else, and only a text is a
// hint: any other form (a number, true, a list) is ignored without a word, as in every version before
// sockets, so a file from then loads and reports as it did. On an entry with sockets the hint decides whether
// the sockets are locked (hintKind), so it is never ignored: a number or true/false counts as its text
// (hintText), and a form without a text is a config problem, named by the entry's id and the key, with
// nothing of the value.
func NewRelay(sources, upsCfg []map[string]any) (*Relay, error) {
	r := &Relay{rows: map[string]map[string]any{}, upsRows: map[string][]map[string]any{}}
	seen := map[string]bool{}
	for _, raw := range sources {
		raw = maps.Clone(raw)
		written := raw["system_hint"]
		hint, _ := written.(string)
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
		if sk, ok := s.(power.Socketed); ok && len(sk.Sockets()) > 0 {
			text, ok := hintText(written)
			if !ok {
				return nil, fmt.Errorf("power source %s: system_hint is not a text (it is a list, a set of members or a date): on an entry with sockets it says "+
					"whether the sockets are locked, so it must be one text. Write system_hint: self for this machine, or one name, in quotes", s.Info().ID)
			}
			hint = text
		}
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

// NewRelay builds the relay of this config's power_sources and ups entries (the function NewRelay) and makes
// the checks that need the whole config: the variable a homeassistant entry names in token_env is not the
// one another setting keeps its secret in (tokenEnvShared), and an entry with sockets fits the home_assistant
// block (socketChecks). The running agent and check-config build their relay with it.
func (c *Config) NewRelay() (*Relay, error) {
	r, err := NewRelay(c.PowerSources, c.UPS)
	if err != nil {
		return nil, err
	}
	if err := c.tokenEnvShared(); err != nil { // after NewRelay: every id it names has been checked
		return nil, err
	}
	if err := c.socketChecks(r); err != nil {
		return nil, err
	}
	return r, nil
}

// tokenEnvShared is the error for a homeassistant entry whose token_env names a variable that something else
// in config.yaml names for its own secret: a member ending in "_env" of a power_sources entry of another type
// or of a ups entry, ipmi.password_env, or the password_env of a BMC relay target. What that variable holds (a
// plug's, a UPS's or a BMC's password) would be sent to Home Assistant as the token with every reading. Names
// are compared without regard to case, as Windows does.
//
// The error names the two settings by their ids and the member, never the variable: an error of a
// homeassistant entry repeats no value of the entry. Several homeassistant entries may name one variable (the
// plugs of one Home Assistant share its token), and an ignored entry (tuya) is not looked at.
//
// The same holds for home_assistant.token_env, the token plug sockets are switched with: never a variable that
// another kind of secret is kept in.
//
// It may be the variable the homeassistant entries read with, with switching on or off: one token for reading
// and for switching is the normal setup (the owner's decision of 15 Nov 16:35Z: Home Assistant gives every
// token of an account the same rights, so a second token only lets one be revoked without the other). Then
// Config.PlugReport says so in one neutral line. Two variables work as well. What never happens in either
// setup: one variable's token being used because the other variable is empty.
func (c *Config) tokenEnvShared() error {
	type named struct{ what, env string }
	var tokens, others []named
	if env := c.HomeAssistant.TokenEnv; env != "" { // the token sockets are switched with goes to Home Assistant too
		tokens = append(tokens, named{"home_assistant", env})
	}
	for _, raw := range c.PowerSources {
		id, _ := raw["id"].(string)
		if typ, _ := raw["type"].(string); typ == "homeassistant" {
			if env, _ := raw["token_env"].(string); env != "" {
				tokens = append(tokens, named{id, env})
			}
			continue
		}
		for _, k := range slices.Sorted(maps.Keys(raw)) {
			if env, ok := raw[k].(string); ok && env != "" && strings.HasSuffix(k, "_env") {
				others = append(others, named{k + " of power source " + id, env})
			}
		}
	}
	for _, raw := range c.UPS {
		id, _ := raw["id"].(string)
		for _, k := range slices.Sorted(maps.Keys(raw)) {
			if env, ok := raw[k].(string); ok && env != "" && strings.HasSuffix(k, "_env") {
				others = append(others, named{k + " of ups " + id, env})
			}
		}
	}
	if c.IPMI.PasswordEnv != "" {
		others = append(others, named{"ipmi.password_env", c.IPMI.PasswordEnv})
	}
	for _, t := range c.BMCRelay.Targets {
		if t.PasswordEnv != "" {
			others = append(others, named{"password_env of bmc_relay target " + t.ID, t.PasswordEnv})
		}
	}
	for _, tok := range tokens {
		for _, o := range others {
			if strings.EqualFold(tok.env, o.env) {
				who := "power source " + tok.what
				if tok.what == "home_assistant" {
					who = "home_assistant" // the block, not an entry
				}
				return fmt.Errorf("%s: token_env names the same variable as %s: what that variable holds would be sent to Home Assistant as the token. The token needs a variable that nothing else names", who, o.what)
			}
		}
	}
	return nil
}

// Checks are the config check's facts about the relayed power sources that read with a secret (homeassistant:
// the host, the sensor, the token's variable and whether it is set), in config order. Never a secret.
func (r *Relay) Checks() []power.Check {
	var out []power.Check
	if r == nil {
		return out
	}
	for _, s := range r.sources {
		if c, ok := s.src.(power.Checker); ok {
			out = append(out, c.Check())
		}
	}
	return out
}

// SocketSource is a relayed power source whose entry lists sockets: its id and name, its system_hint, the
// Home Assistant it reads from and the sockets, in the entry's order.
type SocketSource struct {
	ID, Name, Hint string
	Scheme, Host   string // of the entry's url: http or https, host[:port]
	Sockets        []power.Socket
}

// SocketSources are the power sources that have sockets, in config order. Nothing is asked of any device.
func (r *Relay) SocketSources() []SocketSource {
	var out []SocketSource
	if r == nil {
		return out
	}
	for _, s := range r.sources {
		sk, ok := s.src.(power.Socketed)
		if !ok || len(sk.Sockets()) == 0 {
			continue
		}
		b := s.src.Info()
		ss := SocketSource{ID: b.ID, Name: b.DisplayName(), Hint: s.hint, Sockets: sk.Sockets()}
		if c, ok := s.src.(power.Checker); ok {
			ch := c.Check()
			ss.Scheme, ss.Host = ch.Scheme, ch.Host
		}
		out = append(out, ss)
	}
	return out
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

// loopSource reads one source at its interval until ctx ends.
//
// After a refusal of the source's secret (power.Refused: Home Assistant answered 401 or 403) the next reading
// is not after the interval but after power.RefusedWait: 5 minutes, then 15 minutes, then an hour for the
// third and each further refusal in a row. A revoked token would otherwise be sent every 10 s for as long as the agent runs, and Home
// Assistant counts each as a failed login and can ban the agent's address. The row keeps the refusal's text
// while the source waits. The count of refusals goes back to zero with the first reading that succeeds; a
// failure of another kind in between (Home Assistant restarts) is waited out at the normal interval and does
// not start the count again. The count is kept here and nowhere else: a restart of the agent starts it anew,
// and the first reading after a restart is made at once. Only homeassistant returns refusals: the timing of
// every other type is unchanged.
func (r *Relay) loopSource(ctx context.Context, s relaySource) {
	iv := interval(s.src)
	pause := r.pause
	if pause == nil {
		pause = pauseFor
	}
	refusals := 0
	for ctx.Err() == nil {
		err := r.PollSource(ctx, s, min(iv, 10*time.Second))
		wait := iv
		switch {
		case err == nil:
			refusals = 0
		case power.Refused(err):
			refusals++
			wait = max(iv, power.RefusedWait(refusals))
		}
		if !pause(ctx, wait) {
			return
		}
	}
}

// pauseFor waits d, or until ctx ends: then it reports false.
func pauseFor(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// PollSource reads one device and stores its row (exported for tests through PollOnce). It returns the error
// of the reading, nil when the device answered.
//
// A row has the same members for every type. One more, "missing", is there only in the row of a reading that
// came without a value its source was set up to read (power.Partial: a homeassistant entry with
// voltage_entity, current_entity or energy_entity whose sensor gave nothing): an object with that value's
// member name ("voltage", "current", "energy_kwh_total") and a short fixed text for why it is null. The row is
// still ok, with its watts. A panel that does not know the member does not look at it.
func (r *Relay) PollSource(ctx context.Context, s relaySource, timeout time.Duration) error {
	b := s.src.Info()
	row := map[string]any{"id": b.ID, "name": b.DisplayName(), "type": b.Type, "ok": false, "watts": nil,
		"voltage": nil, "current": nil, "energy_kwh_total": nil, "system_hint": nil, "error": nil}
	if s.hint != "" {
		row["system_hint"] = s.hint
	}
	cctx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	var readings []power.Reading
	var missing map[string]string
	var err error
	if p, ok := s.src.(power.Partial); ok {
		readings, missing, err = p.ReadPartial(cctx, timeout)
	} else {
		readings, err = s.src.Read(cctx, timeout)
	}
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
		if len(missing) > 0 {
			row["missing"] = missing
		}
	}
	r.mu.Lock()
	r.rows[b.ID] = row
	r.mu.Unlock()
	return err
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
