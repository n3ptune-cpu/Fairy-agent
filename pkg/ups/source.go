// Package ups reads UPSes from NUT (upsd): the `ups:` config entries, which systems each UPS powers, and one
// row per UPS in the generic shape agents send. fairy-agent uses it to relay the UPSes on its own network; the
// Fairy panel (github.com/n3ptune-cpu/Fairy-dashboard) uses the same sources and adds state, history and events.
//
// Read-only by design: only LIST UPS / LIST VAR are ever sent (no INSTCMD, no SET VAR).
package ups

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/configutil"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// Powers says which systems a source's UPSes power: a list applies to every UPS of this source; a map maps NUT UPS
// name -> system ids.
type Powers struct {
	All    []string
	ByName map[string][]string
}

// For returns the systems powered by the named UPS.
func (p Powers) For(upsName string) []string {
	if p.ByName != nil {
		return slices.Clone(p.ByName[upsName])
	}
	return slices.Clone(p.All)
}

// NutConfig is a `ups:` entry of type nut: an upsd to poll (all its UPSes, or the listed ones).
type NutConfig struct {
	ID          string   `yaml:"id"`
	Type        string   `yaml:"type"`
	Name        string   `yaml:"name"`
	PowersRaw   any      `yaml:"powers"`
	Host        string   `yaml:"host"`
	Port        int      `yaml:"port"`
	UPS         []string `yaml:"ups"` // empty = every UPS that upsd lists
	Username    string   `yaml:"username"`
	PasswordEnv string   `yaml:"password_env"`
	powers      Powers
}

func parsePowers(id string, raw any) (Powers, error) {
	ids := func(v any) ([]string, error) {
		l, ok := v.([]any)
		if !ok && v != nil {
			return nil, fmt.Errorf("ups %s: powers must be a list of system ids or a mapping", id)
		}
		out := []string{}
		for _, x := range l {
			s, _ := x.(string)
			if !configutil.ValidID(s) {
				return nil, fmt.Errorf("ups %s: invalid system id in powers", id)
			}
			out = append(out, s)
		}
		return out, nil
	}
	switch x := raw.(type) {
	case nil:
		return Powers{All: []string{}}, nil
	case map[string]any:
		p := Powers{ByName: map[string][]string{}}
		for k, v := range x {
			l, err := ids(v)
			if err != nil {
				return p, err
			}
			p.ByName[k] = l
		}
		return p, nil
	default:
		l, err := ids(raw)
		return Powers{All: l}, err
	}
}

// Source is one configured UPS source (a NUT daemon, or a registered extra type).
type Source struct {
	ID, Name string
	Powers   Powers
	Read     func(ctx context.Context, timeout time.Duration) ([]map[string]any, error)
}

// Extra holds additional source types (the demo simulator registers "demo").
var Extra = map[string]func(raw map[string]any) (*Source, error){}

// ParsePowers is exported for Extra types.
func ParsePowers(id string, raw any) (Powers, error) { return parsePowers(id, raw) }

// Build validates one `ups:` entry.
func Build(raw map[string]any) (*Source, error) {
	if t, _ := raw["type"].(string); Extra[t] != nil {
		return Extra[t](raw)
	}
	c, err := buildNut(raw)
	if err != nil {
		return nil, err
	}
	return &Source{ID: c.ID, Name: c.Name, Powers: c.powers, Read: c.read}, nil
}

func buildNut(raw map[string]any) (*NutConfig, error) {
	c := &NutConfig{Type: "nut", Port: 3493}
	if err := power.DecodeStrict(raw, c); err != nil {
		return nil, fmt.Errorf("ups %v: %w", raw["id"], err)
	}
	if c.Type != "nut" {
		return nil, fmt.Errorf("ups %q: unknown type %q (known: nut)", c.ID, c.Type)
	}
	if !configutil.ValidID(c.ID) {
		return nil, fmt.Errorf("ups %q: id must be lowercase letters, digits and dashes", c.ID)
	}
	if c.Host == "" {
		return nil, fmt.Errorf("ups %s: host is required", c.ID)
	}
	p, err := parsePowers(c.ID, c.PowersRaw)
	if err != nil {
		return nil, err
	}
	c.powers = p
	return c, nil
}

// ValidateConfigs checks every `ups:` entry (config check / startup).
func ValidateConfigs(raws []map[string]any) error {
	for _, r := range raws {
		if _, err := Build(r); err != nil {
			return err
		}
	}
	return nil
}

func (c *NutConfig) read(ctx context.Context, timeout time.Duration) ([]map[string]any, error) {
	pw, err := configutil.EnvSecret(c.PasswordEnv, "ups "+c.ID, 1)
	if err != nil {
		return nil, devices.Safe(err)
	}
	all, err := devices.NUTReadAll(ctx, c.Host, c.Port, c.Username, pw, timeout, c.UPS)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(all))
	for _, u := range all {
		out = append(out, RowMap(devices.UPSFromVars(u.Name, u.Vars, u.Description)))
	}
	return out, nil
}

// RowMap converts a typed row to the generic shape agents send.
func RowMap(r devices.UPSRow) map[string]any {
	b, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
