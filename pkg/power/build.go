package power

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

func httpURL(id, field, u string) error {
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
		return fmt.Errorf("power source %s: %s must be an http(s) URL", id, field)
	}
	return nil
}

// DecodeStrict re-decodes a generic YAML mapping into a typed struct, rejecting unknown keys.
func DecodeStrict(raw map[string]any, out any) error {
	b, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	return dec.Decode(out)
}

// Types are the built-in `type:` values of power_sources entries.
var Types = []string{"agent", "ipmi", "nut", "redfish", "shelly", "tasmota", "tuya"}

// Extra holds additional source types (the demo simulator registers "demo").
var Extra = map[string]func(raw map[string]any) (Source, error){}

// NewBase decodes and validates the common fields (for Extra types).
func NewBase(raw map[string]any) (Base, error) {
	b := Base{}
	b.ID, _ = raw["id"].(string)
	b.Type, _ = raw["type"].(string)
	b.Name, _ = raw["name"].(string)
	b.System, _ = raw["system"].(string)
	if v, ok := raw["include_in_total"].(bool); ok {
		b.IncludeInTotal = &v
	}
	return b, b.validate()
}

// Defaults can be embedded by Extra source types.
type Defaults = defaults

// Build validates one config entry and constructs the source.
func Build(raw map[string]any, agentPower AgentPowerFn) (Source, error) {
	typ, _ := raw["type"].(string)
	if fn, ok := Extra[typ]; ok {
		return fn(raw)
	}
	decode := newDecoder(raw)
	switch typ {
	case "shelly":
		return buildShelly(decode)
	case "tasmota":
		return buildTasmota(decode)
	case "nut":
		return buildNut(decode)
	case "redfish", "ipmi":
		return buildRedfish(decode)
	case "agent":
		return buildAgentPower(decode, agentPower)
	case "tuya":
		return buildTuya(decode)
	}
	return nil, fmt.Errorf("power source %q: unknown type %q (known: %s)", fmt.Sprint(raw["id"]), typ, strings.Join(Types, ", "))
}

// configDecoder decodes one raw `power_sources:` entry strictly (unknown keys are errors) into a typed config.
type configDecoder func(out any) error

func newDecoder(raw map[string]any) configDecoder {
	id := fmt.Sprint(raw["id"])
	return func(out any) error {
		if err := DecodeStrict(raw, out); err != nil {
			return fmt.Errorf("power source %q: %w", id, err)
		}
		return nil
	}
}

// ValidateConfigs checks every entry (config check / startup).
func ValidateConfigs(raws []map[string]any) error {
	seen := map[string]bool{}
	for _, r := range raws {
		s, err := Build(r, nil)
		if err != nil {
			return err
		}
		if seen[s.Info().ID] {
			return fmt.Errorf("power source %s: duplicate id", s.Info().ID)
		}
		seen[s.Info().ID] = true
	}
	return nil
}
