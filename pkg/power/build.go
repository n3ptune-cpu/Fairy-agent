package power

import (
	"bytes"
	"fmt"
	"net/url"
	"slices"
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
var Types = []string{"agent", "ipmi", "nut", "redfish", "shelly", "tasmota"}

// Removed are `type:` values that earlier versions read and this one does not (tuya, the plugs' local protocol:
// nobody had set one up). A config file that still has such an entry must never stop the agent or
// the panel from starting: whoever loads power_sources takes these entries out with DropRemoved first and
// shows its lines (in the log at start and in the config check).
var Removed = []string{"tuya"}

// removedSecretEnv: for each removed type, the member of its entries that names the environment variable with
// the device's secret (tuya: the plug's local key). The entry is ignored, but the secret is usually still in
// the env file, and nothing uses it any more.
var removedSecretEnv = map[string]string{"tuya": "local_key_env"}

// secretEnvOf is the name of the environment variable a removed entry kept its secret in ("": none, or not a
// name that can be an environment variable's, which is then neither printed nor acted on).
func secretEnvOf(raw map[string]any) string {
	typ, _ := raw["type"].(string)
	name, _ := raw[removedSecretEnv[typ]].(string)
	if name == "" || len(name) > 128 {
		return ""
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9') {
			return ""
		}
	}
	return name
}

// RemovedSecretEnv are the names of the environment variables that the entries of a removed type in raws kept
// their secrets in (each once, in the order of the list). Call it before DropRemoved takes the entries out.
// Only names: a value is never read here.
func RemovedSecretEnv(raws []map[string]any) []string {
	var names []string
	for _, raw := range raws {
		if typ, _ := raw["type"].(string); !slices.Contains(Removed, typ) {
			continue
		}
		if n := secretEnvOf(raw); n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

// DropRemoved returns raws without the entries of a type that is no longer supported (Removed), and one line
// for each entry it took out, such as
//
//	power source "desk-plug": tuya is no longer supported and is ignored (remove the entry from config.yaml, and the line DESK_KEY=... from the env file: the plug's key is not used any more)
//
// The line names the variable that held the device's secret, never its value (and only a name that can be an
// environment variable's). Such an entry is not checked in any other way: whatever else it holds, it is only
// ignored. An entry without an id is named by its place in the list. Without such an entry, raws comes back as
// it is.
//
// The line says to remove the variable's line only when nothing else uses the variable. Here that is: no entry
// that stays in raws names it (in a member that ends in "_env"; names are compared without regard to case, as
// Windows does). For such a variable the line reads
//
//	power source "plug-3": tuya is no longer supported and is ignored (remove the entry from config.yaml; leave the line SHARED_PW=... in the env file: it is still in use)
//
// A caller whose config can name a variable in other places than this list uses DropRemovedNotes.
func DropRemoved(raws []map[string]any) (kept []map[string]any, notes []string) {
	return DropRemovedNotes(raws, nil)
}

// DropRemovedNotes is DropRemoved with the caller's word on which variables are still in use: inUse(name) is
// true for a variable whose line must stay in the env file (nil: DropRemoved's own rule).
func DropRemovedNotes(raws []map[string]any, inUse func(env string) bool) (kept []map[string]any, notes []string) {
	type gone struct {
		i   int
		raw map[string]any
	}
	var out []gone
	for i, raw := range raws {
		if typ, _ := raw["type"].(string); slices.Contains(Removed, typ) {
			out = append(out, gone{i, raw})
			continue
		}
		kept = append(kept, raw)
	}
	if out == nil {
		return raws, nil
	}
	if inUse == nil {
		inUse = func(env string) bool {
			for _, raw := range kept {
				for k, v := range raw {
					if s, ok := v.(string); ok && strings.HasSuffix(k, "_env") && strings.EqualFold(s, env) {
						return true
					}
				}
			}
			return false
		}
	}
	for _, g := range out {
		typ, _ := g.raw["type"].(string)
		name := fmt.Sprintf("#%d", g.i+1)
		if id, ok := g.raw["id"].(string); ok && id != "" {
			name = fmt.Sprintf("%q", id)
		}
		also := ""
		if env := secretEnvOf(g.raw); env != "" && inUse(env) {
			also = "; leave the line " + env + "=... in the env file: it is still in use"
		} else if env != "" {
			also = ", and the line " + env + "=... from the env file: the plug's key is not used any more"
		}
		notes = append(notes, fmt.Sprintf("power source %s: %s is no longer supported and is ignored (remove the entry from config.yaml%s)", name, typ, also))
	}
	return kept, notes
}

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
	}
	if slices.Contains(Removed, typ) { // only reached by a caller that did not use DropRemoved
		return nil, fmt.Errorf("power source %q: type %s is no longer supported", fmt.Sprint(raw["id"]), typ)
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
