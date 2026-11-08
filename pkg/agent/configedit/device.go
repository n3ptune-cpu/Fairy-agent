package configedit

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrListNotEmpty: AddDevice only fills an empty device list; entries that exist are edited by hand.
var ErrListNotEmpty = errors.New("the list already has entries")

// KV is one setting of a device entry, in the order it is written.
type KV struct {
	Key   string
	Value any // bool, int, float64, string or []string
}

// AddDevice puts one device entry (e.g. the local NUT server under `ups`) into a top-level device list that is
// empty (`ups: []`, `ups:`) or missing, as one flow-style line: `ups: [{id: local-ups, host: 127.0.0.1}]`.
// Comments and everything else stay as they are; the result is decoded again and must differ only there.
func AddDevice(data []byte, list string, item []KV) ([]byte, error) {
	var parts []string
	want := map[string]any{}
	for _, kv := range item {
		r, err := Render(kv.Value)
		if err != nil {
			return nil, err
		}
		parts = append(parts, kv.Key+": "+r)
		want[kv.Key] = kv.Value
	}
	text := "[{" + strings.Join(parts, ", ") + "}]"
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("config.yaml is not valid YAML, fix it by hand first: %w", err)
	}
	var top *yaml.Node
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		top = root.Content[0]
	}
	if n := find(top, []string{list}); n != nil && !isNull(n) && (n.Kind != yaml.SequenceNode || len(n.Content) > 0) {
		return nil, fmt.Errorf("%s: %w", list, ErrListNotEmpty)
	}
	d := newDoc(data)
	e, err := d.plan(top, []string{list}, text)
	if err != nil {
		return nil, fmt.Errorf("cannot add to %s safely (%v): edit config.yaml by hand", list, err)
	}
	out := d.apply(e)
	var a, b map[string]any
	if err := yaml.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(out, &b); err != nil {
		return nil, fmt.Errorf("cannot add to %s safely (%v): edit config.yaml by hand", list, err)
	}
	if a == nil {
		a = map[string]any{}
	}
	got, _ := b[list].([]any)
	if len(got) != 1 || !sameItem(got[0], want) {
		return nil, fmt.Errorf("cannot add to %s safely (it reads back as %v): edit config.yaml by hand", list, b[list])
	}
	delete(a, list)
	delete(b, list)
	if !reflect.DeepEqual(prune(a), prune(b)) {
		return nil, fmt.Errorf("cannot add to %s safely (other settings would change): edit config.yaml by hand", list)
	}
	return out, nil
}

func sameItem(got any, want map[string]any) bool {
	m, ok := got.(map[string]any)
	if !ok || len(m) != len(want) {
		return false
	}
	for k, v := range want {
		g := m[k]
		if l, ok := v.([]string); ok {
			gl, _ := g.([]any)
			if len(gl) != len(l) {
				return false
			}
			for i := range l {
				if gl[i] != l[i] {
					return false
				}
			}
			continue
		}
		if g != v {
			return false
		}
	}
	return true
}
