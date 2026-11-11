package power

import (
	"strings"
	"testing"
)

const ignoredText = "tuya is no longer supported and is ignored"

// Tuya was removed. A power_sources entry of that type is taken out of the list with one line that names it;
// the entries around it stay as they are, in their order.
func TestDropRemovedTakesOutTuyaEntries(t *testing.T) {
	shelly := map[string]any{"id": "shelly-1", "type": "shelly", "url": "http://192.0.2.1"}
	nut := map[string]any{"id": "rack", "type": "nut", "host": "192.0.2.2"}
	raws := []map[string]any{
		shelly,
		{"id": "desk-plug", "type": "tuya", "name": "Desk plug", "device_id": "plug1", "ip": "192.0.2.3", "local_key_env": "DESK_KEY",
			"version": "3.4", "dps": map[string]any{"power": map[string]any{"dp": "19", "scale": 0.1}}, "refresh_dps": []any{18, 19, 20}},
		nut,
		{"type": "tuya"}, // not even an id: named by its place
		{"id": 7, "type": "tuya", "nonsense": true, "version": "9.9"}, // whatever else it holds
	}
	kept, notes := DropRemoved(raws)
	if len(kept) != 2 || kept[0]["id"] != "shelly-1" || kept[1]["id"] != "rack" {
		t.Fatalf("kept: %v", kept)
	}
	want := []string{`power source "desk-plug": ` + ignoredText, "power source #4: " + ignoredText, "power source #5: " + ignoredText}
	if len(notes) != len(want) {
		t.Fatalf("notes: %q", notes)
	}
	for i, w := range want {
		if !strings.HasPrefix(notes[i], w) || strings.Contains(notes[i], "\n") {
			t.Errorf("note %d: %q, want it to start with %q", i, notes[i], w)
		}
	}
	if len(raws) != 5 || raws[1]["type"] != "tuya" {
		t.Fatalf("the caller's list was changed: %v", raws)
	}
	if err := ValidateConfigs(kept); err != nil {
		t.Fatalf("what is left is a valid list: %v", err)
	}
}

// Without such an entry nothing changes: the same list comes back and there is nothing to say.
func TestDropRemovedLeavesOtherListsAlone(t *testing.T) {
	for name, raws := range map[string][]map[string]any{
		"nil":   nil,
		"empty": {},
		"others": {{"id": "a", "type": "shelly", "url": "http://192.0.2.1"}, {"id": "b", "type": "tasmota", "url": "http://192.0.2.2"},
			{"id": "c", "type": "Tuya"}, {"id": "d", "type": 5}, {"id": "e"}}, // only the exact old spelling is the old type
	} {
		kept, notes := DropRemoved(raws)
		if notes != nil || len(kept) != len(raws) || (raws == nil) != (kept == nil) {
			t.Errorf("%s: kept %v, notes %q", name, kept, notes)
		}
	}
	if kept, notes := DropRemoved([]map[string]any{{"id": "only", "type": "tuya"}}); len(kept) != 0 || len(notes) != 1 {
		t.Errorf("a list of one old entry: kept %v, notes %q", kept, notes)
	}
}
