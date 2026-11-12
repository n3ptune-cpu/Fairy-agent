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

// The type is gone from the built-in ones. Build, which a caller reaches only without DropRemoved, says that it
// is no longer supported (not "unknown"), and every other type still builds.
func TestTuyaIsNoLongerABuiltInType(t *testing.T) {
	for _, typ := range Types {
		if typ == "tuya" {
			t.Fatalf("Types still lists tuya: %v", Types)
		}
	}
	_, err := Build(map[string]any{"id": "desk-plug", "type": "tuya", "device_id": "plug1", "ip": "192.0.2.3", "local_key_env": "DESK_KEY"}, nil)
	if err == nil || !strings.Contains(err.Error(), `power source "desk-plug": type tuya is no longer supported`) {
		t.Fatalf("Build: %v", err)
	}
	for _, raw := range []map[string]any{
		{"id": "p", "type": "shelly", "url": "http://192.0.2.1"},
		{"id": "p", "type": "tasmota", "url": "http://192.0.2.1"},
		{"id": "p", "type": "nut", "host": "192.0.2.1"},
		{"id": "p", "type": "redfish", "url": "https://192.0.2.1", "password_env": "X"},
		{"id": "p", "type": "ipmi", "url": "https://192.0.2.1", "password_env": "X"},
		{"id": "p", "type": "agent", "agent": "pc"},
	} {
		if s, err := Build(raw, nil); err != nil || s.Info().Type != raw["type"] {
			t.Errorf("type %v: %v", raw["type"], err)
		}
	}
}

// TestDropRemovedNamesTheKeyVariable (audit 5, r1-a2-06): the note said only "remove the entry from
// config.yaml"; the plug's local key stayed in the env file. It now names the variable (never a value), and
// only a name that can be an environment variable's: what is in the entry is somebody's text.
func TestDropRemovedNamesTheKeyVariable(t *testing.T) {
	raws := []map[string]any{
		{"id": "desk-plug", "type": "tuya", "local_key_env": "DESK_KEY"},
		{"id": "b", "type": "tuya", "local_key_env": "DESK_KEY"}, // the same variable: named in both notes, once in the list
		{"id": "c", "type": "tuya", "local_key_env": "_k9"},
		{"id": "d", "type": "tuya"},
		{"id": "e", "type": "tuya", "local_key_env": 5},
		{"id": "f", "type": "tuya", "local_key_env": "A B"},
		{"id": "g", "type": "tuya", "local_key_env": "X\nlevel=ERROR msg=forged"},
		{"id": "h", "type": "tuya", "local_key_env": "9X"},
		{"id": "i", "type": "tuya", "local_key_env": strings.Repeat("K", 129)},
		{"id": "j", "type": "tuya", "local_key_env": "K=secret-value"},
		{"id": "s", "type": "shelly", "url": "http://192.0.2.1", "password_env": "SHELLY_PW", "local_key_env": "NOT_REMOVED"},
	}
	if got := strings.Join(RemovedSecretEnv(raws), ","); got != "DESK_KEY,_k9" {
		t.Fatalf("RemovedSecretEnv: %s", got)
	}
	_, notes := DropRemoved(raws)
	if len(notes) != 10 {
		t.Fatalf("notes: %q", notes)
	}
	const generic = "(remove the entry from config.yaml)"
	for i, want := range []string{"the line DESK_KEY=... from the env file", "the line DESK_KEY=... from the env file", "the line _k9=... from the env file",
		generic, generic, generic, generic, generic, generic, generic} {
		if !strings.Contains(notes[i], want) || strings.ContainsAny(notes[i], "\n\r") || strings.Contains(notes[i], "secret-value") || strings.Contains(notes[i], "forged") {
			t.Errorf("note %d: %q, want it to hold %q and nothing of the entry's own text", i, notes[i], want)
		}
	}
	if RemovedSecretEnv(nil) != nil || RemovedSecretEnv([]map[string]any{{"id": "s", "type": "shelly", "password_env": "P"}}) != nil {
		t.Error("names for a list without a removed entry")
	}
}

// TestDropRemovedLeavesALineThatIsStillInUse (audit 5, r2-a2-03): the note told the owner to delete the env
// file's line of a variable that an entry which stays still uses (a Shelly's password under the same name).
// It says "remove the line" only for a variable nothing else names, and "leave the line" otherwise.
func TestDropRemovedLeavesALineThatIsStillInUse(t *testing.T) {
	const remove, leave = ", and the line %s=... from the env file: the plug's key is not used any more)", "; leave the line %s=... in the env file: it is still in use)"
	raws := []map[string]any{
		{"id": "desk-plug", "type": "tuya", "local_key_env": "TUYA_KEY_DESK"},
		{"id": "plug-3", "type": "tuya", "local_key_env": "SHARED_PW"},
		{"id": "plug-4", "type": "tuya", "local_key_env": "shared_pw"}, // the same variable where names have no case
		{"id": "plug-5", "type": "tuya", "local_key_env": "TOKEN_OF_TASMOTA"},
		{"id": "plug-6", "type": "tuya", "local_key_env": "http://192.0.2.9"}, // not a name: nothing is said about it
		{"id": "plug-7", "type": "tuya", "local_key_env": "ONLY_AMONG_REMOVED"},
		{"id": "plug-8", "type": "tuya", "local_key_env": "ONLY_AMONG_REMOVED"}, // named by removed entries only
		{"id": "plug-9", "type": "tuya", "local_key_env": "A_URL"},              // a kept entry holds this text, but not as a variable's name
		{"id": "shelly-1", "type": "shelly", "url": "http://192.0.2.1", "password_env": "SHARED_PW"},
		{"id": "tasmota-1", "type": "tasmota", "url": "A_URL", "token_env": "Token_Of_Tasmota"},
	}
	want := []string{remove, leave, leave, leave, "", remove, remove, remove}
	check := func(what string, notes []string, want []string) {
		t.Helper()
		if len(notes) != len(want) {
			t.Fatalf("%s: notes: %q", what, notes)
		}
		for i, w := range want {
			env, _ := raws[i]["local_key_env"].(string)
			end := "(remove the entry from config.yaml)"
			if w != "" {
				end = "(remove the entry from config.yaml" + strings.Replace(w, "%s", env, 1)
			}
			if !strings.HasSuffix(notes[i], end) || strings.Count(notes[i], "env file") > 1 {
				t.Errorf("%s: note %d: %q, want it to end %q", what, i, notes[i], end)
			}
		}
	}
	kept, notes := DropRemoved(raws)
	if len(kept) != 2 {
		t.Fatalf("kept: %v", kept)
	}
	check("the list alone", notes, want)
	// a caller that knows more says so itself, name by name
	asked := map[string]int{}
	_, notes = DropRemovedNotes(raws, func(env string) bool { asked[env]++; return env == "TUYA_KEY_DESK" || env == "ONLY_AMONG_REMOVED" })
	check("the caller's word", notes, []string{leave, remove, remove, remove, "", leave, leave, remove})
	if asked["http://192.0.2.9"] != 0 || asked["SHARED_PW"] != 1 {
		t.Errorf("asked about: %v", asked)
	}
	if kept, notes := DropRemovedNotes(raws[8:], func(string) bool { t.Error("asked without a removed entry"); return true }); notes != nil || len(kept) != 2 {
		t.Errorf("a list without a removed entry: %v %q", kept, notes)
	}
}
