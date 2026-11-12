package approval_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// jsonReadsAs reports whether encoding/json reads a member called member into a struct field whose JSON name
// is field: asked of encoding/json itself, with a struct made for the question.
func jsonReadsAs(t *testing.T, member, field string) bool {
	t.Helper()
	st := reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.TypeFor[int](), Tag: reflect.StructTag(`json:"` + field + `"`)}})
	v := reflect.New(st)
	name, _ := json.Marshal(member)
	if err := json.Unmarshal([]byte(`{`+string(name)+`:7}`), v.Interface()); err != nil {
		t.Fatalf("member %q into field %q: %v", member, field, err)
	}
	return v.Elem().Field(0).Int() == 7
}

// TestFoldNameIsEncodingJSONs: the strict look calls two member names "the same name" when their foldName is
// the same. That must be exactly when encoding/json reads the one into a field named like the other; otherwise
// a pair that the check lets through is still one field to the decoder (audit 5, r3-a1-02: the check compared
// strings.ToLower forms, under which "delay_s" and "delay_\u017f" differ, and encoding/json does not).
func TestFoldNameIsEncodingJSONs(t *testing.T) {
	// every character there is, as a member name of its own, against the fields "k" and "s" (the two ASCII
	// letters that have a third spelling: the Kelvin sign U+212A and the long s U+017F) and against "e"
	k, s := []string{}, []string{}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		c := string(r)
		f := approval.FoldName(c)
		if f == "K" {
			k = append(k, c)
		}
		if f == "S" {
			s = append(s, c)
		}
		if r < 0x3000 || f == "K" || f == "S" || f == "E" { // the decoder itself is asked for these (it is slow for a million)
			for _, field := range []string{"k", "s", "e"} {
				if got, want := approval.FoldName(c) == approval.FoldName(field), jsonReadsAs(t, c, field); got != want {
					t.Fatalf("U+%04X against field %q: foldName says same=%v, encoding/json reads it into the field: %v", r, field, got, want)
				}
			}
		}
		// and for every character: the same form exactly when strings.EqualFold says equal, against the
		// other spellings of the character and against its neighbour
		for o := unicode.SimpleFold(r); ; o = unicode.SimpleFold(o) {
			if approval.FoldName(string(o)) != f {
				t.Fatalf("U+%04X and U+%04X fold to each other, their forms differ", r, o)
			}
			if o == r {
				break
			}
		}
		if n := r + 1; utf8.ValidRune(n) {
			if got, want := approval.FoldName(string(n)) == f, strings.EqualFold(string(n), c); got != want {
				t.Fatalf("U+%04X and U+%04X: same form %v, strings.EqualFold %v", r, n, got, want)
			}
		}
	}
	if strings.Join(k, " ") != "K k \u212a" || strings.Join(s, " ") != "S s \u017f" {
		t.Errorf("the spellings of k: %q, of s: %q", k, s)
	}
	// whole names, as the requests have them
	for _, c := range []struct {
		member, field string
		same          bool
	}{
		{"delay_s", "delay_s", true}, {"DELAY_S", "delay_s", true}, {"Delay_S", "delay_s", true}, {"delay_\u017f", "delay_s", true},
		{"\u212aeys", "keys", true}, {"\u212aEY\u017f", "keys", true}, {"u\u017fer\u017f", "users", true}, {"i\u017f\u017fuer", "issuer", true},
		{"to\u212aen", "token", true}, {"reque\u017ft", "request", true}, {"tru\u017ft_ha\u017fh", "trust_hash", true},
		{"delay-s", "delay_s", false}, {"delays", "delay_s", false}, {"delay_s ", "delay_s", false}, {"delay_\u0455", "delay_s", false}, // a Cyrillic letter that looks like s
		{"\u0131ssuer", "issuer", false}, {"\u0130ssuer", "issuer", false}, // dotless i, I with a dot: no other spelling of i
		{"stra\u00dfe", "STRA\u1e9eE", true}, {"strasse", "stra\u00dfe", false},
	} {
		if got := approval.FoldName(c.member) == approval.FoldName(c.field); got != c.same {
			t.Errorf("%q and %q: same form %v, want %v", c.member, c.field, got, c.same)
		}
		if got := jsonReadsAs(t, c.member, c.field); got != c.same {
			t.Errorf("%q into field %q: encoding/json reads it: %v, the table says %v", c.member, c.field, got, c.same)
		}
	}
}

// TestCheckJSONNamesThatFoldToOne (audit 5, r3-a1-02): two members of one object whose names encoding/json
// takes for one are "a name twice", whichever way they differ.
func TestCheckJSONNamesThatFoldToOne(t *testing.T) {
	const twice = "a name is used twice in one object"
	for _, c := range []struct{ in, want string }{
		{`{"delay_s":3600,"delay_s":60}`, twice},
		{`{"delay_s":3600,"DELAY_S":60}`, twice},
		{`{"delay_s":3600,"delay_` + "\u017f" + `":60}`, twice}, // the auditor's body: a long s, U+017F
		{`{"delay_s":3600,"delay_\u017f":60}`, twice},           // the same name, written as a JSON escape
		{`{"delay_` + "\u017f" + `":3600,"DELAY_S":60}`, twice},
		{`{"keys":[],"` + "\u212a" + `eys":[]}`, twice}, // a Kelvin sign
		{`{"a":{"b":[{"users":1,"u` + "\u017f" + `ers":2}]}}`, twice},
		{`{"stra` + "\u00df" + `e":1,"STRA` + "\u1e9e" + `E":2}`, twice},
		{`{"delay_s":3600,"delay_` + "\u0455" + `":60}`, ""}, // Cyrillic: another name, also to encoding/json
		{`{"i":1,"` + "\u0131" + `":2}`, ""},                 // a dotless i is another name, to encoding/json and in lower case
		{`{"i":1,"` + "\u0130" + `":3}`, twice},              // I with a dot above: another name to encoding/json, but "i" in lower case: refused as before this change
		{`{"I":1,"\u0130":3}`, twice},                        // the same
		{`{"` + "\u0131" + `":1,"` + "\u0130" + `":3}`, ""},  // those two differ in every form
		{`{"delay_s":60,"delay-s":60,"delays":60}`, ""},
		{`{"DELAY_S":60}`, ""}, // one member, and no struct is named here that would say how it is spelled
	} {
		err := approval.CheckJSON([]byte(c.in))
		if got := errText(err); got != c.want {
			t.Errorf("%s: %q, want %q", c.in, got, c.want)
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestCheckJSONForExactNames: read into a struct, a member that encoding/json would take for one of the
// struct's fields must be spelled as that field is, at every depth the struct has; everything the struct does
// not know is left to the decoder.
func TestCheckJSONForExactNames(t *testing.T) {
	type entry struct {
		Request string `json:"request"`
	}
	type inner struct {
		Token   string  `json:"token"`
		Entries []entry `json:"entries"`
	}
	type Embedded struct {
		Kind string `json:"kind"`
	}
	type body struct {
		Embedded
		Action   string           `json:"action"`
		DelayS   json.RawMessage  `json:"delay_s"`
		Who      any              `json:"requested_by"`
		Approval *inner           `json:"approval,omitempty"`
		ByName   map[string]entry `json:"by_name"`
		Plain    int              // no tag: the member is "Plain"
		Hidden   string           `json:"-"`
		Dash     string           `json:"-,"` // the member is "-"
	}
	const twice, spelled = "a name is used twice in one object", "a name is not spelled exactly as the member it would be read as"
	for _, c := range []struct{ in, want string }{
		{`{"action":"shutdown","delay_s":60,"requested_by":"a","approval":{"token":"t","entries":[{"request":"r"}]},"by_name":{"X":{"request":"r"}},"Plain":1,"kind":"k","-":"d"}`, ""},
		{`{"action":"shutdown","delay_s":3600,"delay_` + "\u017f" + `":60}`, twice},
		{`{"action":"shutdown","DELAY_S":60}`, spelled},
		{`{"action":"shutdown","delay_` + "\u017f" + `":60}`, spelled},
		{`{"action":"shutdown","delay_\u017f":60}`, spelled}, // written as a JSON escape
		{`{"Action":"shutdown"}`, spelled},
		{`{"ACTION":"shutdown"}`, spelled},
		{`{"action":"shutdown","Requested_By":"a"}`, spelled},
		{`{"action":"shutdown","approval":{"to` + "\u212a" + `en":"t","entries":[]}}`, spelled}, // a Kelvin sign
		{`{"action":"shutdown","approval":{"token":"t","Entries":[]}}`, spelled},
		{`{"action":"shutdown","approval":{"token":"t","entries":[{"request":"r"},{"reque` + "\u017f" + `t":"r"}]}}`, spelled},
		{`{"by_name":{"X":{"Request":"r"}}}`, spelled},
		{`{"by_name":{"X":{"request":"r"},"x":{"request":"r"}}}`, twice}, // the same for a map as for any object
		{`{"plain":1}`, spelled}, {`{"PLAIN":1}`, spelled},
		{`{"Kind":"k"}`, spelled},                          // a field of the embedded struct
		{`{"hidden":"h","Hidden":"h2","HIDDEN":3}`, twice}, // not a member of the struct at all: unknown names, and two that fold to one
		{`{"hidden":"h"}`, ""},
		{`{"Embedded":{"Kind":1}}`, ""}, // not a member either
		{`{"action":"shutdown","Comment":"x","X-Other":{"Action":1,"DELAY_S":2}}`, ""}, // unknown members, and what is inside them
		{`{"action":"shutdown","requested_by":{"Action":"x","Name":"y"}}`, ""},         // inside a member of any shape
		{`{"action":"shutdown","requested_by":{"name":"y","NAME":"z"}}`, twice},
		{`{"action":"shutdown","delay_s":{"Action":1}}`, ""}, // inside a member the struct keeps as raw text
		{`[{"Action":1}]`, ""},             // not an object: nothing of the struct applies
		{`{"approval":[{"Token":1}]}`, ""}, // a list where the struct has an object: the decoder refuses it, not this check
	} {
		for _, v := range []any{&body{}, body{}, new(*body)} {
			if got := errText(approval.CheckJSONFor([]byte(c.in), v)); got != c.want {
				t.Errorf("%s into %T: %q, want %q", c.in, v, got, c.want)
			}
		}
	}
	// without a struct to read into, only "twice" is judged
	if err := approval.CheckJSONFor([]byte(`{"Action":"shutdown","DELAY_S":1}`), nil); err != nil {
		t.Error(err)
	}
	var m map[string]any
	if err := approval.CheckJSONFor([]byte(`{"Action":"shutdown","DELAY_S":1}`), &m); err != nil {
		t.Error(err)
	}
}

// TestCheckJSONForLetsNoFoldedMemberReachAField: for a few hundred bodies made of exact and folded spellings
// of a request's members, in any order: when the check passes, encoding/json has filled every field from the
// member that is spelled exactly, and from nothing else.
func TestCheckJSONForLetsNoFoldedMemberReachAField(t *testing.T) {
	type req struct {
		Action string `json:"action"`
		DelayS int    `json:"delay_s"`
		Keys   int    `json:"keys"`
	}
	spell := map[string][]string{
		"action":  {"action", "Action", "ACTION", "actIon"},
		"delay_s": {"delay_s", "DELAY_S", "delay_\u017f", "Delay_s"},
		"keys":    {"keys", "\u212aeys", "KEYS", "key\u017f"},
	}
	passed, refused := 0, 0
	for _, a := range spell["action"] {
		for _, d1 := range spell["delay_s"] {
			for _, d2 := range append([]string{""}, spell["delay_s"]...) {
				for _, k := range spell["keys"] {
					na, _ := json.Marshal(a)
					nd1, _ := json.Marshal(d1)
					nk, _ := json.Marshal(k)
					in := `{` + string(na) + `:"shutdown",` + string(nd1) + `:1,` + string(nk) + `:3`
					if d2 != "" {
						nd2, _ := json.Marshal(d2)
						in += `,` + string(nd2) + `:2`
					}
					in += `}`
					exactOnly := a == "action" && d1 == "delay_s" && k == "keys" && d2 == ""
					err := approval.CheckJSONFor([]byte(in), &req{})
					if (err == nil) != exactOnly {
						t.Fatalf("%s: %v, want it to pass: %v", in, err, exactOnly)
					}
					if err == nil {
						passed++
					} else {
						refused++
					}
				}
			}
		}
	}
	if passed != 1 || refused != 4*4*5*4-1 {
		t.Errorf("passed %d, refused %d", passed, refused)
	}
}
