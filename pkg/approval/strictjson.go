// Package approval checks the passkey approval of a control action on the machine itself: the trust file (which
// Pocket ID, which client, which signing keys, which users), the offline check of the ID token, the challenges a
// token must answer, the fan window and the shutdown-after-boot setting. The Windows helper uses it (the agent
// is not trusted there); on every other system the agent uses it itself. The protocol is described next to the
// wire types in pkg/agent/api (approval.go).
//
// Nothing here opens a network connection, and it uses the standard library only. Every input is treated as
// hostile: sizes are bounded before anything is parsed, JSON is read strictly, and no input can make it panic
// (see the fuzz tests).
package approval

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxJSONDepth is how deep objects and lists may nest in anything this package reads (a token's claims and a
// trust file are two levels deep).
const maxJSONDepth = 8

// checkJSON accepts exactly one JSON value in valid UTF-8 with nothing after it, whose objects have no name
// twice, nested at most maxJSONDepth deep. Two names are the same name when encoding/json would read them
// into the same struct field: it matches a member to a field without regard to case, by Unicode's simple case
// folding (foldName), so "alg" and "ALG" are one field with the last one winning, and so are "delay_s" and
// "delay_\u017f" (a long s) or "keys" and "\u212aeys" (a Kelvin sign).
func checkJSON(b []byte) error { return checkJSONAs(b, nil) }

// checkJSONAs is checkJSON for a text that is read into a value of type t afterwards (nil: not known).
func checkJSONAs(b []byte, t reflect.Type) error {
	if !utf8.Valid(b) {
		return errors.New("not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walkJSON(dec, 0, t); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the JSON value")
	}
	return nil
}

// CheckJSON is the strict look at a JSON text for the other programs' inputs that carry or frame an approval (a
// control request's body, a frame on the helper's pipe): exactly one value in valid UTF-8, nothing after it, no
// name twice in one object (without regard to case, as encoding/json folds it), nested at most eight deep.
// encoding/json alone takes the last of two members of one name, so two readers of one text could each
// believe another value.
func CheckJSON(b []byte) error { return checkJSON(b) }

// CheckJSONFor is CheckJSON for a text that encoding/json then reads into v (a pointer to a struct), with one
// more rule: a member that encoding/json would read into a field of v, or of a struct inside v, must be
// spelled exactly as that field is. encoding/json takes every spelling that is the same without case:
// "DELAY_S" is "delay_s" to it, and so is "delay_\u017f". Such a member is refused, alone or next to the
// exact one, so that the text has one reading for every reader (audit 5, r3-a1-02: the check for "no name
// twice" compared lower-case forms and let "delay_s" pass next to "delay_\u017f"; the second value ran).
// Members v has no field for are not judged here: whoever decodes decides whether they are allowed.
func CheckJSONFor(b []byte, v any) error { return checkJSONAs(b, reflect.TypeOf(v)) }

// foldName is the form of a member name under which encoding/json compares it with a field's name when the
// two are not the same bytes (its own foldName, written out here because it is not exported): ASCII letters
// in upper case, every other character replaced by the smallest of the characters that are equal to it under
// Unicode's simple case folding. Two names have the same form exactly when strings.EqualFold says they are
// equal. TestFoldNameIsEncodingJSONs holds it against encoding/json itself.
func foldName(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r < utf8.RuneSelf {
			if 'a' <= r && r <= 'z' {
				r -= 'a' - 'A'
			}
			out = append(out, byte(r))
			continue
		}
		for {
			r2 := unicode.SimpleFold(r)
			if r2 <= r {
				r = r2
				break
			}
			r = r2
		}
		out = utf8.AppendRune(out, r)
	}
	return string(out)
}

var (
	jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()
)

// jsonTarget is the type encoding/json fills from a JSON object or list that is read into a t: t without its
// pointers. nil when t is not known, or reads its JSON itself (json.RawMessage), or is an interface.
func jsonTarget(t reflect.Type) reflect.Type {
	for t != nil {
		if t.Kind() == reflect.Interface || t.Implements(jsonUnmarshalerType) || reflect.PointerTo(t).Implements(jsonUnmarshalerType) ||
			t.Implements(textUnmarshalerType) || reflect.PointerTo(t).Implements(textUnmarshalerType) {
			return nil
		}
		if t.Kind() != reflect.Pointer {
			return t
		}
		t = t.Elem()
	}
	return nil
}

// jsonFields are the member names encoding/json knows for struct type t, each with its field's type, and the
// folded forms of those names.
func jsonFields(t reflect.Type) (exact map[string]reflect.Type, folded map[string]bool) {
	exact, folded = map[string]reflect.Type{}, map[string]bool{}
	for _, f := range reflect.VisibleFields(t) {
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if !f.IsExported() || tag == "-" {
			continue
		}
		if f.Anonymous && name == "" { // an embedded struct: its fields are members of t and are listed themselves
			if ft := jsonTarget(f.Type); ft != nil && ft.Kind() == reflect.Struct {
				continue
			}
		}
		if name == "" {
			name = f.Name
		}
		exact[name] = f.Type
		folded[foldName(name)] = true
	}
	return exact, folded
}

func walkJSON(dec *json.Decoder, depth int, t reflect.Type) error {
	tok, err := dec.Token()
	if err != nil {
		return errors.New("not valid JSON")
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxJSONDepth {
		return errors.New("nested too deep")
	}
	t = jsonTarget(t)
	switch d {
	case '{':
		var exact map[string]reflect.Type
		var known map[string]bool
		if t != nil && t.Kind() == reflect.Struct {
			exact, known = jsonFields(t)
		}
		seen, seenLower := map[string]bool{}, map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return errors.New("not valid JSON")
			}
			name, ok := k.(string)
			if !ok {
				return errors.New("not valid JSON")
			}
			// "twice" by encoding/json's own folding, and by lower case as this check compared before it knew
			// that folding (so nothing it refused then passes now: lower case also joins "I" with a dot above,
			// U+0130, and "i", which encoding/json keeps apart)
			folded, lower := foldName(name), strings.ToLower(name)
			if seen[folded] || seenLower[lower] {
				return errors.New("a name is used twice in one object")
			}
			seen[folded], seenLower[lower] = true, true
			var member reflect.Type // what the member's value is read into, where that is known
			switch {
			case exact != nil:
				if member, ok = exact[name]; !ok && known[folded] {
					return errors.New("a name is not spelled exactly as the member it would be read as")
				}
			case t != nil && t.Kind() == reflect.Map:
				member = t.Elem()
			}
			if err := walkJSON(dec, depth+1, member); err != nil {
				return err
			}
		}
	case '[':
		var item reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			item = t.Elem()
		}
		for dec.More() {
			if err := walkJSON(dec, depth+1, item); err != nil {
				return err
			}
		}
	default:
		return errors.New("not valid JSON")
	}
	if _, err := dec.Token(); err != nil { // the closing bracket
		return errors.New("not valid JSON")
	}
	return nil
}

// decodeStrict reads b into v: checkJSON, and no field v does not have.
func decodeStrict(b []byte, v any) error {
	if err := checkJSON(b); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		msg, _, _ := strings.Cut(err.Error(), "\n")
		if len(msg) > 120 {
			msg = msg[:120]
		}
		return errors.New(msg)
	}
	return nil
}

// decodeObject reads b as one JSON object with its members unparsed. Names keep their exact spelling.
func decodeObject(b []byte) (map[string]json.RawMessage, error) {
	if err := checkJSON(b); err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, errors.New("not a JSON object")
	}
	return m, nil
}

// jsonString is a member that must be a JSON string.
func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// b64url decodes base64url without padding and nothing else: only the 64 characters of the URL-safe alphabet
// (encoding/base64 skips line breaks even in strict mode, so they are refused here first), no "=", and no stray
// bits in the last character.
func b64url(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, errors.New("not base64url")
		}
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}
