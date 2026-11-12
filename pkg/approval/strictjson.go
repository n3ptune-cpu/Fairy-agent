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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// maxJSONDepth is how deep objects and lists may nest in anything this package reads (a token's claims and a
// trust file are two levels deep).
const maxJSONDepth = 8

// checkJSON accepts exactly one JSON value in valid UTF-8 with nothing after it, whose objects have no name
// twice (compared without case: encoding/json matches struct fields without case, so "alg" and "ALG" would be
// the same field with the last one winning), nested at most maxJSONDepth deep.
func checkJSON(b []byte) error {
	if !utf8.Valid(b) {
		return errors.New("not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walkJSON(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the JSON value")
	}
	return nil
}

// CheckJSON is the strict look at a JSON text for the other programs' inputs that carry or frame an approval (a
// control request's body, a frame on the helper's pipe): exactly one value in valid UTF-8, nothing after it, no
// name twice in one object (without regard to case), nested at most eight deep. encoding/json alone takes the
// last of two members of one name, so two readers of one text could each believe another value.
func CheckJSON(b []byte) error { return checkJSON(b) }

func walkJSON(dec *json.Decoder, depth int) error {
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
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return errors.New("not valid JSON")
			}
			name, ok := k.(string)
			if !ok {
				return errors.New("not valid JSON")
			}
			name = strings.ToLower(name)
			if seen[name] {
				return errors.New("a name is used twice in one object")
			}
			seen[name] = true
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkJSON(dec, depth+1); err != nil {
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
