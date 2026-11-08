package devices

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

// DigestAuthorization builds an RFC 7616 Authorization header (MD5 or SHA-256, qop=auth) for a challenge.
// Shelly Gen2+ uses SHA-256 digest auth.
func DigestAuthorization(challenge, method, uri, user, pass string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(challenge), "digest ") {
		return "", Errf("auth: unsupported challenge")
	}
	params := parseAuthParams(challenge[7:])
	realm, nonce := params["realm"], params["nonce"]
	if nonce == "" {
		return "", Errf("auth: no nonce in challenge")
	}
	algo := strings.ToUpper(params["algorithm"])
	var h func() hash.Hash
	switch algo {
	case "", "MD5":
		h, algo = md5.New, "MD5"
	case "SHA-256":
		h = sha256.New
	default:
		return "", Errf("auth: unsupported digest algorithm")
	}
	sum := func(s string) string { x := h(); x.Write([]byte(s)); return hex.EncodeToString(x.Sum(nil)) }
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	cnonce := hex.EncodeToString(b)
	ha1 := sum(user + ":" + realm + ":" + pass)
	ha2 := sum(method + ":" + uri)
	nc := "00000001"
	var response string
	qop := ""
	if q := params["qop"]; q != "" {
		qop = "auth"
		response = sum(strings.Join([]string{ha1, nonce, nc, cnonce, qop, ha2}, ":"))
	} else {
		response = sum(ha1 + ":" + nonce + ":" + ha2)
	}
	hdr := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s, response="%s"`,
		user, realm, nonce, uri, algo, response)
	if qop != "" {
		hdr += fmt.Sprintf(`, qop=%s, nc=%s, cnonce="%s"`, qop, nc, cnonce)
	}
	if op := params["opaque"]; op != "" {
		hdr += fmt.Sprintf(`, opaque="%s"`, op)
	}
	return hdr, nil
}

func parseAuthParams(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ,")
		k, rest, ok := strings.Cut(s, "=")
		if !ok {
			break
		}
		k = strings.ToLower(strings.TrimSpace(k))
		var v string
		if strings.HasPrefix(rest, `"`) {
			end := strings.Index(rest[1:], `"`)
			if end < 0 {
				v, s = rest[1:], ""
			} else {
				v, s = rest[1:1+end], rest[2+end:]
			}
		} else {
			v, s, _ = strings.Cut(rest, ",")
		}
		out[k] = strings.TrimSpace(v)
	}
	return out
}
