package approval

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// ClockAllowance is how far this machine's clock and Pocket ID's may differ: every comparison of a time in the
// token with this machine's clock gives this much. A machine whose clock is further off refuses every approval;
// a wrong clock never makes it accept one.
const ClockAllowance = 60 * time.Second

// Reasons an approval is refused (the word in "approval refused (<reason>)" and in the log).
const (
	ReasonEntries     = "entries"           // the list is malformed, or names this machine's challenge with another request
	ReasonNoChallenge = "no_challenge"      // no entry has an open challenge of this machine for this request
	ReasonAmbiguous   = "ambiguous"         // more than one entry does
	ReasonExpired     = "challenge_expired" // the challenge is too old
	ReasonFormat      = "token_format"      // not three base64url parts, too large
	ReasonHeader      = "token_header"      // the header is not strict JSON, or has a member that selects a key or changes the processing
	ReasonAlg         = "token_alg"         // not RS256
	ReasonKey         = "token_key"         // the key id is not pinned
	ReasonSignature   = "token_signature"
	ReasonClaims      = "token_claims" // the payload is not strict JSON, or a claim has the wrong type
	ReasonIssuer      = "issuer"
	ReasonAudience    = "audience"
	ReasonUser        = "user"      // sub is not an allowed user
	ReasonTokenExp    = "expired"   // exp has passed
	ReasonClock       = "clock"     // a time in the token is in this machine's future, or before the challenge
	ReasonAuthTime    = "auth_time" // no auth_time, or the user authenticated before the challenge was issued
	ReasonAMR         = "amr"       // not a passkey sign-in
	ReasonNonce       = "nonce"
)

// headerRefused are header members a token for this check never needs: each would select a key from the token
// itself or change how it is processed. "crit" is refused whatever it lists, since no extension is understood.
var headerRefused = []string{"jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256", "crit", "b64", "zip", "enc"}

// claims are what the caller logs of an accepted (or, as far as known, a refused) token.
type claims struct {
	Sub  string
	Name string // preferred_username, cleaned; for the log only
	Kid  string
	// Iat is the token's "iat", set once it was read from a token whose signature holds (the zero time before
	// that). A run ticket is compared with the moment this machine started by it (Gate.Arm).
	Iat time.Time
}

// verifyToken checks the compact ID token tok against t. nonce is the nonce of the entry list it must carry,
// now this machine's clock, issued when the challenge was issued by that same clock. It returns the reason of
// the first check that fails. Nothing of the token is used before its signature is verified except the
// header's alg and kid.
func verifyToken(tok string, t *Trust, nonce string, now, issued time.Time) (claims, string) {
	var c claims
	if len(tok) == 0 || len(tok) > api.MaxApprovalToken {
		return c, ReasonFormat
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return c, ReasonFormat
	}
	hb, err1 := b64url(parts[0])
	pb, err2 := b64url(parts[1])
	sig, err3 := b64url(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return c, ReasonFormat
	}
	hdr, err := decodeObject(hb)
	if err != nil {
		return c, ReasonHeader
	}
	for _, name := range headerRefused {
		if _, has := hdr[name]; has {
			return c, ReasonHeader
		}
	}
	if raw, has := hdr["typ"]; has {
		if typ, ok := jsonString(raw); !ok || !strings.EqualFold(typ, "JWT") {
			return c, ReasonHeader
		}
	}
	alg, ok := jsonString(hdr["alg"])
	if !ok {
		return c, ReasonHeader
	}
	if alg != "RS256" { // "none", HS256 with the public key as the secret, and everything else
		return c, ReasonAlg
	}
	kid, ok := jsonString(hdr["kid"])
	if !ok {
		return c, ReasonKey
	}
	pub := t.pub[kid]
	if pub == nil {
		return c, ReasonKey
	}
	c.Kid = kid
	if len(sig) != pub.Size() {
		return c, ReasonSignature
	}
	sum := sha256.Sum256([]byte(tok[:len(parts[0])+1+len(parts[1])]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
		return c, ReasonSignature
	}

	// From here on the payload is Pocket ID's own text.
	cl, err := decodeObject(pb)
	if err != nil {
		return c, ReasonClaims
	}
	if iss, ok := jsonString(cl["iss"]); !ok || iss != t.Issuer {
		return c, ReasonIssuer
	}
	if !audienceIs(cl["aud"], t.ClientID) {
		return c, ReasonAudience
	}
	if raw, has := cl["azp"]; has {
		if azp, ok := jsonString(raw); !ok || azp != t.ClientID {
			return c, ReasonAudience
		}
	}
	got, ok := jsonString(cl["nonce"])
	if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return c, ReasonNonce
	}
	sub, ok := jsonString(cl["sub"])
	if !ok {
		return c, ReasonClaims
	}
	c.Sub = cleanForLog(sub)
	if name, ok := jsonString(cl["preferred_username"]); ok {
		c.Name = cleanForLog(name)
	}
	if !slices.Contains(t.Users, sub) {
		return c, ReasonUser
	}
	exp, ok := numericDate(cl["exp"])
	if !ok {
		return c, ReasonClaims
	}
	if !now.Before(exp.Add(ClockAllowance)) {
		return c, ReasonTokenExp
	}
	iat, ok := numericDate(cl["iat"])
	if !ok {
		return c, ReasonClaims
	}
	c.Iat = iat
	if iat.After(now.Add(ClockAllowance)) || iat.Before(issued.Add(-ClockAllowance)) {
		return c, ReasonClock // the token was made for this challenge, so it cannot be older than it
	}
	if raw, has := cl["nbf"]; has {
		nbf, ok := numericDate(raw)
		if !ok {
			return c, ReasonClaims
		}
		if nbf.After(now.Add(ClockAllowance)) {
			return c, ReasonClock
		}
	}
	raw, has := cl["auth_time"]
	if !has {
		return c, ReasonAuthTime
	}
	at, ok := numericDate(raw)
	if !ok {
		return c, ReasonClaims
	}
	if at.After(now.Add(ClockAllowance)) {
		return c, ReasonClock
	}
	if at.Before(issued.Add(-ClockAllowance)) {
		return c, ReasonAuthTime // the user's last authentication is older than the challenge: no fresh check
	}
	var amr []string
	if raw, has := cl["amr"]; !has || json.Unmarshal(raw, &amr) != nil || !slices.Contains(amr, "phr") {
		return c, ReasonAMR
	}
	return c, ""
}

// audienceIs: aud is the client id as a string, or a list with exactly that one string.
func audienceIs(raw json.RawMessage, clientID string) bool {
	if s, ok := jsonString(raw); ok {
		return s == clientID
	}
	var list []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &list) != nil || len(list) != 1 {
		return false
	}
	s, ok := jsonString(list[0])
	return ok && s == clientID
}

// numericDate reads a NumericDate claim (seconds since 1970, whole or with a fraction): a JSON number between
// 0 and the year 5000.
func numericDate(raw json.RawMessage) (time.Time, bool) {
	if len(raw) == 0 || len(raw) > 32 || !(raw[0] >= '0' && raw[0] <= '9') {
		return time.Time{}, false
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 95617584000 {
		return time.Time{}, false
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), true
}

// cleanForLog keeps letters, digits and " ._@-" of s, at most 64 characters: what the audit log already
// accepts for a requester's name.
func cleanForLog(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 64 {
			break
		}
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune(" ._@-", r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
