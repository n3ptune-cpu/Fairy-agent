package approval_test

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

func mustKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestTokenChecks: every check of the ID token, each with a token that fails exactly that one. The request, the
// challenge and the entry list are good every time; only the token differs.
func TestTokenChecks(t *testing.T) {
	r := newRig(t, true)
	req := power("shutdown", 60)
	e := r.entry(req)
	entries := []api.MachineEntry{e}
	nonce, _ := api.ApprovalNonce(entries)
	iss, now := r.iss, r.Now()
	good := func() map[string]any { return iss.Claims(nonce, now) }
	with := func(k string, v any) string {
		c := good()
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return iss.Token(c)
	}
	hdr := func(extra map[string]any) string { return iss.Sign(iss.Header(extra), jsonOf(good())) }
	unsigned := func(header string) string { // a token with this header, the good claims and no usable signature
		return approvaltest.B64([]byte(header)) + "." + approvaltest.B64([]byte(jsonOf(good())))
	}
	other := *iss
	other.Key = approvaltest.Key(1)
	goodTok := iss.Token(good())
	parts := strings.Split(goodTok, ".")
	pub := x509.MarshalPKCS1PublicKey(&iss.Key.PublicKey)
	hs := unsigned(`{"alg":"HS256","kid":"` + iss.Kid + `","typ":"JWT"}`)
	mac := hmac.New(sha256.New, pub)
	mac.Write([]byte(hs))
	rs512 := unsigned(`{"alg":"RS512","kid":"` + iss.Kid + `"}`)
	sum512 := sha512.Sum512([]byte(rs512))
	sig512, _ := rsa.SignPKCS1v15(rand.Reader, iss.Key, crypto.SHA512, sum512[:])
	ps := unsigned(`{"alg":"PS256","kid":"` + iss.Kid + `"}`)
	sumPS := sha256.Sum256([]byte(ps))
	sigPS, _ := rsa.SignPSS(rand.Reader, iss.Key, crypto.SHA256, sumPS[:], nil)
	loginClient := *iss
	loginClient.ClientID = "fairy-panel-login"

	for _, c := range []struct {
		name, token, reason string
	}{
		// shape
		{"empty", "", approval.ReasonFormat},
		{"two parts", parts[0] + "." + parts[1], approval.ReasonFormat},
		{"four parts", goodTok + ".AAAA", approval.ReasonFormat},
		{"empty signature", parts[0] + "." + parts[1] + ".", approval.ReasonFormat},
		{"padded part", parts[0] + "=." + parts[1] + "." + parts[2], approval.ReasonFormat},
		{"standard base64 alphabet", parts[0] + "." + parts[1] + "." + strings.Repeat("+", len(parts[2])), approval.ReasonFormat},
		{"space in a part", parts[0] + "." + parts[1] + " ." + parts[2], approval.ReasonFormat},
		{"newline at the end", goodTok + "\n", approval.ReasonFormat},
		{"newline inside the signature", parts[0] + "." + parts[1] + "." + parts[2][:100] + "\r\n" + parts[2][100:], approval.ReasonFormat},
		{"newline inside the payload", parts[0] + "." + parts[1][:10] + "\n" + parts[1][10:] + "." + parts[2], approval.ReasonFormat},
		{"too large", iss.Token(map[string]any{"x": strings.Repeat("a", api.MaxApprovalToken)}), approval.ReasonFormat},
		// header
		{"header not JSON", iss.Sign(`not json`, jsonOf(good())), approval.ReasonHeader},
		{"header a list", iss.Sign(`["RS256"]`, jsonOf(good())), approval.ReasonHeader},
		{"header with data after it", iss.Sign(iss.Header(nil)+`{}`, jsonOf(good())), approval.ReasonHeader},
		{"alg twice", iss.Sign(`{"alg":"none","alg":"RS256","kid":"`+iss.Kid+`"}`, jsonOf(good())), approval.ReasonHeader},
		{"alg twice, other case", iss.Sign(`{"ALG":"none","alg":"RS256","kid":"`+iss.Kid+`"}`, jsonOf(good())), approval.ReasonHeader},
		{"alg missing", hdr(map[string]any{"alg": nil}), approval.ReasonHeader},
		{"alg a number", hdr(map[string]any{"alg": 256}), approval.ReasonHeader},
		{"typ of an access token", hdr(map[string]any{"typ": "at+jwt"}), approval.ReasonHeader},
		{"crit", hdr(map[string]any{"crit": []string{"exp"}}), approval.ReasonHeader},
		{"empty crit", hdr(map[string]any{"crit": []string{}}), approval.ReasonHeader},
		{"embedded jwk", hdr(map[string]any{"jwk": approval.KeyFromRSA("x", &other.Key.PublicKey)}), approval.ReasonHeader},
		{"jku", hdr(map[string]any{"jku": "https://evil.test.invalid/jwks.json"}), approval.ReasonHeader},
		{"x5u", hdr(map[string]any{"x5u": "https://evil.test.invalid/cert.pem"}), approval.ReasonHeader},
		{"x5c", hdr(map[string]any{"x5c": []string{"AAAA"}}), approval.ReasonHeader},
		{"b64 false", hdr(map[string]any{"b64": false}), approval.ReasonHeader},
		// algorithm and key
		{"alg none", unsigned(`{"alg":"none","kid":"`+iss.Kid+`"}`) + ".AAAA", approval.ReasonAlg},
		{"alg None", unsigned(`{"alg":"None","kid":"`+iss.Kid+`"}`) + ".AAAA", approval.ReasonAlg},
		{"HS256 with the public key as the secret", hs + "." + approvaltest.B64(mac.Sum(nil)), approval.ReasonAlg},
		{"RS512, really signed", rs512 + "." + approvaltest.B64(sig512), approval.ReasonAlg},
		{"PS256, really signed", ps + "." + approvaltest.B64(sigPS), approval.ReasonAlg},
		{"ES256", unsigned(`{"alg":"ES256","kid":"`+iss.Kid+`"}`) + "." + strings.Repeat("A", 86), approval.ReasonAlg},
		{"EdDSA", unsigned(`{"alg":"EdDSA","kid":"`+iss.Kid+`"}`) + "." + strings.Repeat("A", 86), approval.ReasonAlg},
		{"no kid", hdr(map[string]any{"kid": nil}), approval.ReasonKey},
		{"kid not pinned", hdr(map[string]any{"kid": "another-key"}), approval.ReasonKey},
		{"kid a number", hdr(map[string]any{"kid": 1}), approval.ReasonKey},
		// signature
		{"signed with another key under the pinned kid", other.Token(good()), approval.ReasonSignature},
		{"payload changed after signing", parts[0] + "." + approvaltest.B64([]byte(strings.Replace(jsonOf(good()), approvaltest.User, "someone-else", 1))) + "." + parts[2], approval.ReasonSignature},
		{"header changed after signing", approvaltest.B64([]byte(iss.Header(map[string]any{"x": 1}))) + "." + parts[1] + "." + parts[2], approval.ReasonSignature},
		{"short signature", parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-2], approval.ReasonSignature},
		{"signature of zeros", parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2])-1) + "A", approval.ReasonSignature},
		// claims, all really signed by the pinned key
		{"payload not JSON", iss.Sign(iss.Header(nil), `hello`), approval.ReasonClaims},
		{"payload a list", iss.Sign(iss.Header(nil), `[1]`), approval.ReasonClaims},
		{"payload with data after it", iss.Sign(iss.Header(nil), jsonOf(good())+` {}`), approval.ReasonClaims},
		{"a claim twice", iss.Sign(iss.Header(nil), strings.Replace(jsonOf(good()), `{`, `{"sub":"x",`, 1)), approval.ReasonClaims},
		{"other issuer", with("iss", "https://other.test.invalid"), approval.ReasonIssuer},
		{"issuer with a slash more", with("iss", iss.URL+"/"), approval.ReasonIssuer},
		{"issuer missing", with("iss", nil), approval.ReasonIssuer},
		{"issuer a list", with("iss", []string{iss.URL}), approval.ReasonIssuer},
		{"the panel's login client", loginClient.Token(loginClient.Claims(nonce, now)), approval.ReasonAudience},
		{"audience missing", with("aud", nil), approval.ReasonAudience},
		{"two audiences", with("aud", []string{iss.ClientID, "fairy-panel-login"}), approval.ReasonAudience},
		{"empty audience list", with("aud", []string{}), approval.ReasonAudience},
		{"audience a prefix", with("aud", iss.ClientID+"x"), approval.ReasonAudience},
		{"azp of another client", with("azp", "fairy-panel-login"), approval.ReasonAudience},
		{"nonce of another list", with("nonce", strings.Repeat("A", 43)), approval.ReasonNonce},
		{"nonce missing", with("nonce", nil), approval.ReasonNonce},
		{"nonce a number", with("nonce", 1), approval.ReasonNonce},
		{"nonce longer", with("nonce", nonce+"A"), approval.ReasonNonce},
		{"user not allowed", with("sub", "99999999-0000-4000-8000-000000000000"), approval.ReasonUser},
		{"user a prefix of an allowed one", with("sub", approvaltest.User[:len(approvaltest.User)-1]), approval.ReasonUser},
		{"sub missing", with("sub", nil), approval.ReasonClaims},
		{"sub a number", with("sub", 7), approval.ReasonClaims},
		{"expired", with("exp", now.Add(-61*time.Second).Unix()), approval.ReasonTokenExp},
		{"exp missing", with("exp", nil), approval.ReasonClaims},
		{"exp a string", with("exp", "tomorrow"), approval.ReasonClaims},
		{"exp negative", with("exp", -1), approval.ReasonClaims},
		{"iat missing", with("iat", nil), approval.ReasonClaims},
		{"issued in the future", with("iat", now.Add(61*time.Second).Unix()), approval.ReasonClock},
		{"issued before the challenge", with("iat", now.Add(-61*time.Second).Unix()), approval.ReasonClock},
		{"not valid yet", with("nbf", now.Add(61*time.Second).Unix()), approval.ReasonClock},
		{"nbf a string", with("nbf", "x"), approval.ReasonClaims},
		{"no auth_time", with("auth_time", nil), approval.ReasonAuthTime},
		{"auth_time a string", with("auth_time", "now"), approval.ReasonClaims},
		{"authenticated before the challenge (no fresh passkey check)", with("auth_time", now.Add(-61*time.Second).Unix()), approval.ReasonAuthTime},
		{"authenticated an hour ago", with("auth_time", now.Add(-time.Hour).Unix()), approval.ReasonAuthTime},
		{"authenticated in the future", with("auth_time", now.Add(61*time.Second).Unix()), approval.ReasonClock},
		{"no amr", with("amr", nil), approval.ReasonAMR},
		{"password sign-in", with("amr", []string{"pwd"}), approval.ReasonAMR},
		{"amr a string", with("amr", "phr"), approval.ReasonAMR},
		{"amr empty", with("amr", []string{}), approval.ReasonAMR},
	} {
		ref := r.g.Check(req, &api.Approval{Token: c.token, Entries: entries})
		refused(t, c.name, ref, api.CodeApprovalRefused, c.reason)
	}
	// none of these used the challenge up, and tokens at the edge of each allowance are accepted
	claim := func(k string, v any) func(string) string {
		return func(n string) string {
			cl := iss.Claims(n, now)
			cl[k] = v
			return iss.Token(cl)
		}
	}
	for _, c := range []struct {
		name  string
		token func(nonce string) string
	}{
		{"audience as a list of one", claim("aud", []string{iss.ClientID})},
		{"azp of this client", claim("azp", iss.ClientID)},
		{"authenticated 60 s before the challenge by this clock", claim("auth_time", now.Add(-60*time.Second).Unix())},
		{"times 60 s ahead of this clock", func(n string) string { return iss.Token(iss.Claims(n, now.Add(60*time.Second))) }},
		{"expired 59 s ago by this clock", claim("exp", now.Add(-59*time.Second).Unix())},
		{"times with a fraction", claim("iat", float64(now.Unix())+0.5)},
		{"no typ, an unknown header member", func(n string) string {
			return iss.Sign(iss.Header(map[string]any{"typ": nil, "x-extra": true}), jsonOf(iss.Claims(n, now)))
		}},
		{"passkey among other methods", claim("amr", []string{"mfa", "phr"})},
	} {
		list := []api.MachineEntry{r.entry(req)}
		n, _ := api.ApprovalNonce(list)
		accepted(t, c.name, r.g.Check(req, &api.Approval{Token: c.token(n), Entries: list}))
	}
	accepted(t, "the good token, after all the bad ones", r.g.Check(req, &api.Approval{Token: goodTok, Entries: entries}))
}

// TestOldTokenForNewChallenge: a token from an earlier, real approval cannot be attached to a later challenge,
// and a user who was signed in before the challenge but did not confirm again is not enough.
func TestOldTokenForNewChallenge(t *testing.T) {
	r := newRig(t, true)
	req := power("shutdown", 60)
	old := r.approve(req)
	accepted(t, "first", r.g.Check(req, old))
	r.wait(10 * time.Minute)
	e := r.entry(req)
	refused(t, "old token, new challenge", r.g.Check(req, &api.Approval{Token: old.Token, Entries: []api.MachineEntry{e}}),
		api.CodeApprovalRefused, approval.ReasonNonce)
	// Pocket ID answering without a re-authentication: the right nonce, auth_time of the old sign-in
	n, _ := api.ApprovalNonce([]api.MachineEntry{e})
	cl := r.iss.Claims(n, r.Now())
	cl["auth_time"] = r.Now().Add(-10 * time.Minute).Unix()
	refused(t, "no fresh passkey check", r.g.Check(req, &api.Approval{Token: r.iss.Token(cl), Entries: []api.MachineEntry{e}}),
		api.CodeApprovalRefused, approval.ReasonAuthTime)
}

// TestRotatedKeys: two pinned keys (rotation overlap) both work; a key that is not pinned does not.
func TestRotatedKeys(t *testing.T) {
	r := newRig(t, false)
	next := *r.iss
	next.Kid, next.Key = "test-key-2", approvaltest.Key(1)
	in := r.iss.Init()
	in.Keys = append(in.Keys, approval.KeyFromRSA(next.Kid, &next.Key.PublicKey))
	if st, ref := r.firstSet(r.g, r.iss, in); ref != nil || len(st.Keys) != 2 || st.Keys[0].Thumbprint == st.Keys[1].Thumbprint {
		t.Fatalf("set with two keys: %+v, %v", st, ref)
	}
	req := fanMode("full")
	accepted(t, "old key", r.g.Check(req, r.iss.Approve(r.Now(), r.entry(req))))
	r.wait(time.Minute)
	accepted(t, "new key", r.g.Check(req, next.Approve(r.Now(), r.entry(req))))
	// the new key's signature under the old key's id
	mixed := next
	mixed.Kid = r.iss.Kid
	r.wait(time.Minute)
	refused(t, "new key, old kid", r.g.Check(req, mixed.Approve(r.Now(), r.entry(req))), api.CodeApprovalRefused, approval.ReasonSignature)
}

func TestThumbprint(t *testing.T) {
	k := approval.KeyFromRSA("k", &approvaltest.Key(0).PublicKey)
	// RFC 7638: the SHA-256 of the JSON object with exactly the members e, kty, n, in that order, no white space
	type rfc7638 struct {
		E   string `json:"e"`
		Kty string `json:"kty"`
		N   string `json:"n"`
	}
	sum := sha256.Sum256([]byte(jsonOf(rfc7638{k.E, k.Kty, k.N})))
	if got, want := approval.Thumbprint(k), approvaltest.B64(sum[:]); got != want || len(got) != 43 {
		t.Errorf("thumbprint %s, want %s", got, want)
	}
	if k.E != "AQAB" || k.Alg != "RS256" || k.Kty != "RSA" {
		t.Errorf("key %+v", k)
	}
}
