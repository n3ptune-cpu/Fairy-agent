// Package approvaltest is a made-up Pocket ID for tests: signing keys generated when the test runs and ID
// tokens put together from their parts. No token is written down anywhere; every one is made at run time.
package approvaltest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// Names of the made-up issuer.
const (
	IssuerURL = "https://id.test.invalid"
	ClientID  = "fairy-pc-actions-test"
	User      = "11111111-2222-4333-8444-555555555555" // a "sub" that may approve
	Kid       = "test-key-1"
)

var (
	keyOnce sync.Once
	keys    [2]*rsa.PrivateKey
)

// Key returns one of two RSA keys made once per test program (0: the issuer's, 1: somebody else's).
func Key(i int) *rsa.PrivateKey {
	keyOnce.Do(func() {
		for j := range keys {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			keys[j] = k
		}
	})
	return keys[i]
}

// Issuer signs ID tokens.
type Issuer struct {
	URL      string
	ClientID string
	Kid      string
	Key      *rsa.PrivateKey
	// Sub is the user its tokens are for ("": User).
	Sub string
}

// New is the made-up issuer with key 0.
func New() *Issuer { return &Issuer{URL: IssuerURL, ClientID: ClientID, Kid: Kid, Key: Key(0)} }

// Init is what the panel would send to set this issuer as a machine's trust, with users allowed to approve.
func (i *Issuer) Init(users ...string) api.TrustInit {
	if len(users) == 0 {
		users = []string{User}
	}
	return api.TrustInit{Issuer: i.URL, ClientID: i.ClientID, Users: users,
		Keys: []api.TrustKey{approval.KeyFromRSA(i.Kid, &i.Key.PublicKey)}}
}

// Claims are the claims of a good ID token for nonce, authenticated and issued at now.
func (i *Issuer) Claims(nonce string, now time.Time) map[string]any {
	sub := i.Sub
	if sub == "" {
		sub = User
	}
	return map[string]any{"iss": i.URL, "aud": i.ClientID, "sub": sub, "nonce": nonce, "amr": []string{"phr"},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Unix(), "preferred_username": "neptune"}
}

// B64 is base64url without padding.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Sign is the compact token of a header and a payload given as JSON text, signed RS256 with the issuer's key.
func (i *Issuer) Sign(headerJSON, payloadJSON string) string {
	in := B64([]byte(headerJSON)) + "." + B64([]byte(payloadJSON))
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.Key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return in + "." + B64(sig)
}

// Header is the usual header as JSON, with extra members added or replaced.
func (i *Issuer) Header(extra map[string]any) string {
	h := map[string]any{"alg": "RS256", "kid": i.Kid, "typ": "JWT"}
	maps.Copy(h, extra)
	for k, v := range h {
		if v == nil {
			delete(h, k)
		}
	}
	b, _ := json.Marshal(h)
	return string(b)
}

// Token is a signed ID token with these claims.
func (i *Issuer) Token(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return i.Sign(i.Header(nil), string(b))
}

// Approve is a complete approval of entries: a good token whose nonce is theirs, authenticated at now.
func (i *Issuer) Approve(now time.Time, entries ...api.ApprovalEntry) *api.Approval {
	nonce, err := api.ApprovalNonce(entries)
	if err != nil {
		panic(err)
	}
	return &api.Approval{Token: i.Token(i.Claims(nonce, now)), Entries: entries}
}

// Prove is in as the panel sends it for a first-time set: with this issuer's approval of entries, which must
// hold the machine's challenge for api.TrustSetRequest(in). Authenticated at now.
func (i *Issuer) Prove(now time.Time, in api.TrustInit, entries ...api.ApprovalEntry) api.TrustInit {
	in.Approval = i.Approve(now, entries...)
	return in
}
