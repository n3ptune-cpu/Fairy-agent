package approval

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// Settings only an administrator on the machine changes.
const (
	DefaultFanWindowS = 30
	MaxFanWindowS     = 60
	MaxBootShutdownS  = 900
)

// Key sizes this version checks tokens with.
const (
	minRSABits = 2048
	maxRSABits = 8192
)

// TrustFileName is the trust file's name in the machine's admin-only folder (Windows: the helper's; elsewhere
// the agent's state folder).
const TrustFileName = "approval-trust.json"

// maxTrustFile bounds the trust file (4 keys of 8192 bits and 32 users are under 16 KiB).
const maxTrustFile = 64 << 10

// Trust is the trust file: whose tokens this machine accepts.
type Trust struct {
	Version  int            `json:"version"` // 1
	Issuer   string         `json:"issuer"`
	ClientID string         `json:"client_id"`
	Keys     []api.TrustKey `json:"keys"`
	Users    []string       `json:"users"`
	// FanWindowS: absent means DefaultFanWindowS.
	FanWindowS    *int `json:"fan_window_s,omitempty"`
	BootShutdownS int  `json:"boot_shutdown_s,omitempty"`
	// SetBy ("panel": the first-time set; "admin": helper-trust set) and SetAt are for people.
	SetBy string `json:"set_by,omitempty"`
	SetAt string `json:"set_at,omitempty"`

	pub map[string]*rsa.PublicKey // by kid, filled by validate
}

// ValueError is a refused trust value: Code is api.CodeTrustInvalid or api.CodeTrustUnsupportedKey.
type ValueError struct {
	Code string
	Msg  string
}

func (e *ValueError) Error() string { return e.Msg }

func invalid(f string, a ...any) *ValueError {
	return &ValueError{Code: api.CodeTrustInvalid, Msg: fmt.Sprintf(f, a...)}
}

func unsupported(f string, a ...any) *ValueError {
	return &ValueError{Code: api.CodeTrustUnsupportedKey, Msg: fmt.Sprintf(f, a...)}
}

var (
	clientIDRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)
	kidRe      = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{1,128}$`)
	subRe      = regexp.MustCompile(`^[\x21-\x7e]{1,255}$`)
	setByRe    = regexp.MustCompile(`^[a-z]{1,16}$`)
)

// FanWindow is the fan window in seconds.
func (t *Trust) FanWindow() int {
	if t.FanWindowS == nil {
		return DefaultFanWindowS
	}
	return *t.FanWindowS
}

// validate checks every value and builds the keys. It is the one set of rules for the first-time set from the
// panel, the administrator's command and the file read back from disk.
func (t *Trust) validate() error {
	if t.Version != 1 {
		return invalid("version must be 1")
	}
	if err := checkIssuer(t.Issuer); err != nil {
		return err
	}
	if !clientIDRe.MatchString(t.ClientID) {
		return invalid("client_id must be 1-128 characters of A-Z a-z 0-9 . _ ~ -")
	}
	if len(t.Keys) == 0 || len(t.Keys) > api.MaxTrustKeys {
		return invalid("keys must hold 1-%d keys", api.MaxTrustKeys)
	}
	t.pub = make(map[string]*rsa.PublicKey, len(t.Keys))
	for i, k := range t.Keys {
		pub, err := checkKey(k)
		if err != nil {
			err.Msg = fmt.Sprintf("keys[%d]: %s", i, err.Msg)
			return err
		}
		if t.pub[k.Kid] != nil {
			return invalid("keys[%d]: kid is used twice", i)
		}
		t.pub[k.Kid] = pub
	}
	if len(t.Users) == 0 || len(t.Users) > api.MaxTrustUsers {
		return invalid("users must hold 1-%d users (the sub of each person who may approve)", api.MaxTrustUsers)
	}
	for i, u := range t.Users {
		if !subRe.MatchString(u) {
			return invalid("users[%d] must be 1-255 printable ASCII characters without a space", i)
		}
		if slices.Index(t.Users, u) != i {
			return invalid("users[%d] is in the list twice", i)
		}
	}
	if w := t.FanWindow(); w < 0 || w > MaxFanWindowS {
		return invalid("fan_window_s must be 0-%d", MaxFanWindowS)
	}
	if t.BootShutdownS < 0 || t.BootShutdownS > MaxBootShutdownS {
		return invalid("boot_shutdown_s must be 0-%d", MaxBootShutdownS)
	}
	if t.SetBy != "" && !setByRe.MatchString(t.SetBy) {
		return invalid("set_by must be a short lower-case word")
	}
	if t.SetAt != "" {
		if _, err := time.Parse(time.RFC3339, t.SetAt); err != nil {
			return invalid("set_at must be an RFC 3339 time")
		}
	}
	return nil
}

// checkIssuer: an https URL with a host and nothing a token's "iss" would not have.
func checkIssuer(s string) *ValueError {
	if s == "" || len(s) > 255 {
		return invalid("issuer must be an https:// URL of at most 255 characters")
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] > 0x7e {
			return invalid("issuer must be printable ASCII without spaces")
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" {
		return invalid("issuer must be an https:// URL with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return invalid("issuer must not have user info, a query or a fragment")
	}
	return nil
}

// checkKey accepts one RSA key for RS256 and nothing else, and returns it.
func checkKey(k api.TrustKey) (*rsa.PublicKey, *ValueError) {
	if !kidRe.MatchString(k.Kid) {
		return nil, invalid("kid must be 1-128 characters of A-Z a-z 0-9 . _ ~ + / = -")
	}
	if k.Kty != "RSA" {
		return nil, unsupported("key type %q is not supported (only RSA keys for RS256)", clip(k.Kty))
	}
	if k.Alg != "RS256" {
		return nil, unsupported("alg %q is not supported (only RS256; alg must be given)", clip(k.Alg))
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, invalid("use must be sig or absent")
	}
	if k.E != "AQAB" {
		return nil, unsupported("only the public exponent 65537 (e = AQAB) is supported")
	}
	if len(k.N) > base64.RawURLEncoding.EncodedLen(maxRSABits/8) {
		return nil, unsupported("the modulus is larger than %d bits", maxRSABits)
	}
	nb, err := b64url(k.N)
	if err != nil {
		return nil, invalid("n must be base64url without padding")
	}
	if len(nb) == 0 || nb[0] == 0 {
		return nil, invalid("n must not be empty or start with a zero byte")
	}
	n := new(big.Int).SetBytes(nb)
	if bits := n.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, unsupported("an RSA key of %d bits is not supported (%d-%d)", bits, minRSABits, maxRSABits)
	}
	if n.Bit(0) == 0 {
		return nil, invalid("n is even: not an RSA modulus")
	}
	return &rsa.PublicKey{N: n, E: 65537}, nil
}

func clip(s string) string {
	if len(s) > 24 {
		s = s[:24]
	}
	return s
}

// Thumbprint is the key's JWK SHA-256 thumbprint (RFC 7638): the hash of {"e":..,"kty":"RSA","n":..}, base64url
// without padding.
func Thumbprint(k api.TrustKey) string {
	e, _ := json.Marshal(k.E)
	n, _ := json.Marshal(k.N)
	sum := sha256.Sum256([]byte(`{"e":` + string(e) + `,"kty":"RSA","n":` + string(n) + `}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ParseTrust reads a trust file's content: strict JSON, no unknown member, every value checked.
func ParseTrust(b []byte) (*Trust, error) {
	if len(b) > maxTrustFile {
		return nil, invalid("the trust file is larger than %d bytes", maxTrustFile)
	}
	var t Trust
	if err := decodeStrict(b, &t); err != nil {
		return nil, invalid("not a trust file: %s", err.Error())
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// NewTrust checks t and returns it ready to use and to write (the administrator's command).
func NewTrust(t Trust) (*Trust, error) {
	t.Version = 1
	if err := t.validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// FromInit is the trust a first-time set from the panel asks for: its four values, the default fan window, no
// shutdown-after-boot.
func FromInit(in api.TrustInit, now time.Time) (*Trust, error) {
	w := DefaultFanWindowS
	return NewTrust(Trust{Issuer: in.Issuer, ClientID: in.ClientID, Keys: in.Keys, Users: in.Users, FanWindowS: &w,
		SetBy: "panel", SetAt: now.UTC().Format(time.RFC3339)})
}

// Marshal is the file's content.
func (t *Trust) Marshal() []byte {
	b, _ := json.MarshalIndent(t, "", "  ")
	return append(b, '\n')
}

// Status is the trust as the "approval" block shows it (state required).
func (t *Trust) Status() api.ApprovalStatus {
	st := api.ApprovalStatus{State: api.ApprovalRequired, Proto: api.ApprovalProto, Issuer: t.Issuer, ClientID: t.ClientID,
		Users: len(t.Users), SetBy: t.SetBy, SetAt: t.SetAt,
		TrustHash: api.TrustHash(api.TrustInit{Issuer: t.Issuer, ClientID: t.ClientID, Keys: t.Keys, Users: t.Users})}
	for _, k := range t.Keys {
		st.Keys = append(st.Keys, api.ApprovalKey{Kid: k.Kid, Alg: k.Alg, Thumbprint: Thumbprint(k)})
	}
	w, b := t.FanWindow(), t.BootShutdownS
	st.FanWindowS, st.BootShutdownS = &w, &b
	return st
}

// KeyFromRSA is the pinned form of an RSA public key (the administrator's command, tests).
func KeyFromRSA(kid string, pub *rsa.PublicKey) api.TrustKey {
	return api.TrustKey{Kty: "RSA", Kid: kid, Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())}
}
