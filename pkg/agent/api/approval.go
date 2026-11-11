package api

// The passkey approval of control actions, as the panel sees it: the two routes, the "approval" field of the
// action routes, the "approval" block of GET /metrics, and the two things the panel has to compute exactly like
// the machine does: the canonical text of a request and the nonce of a list of entries. The checking itself is
// in pkg/approval; nothing here trusts its input.
//
// One approval is one ID token of the Pocket ID client "Fairy PC actions" whose nonce is ApprovalNonce of a list
// of entries, one entry per (machine challenge, exact request). Each machine checks the token offline against
// the key it has pinned and finds its own entry in the list.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// Approval routes (POST, control token, counted in the control rate limit like every control action).
const (
	// PathApprovalChallenge: body ApprovalRequest; 200 ChallengeResponse.
	PathApprovalChallenge = "/approval/challenge"
	// PathApprovalTrust: body TrustInit, with the approval that proves the proposed trust works; 200
	// ApprovalStatus. Only while the machine has no trust file.
	PathApprovalTrust = "/approval/trust"
)

// ApprovalProto is the version of the scheme below (canonical text, nonce, token checks). It is the "proto" of
// the "approval" block of GET /metrics; a panel that reads another number does not know this machine's rules.
const ApprovalProto = 1

// Limits. A machine refuses anything beyond them before it looks at the content.
const (
	MaxApprovalToken   = 8192 // bytes of the compact ID token
	MaxApprovalEntries = 64   // entries of one approval
	MaxApprovalRequest = 128  // bytes of one entry's canonical request
	ChallengeLen       = 43   // characters of a challenge: 32 bytes, base64url without padding
	MaxTrustKeys       = 4    // pinned keys
	MaxTrustUsers      = 32   // allowed users
)

// Error codes ("code" of a refused request).
const (
	CodeApprovalRequired    = "approval_required"    // 403: this request needs an approval and carried none
	CodeApprovalRefused     = "approval_refused"     // 403: the approval it carried was not accepted
	CodeApprovalUnavailable = "approval_unavailable" // 503: the trust file is there but cannot be used; nothing is approved until an administrator repairs it on the machine
	CodeApprovalDisabled    = "approval_disabled"    // 404: this agent has nothing that checks approvals (Windows without the helper)
	CodeTrustAlreadySet     = "already_set"          // 409: a trust file exists; only an administrator on the machine changes it
	CodeTrustInvalid        = "invalid"              // 400: the trust values were refused
	CodeTrustUnsupportedKey = "unsupported_key"      // 400: a key of a kind, algorithm or size this version does not check
	CodeTrustProofRequired  = "proof_required"       // 403: a first-time set of the trust without the approval that proves it; nothing was written
	CodeTrustProofRefused   = "proof_refused"        // 403: the approval sent with a first-time set does not verify against the proposed trust; nothing was written
	CodeHelperTooOld        = "helper_too_old"       // 409: the Windows helper is older than this protocol
)

// Approval states (ApprovalStatus.State).
const (
	ApprovalOff      = "off"      // no trust file: nothing is checked, and the panel may set the trust once
	ApprovalRequired = "required" // trust is set: the requests listed in NeedsApproval need an approval
	ApprovalBroken   = "broken"   // a trust file exists but cannot be used: those requests are refused
	ApprovalUnknown  = "unknown"  // Windows: the helper, which does the checking, is not answering
)

// Who checks (ApprovalStatus.EnforcedBy).
const (
	EnforcedByHelper = "helper" // Windows: the LocalSystem helper; the agent only passes things on
	EnforcedByAgent  = "agent"  // everywhere else: the agent itself
)

// Verbs of an ApprovalRequest: the four requests that need an approval when trust is set, and the one request
// that needs one while there is none: the first-time set of the trust itself.
const (
	ApproveFanSet      = "fan_set"      // POST /fan/duty
	ApproveFanMode     = "fan_mode"     // POST /fan/mode
	ApprovePower       = "power"        // POST /power, every action but cancel
	ApproveApplyUpdate = "apply_update" // POST /update
	ApproveTrustSet    = "trust_set"    // POST /approval/trust (only while the machine has no trust file)
)

var (
	approveFanModes     = []string{"standard", "full", "optimal", "heavyio"}
	approvePowerActions = []string{"shutdown", "reboot", "sleep"}
)

// ApprovalRequest is one exact request: the body of POST /approval/challenge, and what a challenge is bound to.
type ApprovalRequest struct {
	Verb    string  `json:"verb"`
	Zone    *int    `json:"zone,omitempty"`    // fan_set
	Percent *int    `json:"percent,omitempty"` // fan_set
	Mode    *string `json:"mode,omitempty"`    // fan_mode
	Action  *string `json:"action,omitempty"`  // power: shutdown | reboot | sleep
	DelayS  *int    `json:"delay_s,omitempty"` // power
	// TrustHash (trust_set): TrustHash of the trust the panel is about to propose, 43 characters.
	TrustHash *string `json:"trust_hash,omitempty"`
}

// Canonical is the one text form of the request, the "request" of an entry:
//
//	fan_set zone=<0|1> percent=<0-100>
//	fan_mode mode=<standard|full|optimal|heavyio>
//	power action=<shutdown|reboot|sleep> delay_s=<0-86400>
//	apply_update
//	trust_set hash=<43 characters: TrustHash of the proposed trust>
//
// ASCII, single spaces, numbers in decimal without sign or leading zeros, the fields in exactly this order.
// Every value is a small number, one word of a fixed list or 43 characters of the base64url alphabet, so no
// value can contain a space or "=".
// A request with a missing or an extra field, or a value outside these lists, has no canonical form.
func (r ApprovalRequest) Canonical() (string, error) {
	set := map[string]bool{"zone": r.Zone != nil, "percent": r.Percent != nil, "mode": r.Mode != nil,
		"action": r.Action != nil, "delay_s": r.DelayS != nil, "trust_hash": r.TrustHash != nil}
	only := func(fields ...string) error {
		for f, present := range set {
			if want := slices.Contains(fields, f); present != want {
				if want {
					return fmt.Errorf("%s needs %s", r.Verb, f)
				}
				return fmt.Errorf("%s does not take %s", r.Verb, f)
			}
		}
		return nil
	}
	switch r.Verb {
	case ApproveFanSet:
		if err := only("zone", "percent"); err != nil {
			return "", err
		}
		if *r.Zone != 0 && *r.Zone != 1 {
			return "", errors.New("zone must be 0 or 1")
		}
		if *r.Percent < 0 || *r.Percent > 100 {
			return "", errors.New("percent must be 0-100")
		}
		return "fan_set zone=" + strconv.Itoa(*r.Zone) + " percent=" + strconv.Itoa(*r.Percent), nil
	case ApproveFanMode:
		if err := only("mode"); err != nil {
			return "", err
		}
		if !slices.Contains(approveFanModes, *r.Mode) {
			return "", errors.New("mode must be standard, full, optimal or heavyio")
		}
		return "fan_mode mode=" + *r.Mode, nil
	case ApprovePower:
		if err := only("action", "delay_s"); err != nil {
			return "", err
		}
		if !slices.Contains(approvePowerActions, *r.Action) {
			return "", errors.New("action must be shutdown, reboot or sleep (cancel needs no approval)")
		}
		if *r.DelayS < 0 || *r.DelayS > 86400 {
			return "", errors.New("delay_s must be 0-86400")
		}
		return "power action=" + *r.Action + " delay_s=" + strconv.Itoa(*r.DelayS), nil
	case ApproveApplyUpdate:
		if err := only(); err != nil {
			return "", err
		}
		return "apply_update", nil
	case ApproveTrustSet:
		if err := only("trust_hash"); err != nil {
			return "", err
		}
		if _, err := decode32(*r.TrustHash); err != nil {
			return "", errors.New("trust_hash must be 43 characters of base64url (32 bytes, no padding)")
		}
		return "trust_set hash=" + *r.TrustHash, nil
	}
	return "", errors.New("verb must be fan_set, fan_mode, power, apply_update or trust_set")
}

// ApprovalEntry is one (challenge, request) pair of an approval.
type ApprovalEntry struct {
	Challenge string `json:"challenge"` // as the machine gave it: 43 characters
	Request   string `json:"request"`   // ApprovalRequest.Canonical
}

// Approval is the "approval" field of POST /fan/mode, /fan/duty, /power and /update: the ID token and the whole
// list its nonce was made from, in the same order.
type Approval struct {
	Token   string          `json:"token"`
	Entries []ApprovalEntry `json:"entries"`
}

// nonceDomain starts every nonce input: nothing else Fairy hashes begins with it.
const nonceDomain = "fairy-approval-v1"

// DecodeChallenge returns the 32 bytes of a challenge. Exactly 43 characters of the URL-safe alphabet, no
// padding, no stray bits.
func DecodeChallenge(s string) ([]byte, error) {
	b, err := decode32(s)
	if err != nil {
		return nil, errors.New("a challenge is " + err.Error())
	}
	return b, nil
}

// decode32 returns the 32 bytes of s: exactly 43 characters of the URL-safe alphabet, no padding, no stray
// bits. The error says what s must be.
func decode32(s string) ([]byte, error) {
	if len(s) != ChallengeLen {
		return nil, errors.New("43 characters")
	}
	for i := 0; i < len(s); i++ { // encoding/base64 skips line breaks even in strict mode
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, errors.New("base64url")
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("32 bytes in base64url without padding")
	}
	return b, nil
}

// ApprovalNonce is the nonce of the one Pocket ID request that approves entries:
//
//	base64url_nopad( SHA-256( "fairy-approval-v1" || 0x00 || be32(len(entries)) ||
//	                          for each entry, in order: challenge (its 32 bytes) || be32(len(request)) || request ) )
//
// be32 is a 4-byte big-endian number; request is the canonical text as bytes. Every part has a fixed length or
// its length in front, so two different lists never give the same input. It refuses a list that is empty or
// longer than MaxApprovalEntries, a malformed challenge, a challenge that is in the list twice, and a request
// that is empty, longer than MaxApprovalRequest or not printable ASCII.
func ApprovalNonce(entries []ApprovalEntry) (string, error) {
	if len(entries) == 0 || len(entries) > MaxApprovalEntries {
		return "", fmt.Errorf("an approval has 1-%d entries", MaxApprovalEntries)
	}
	h := sha256.New()
	h.Write([]byte(nonceDomain))
	h.Write([]byte{0})
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(entries)))
	h.Write(n[:])
	seen := make(map[[32]byte]bool, len(entries))
	for _, e := range entries {
		c, err := DecodeChallenge(e.Challenge)
		if err != nil {
			return "", err
		}
		if seen[[32]byte(c)] {
			return "", errors.New("a challenge is in the list twice")
		}
		seen[[32]byte(c)] = true
		if len(e.Request) == 0 || len(e.Request) > MaxApprovalRequest {
			return "", fmt.Errorf("a request is 1-%d bytes", MaxApprovalRequest)
		}
		for i := 0; i < len(e.Request); i++ {
			if e.Request[i] < 0x20 || e.Request[i] > 0x7e {
				return "", errors.New("a request is printable ASCII")
			}
		}
		h.Write(c)
		binary.BigEndian.PutUint32(n[:], uint32(len(e.Request)))
		h.Write(n[:])
		h.Write([]byte(e.Request))
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// ChallengeResponse is the 200 answer of POST /approval/challenge.
type ChallengeResponse struct {
	// Needed: the request needs an approval now. false: send it without one (Reason says why). For trust_set it
	// is always true (or the request is refused: already_set).
	Needed bool `json:"needed"`
	// Reason when not needed: "off" (no trust set), "fan_window" (a fan change was approved a moment ago) or
	// "boot_shutdown" (the machine's own setting allows one shutdown shortly after it started).
	Reason string `json:"reason,omitempty"`
	// Request is the canonical text the machine bound the challenge to. The panel compares it with its own.
	Request string `json:"request"`
	// Challenge: 43 characters, single use (needed only).
	Challenge string `json:"challenge,omitempty"`
	// ExpiresInS: seconds until the challenge is dropped (needed only).
	ExpiresInS int `json:"expires_in_s,omitempty"`
	// Issuer and ClientID the machine will accept the token from (needed only; absent for trust_set, where the
	// machine has none yet and the token is checked against the proposed ones).
	Issuer   string `json:"issuer,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// TrustKey is one pinned signing key: an RSA public key as a JWK (RFC 7517) with exactly these members.
type TrustKey struct {
	Kty string `json:"kty"`           // "RSA"
	Kid string `json:"kid"`           // the key id the token header names
	Alg string `json:"alg"`           // "RS256"
	Use string `json:"use,omitempty"` // absent or "sig"
	N   string `json:"n"`             // modulus, base64url without padding, 2048-8192 bits
	E   string `json:"e"`             // "AQAB"
}

// TrustInit is the body of POST /approval/trust: what a machine without a trust file is told to trust. The fan
// window and the shutdown-after-boot setting are not in it: they start at their defaults (30 s, off) and only
// an administrator on the machine changes them.
//
// A first-time set must prove that it works: Approval is an approval of the request "trust_set hash=<TrustHash
// of these four values>" (a challenge of this machine for exactly that request, POST /approval/challenge with
// the verb trust_set), and its token is checked like every approval, against the PROPOSED values: signed by a
// proposed key, "iss" the proposed issuer, "aud" the proposed client, "sub" one of the proposed users. Only
// then is the trust written. So a wrong issuer spelling, client id, user id or key, or a machine whose clock
// is off, is found out before the machine locks, not after.
type TrustInit struct {
	Issuer   string     `json:"issuer"`    // https://..., exactly the "iss" of the tokens
	ClientID string     `json:"client_id"` // the Pocket ID client "Fairy PC actions"
	Keys     []TrustKey `json:"keys"`      // 1-MaxTrustKeys
	Users    []string   `json:"users"`     // 1-MaxTrustUsers "sub" values that may approve
	// Approval is the proof (see above). Without it the set is refused with proof_required.
	Approval *Approval `json:"approval,omitempty"`
}

// trustDomain starts every trust hash input: nothing else Fairy hashes begins with it.
const trustDomain = "fairy-trust-v1"

// TrustHash is the hash of the four values of a proposed trust, the "hash" of the request "trust_set
// hash=...":
//
//	base64url_nopad( SHA-256( "fairy-trust-v1" || 0x00 ||
//	    str(issuer) || str(client_id) ||
//	    be32(number of keys)  || for each key, in the order of "keys":   str(kty) || str(kid) || str(alg) || str(n) || str(e) ||
//	    be32(number of users) || for each user, in the order of "users": str(user) ) )
//
// str(x) is be32(len(x)) || x, the bytes of the string as it is in the JSON body (n and e stay base64url text);
// be32 is a 4-byte big-endian number. A key's "use" is not part of it. The order of keys and users counts: the
// body that is sent must list them in the order that was hashed. Every part has its length in front, so two
// different proposals never give the same input. The values are not checked here.
func TrustHash(in TrustInit) string {
	h := sha256.New()
	h.Write([]byte(trustDomain))
	h.Write([]byte{0})
	var n [4]byte
	num := func(v int) {
		binary.BigEndian.PutUint32(n[:], uint32(v))
		h.Write(n[:])
	}
	str := func(s string) {
		num(len(s))
		h.Write([]byte(s))
	}
	str(in.Issuer)
	str(in.ClientID)
	num(len(in.Keys))
	for _, k := range in.Keys {
		str(k.Kty)
		str(k.Kid)
		str(k.Alg)
		str(k.N)
		str(k.E)
	}
	num(len(in.Users))
	for _, u := range in.Users {
		str(u)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// TrustSetRequest is the request a first-time set of in must be approved as: the body of the POST
// /approval/challenge that comes before it.
func TrustSetRequest(in TrustInit) ApprovalRequest {
	hash := TrustHash(in)
	return ApprovalRequest{Verb: ApproveTrustSet, TrustHash: &hash}
}

// ApprovalKey is one pinned key in ApprovalStatus.
type ApprovalKey struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	// Thumbprint: the JWK SHA-256 thumbprint (RFC 7638), base64url without padding, 43 characters.
	Thumbprint string `json:"thumbprint"`
}

// ApprovalStatus is the "approval" block of GET /metrics (absent: an agent from before approvals), the answer
// of POST /approval/trust and what `fairy-agent helper-status` and `helper-trust show` print. No secrets.
type ApprovalStatus struct {
	State      string `json:"state"`
	EnforcedBy string `json:"enforced_by"`
	Proto      int    `json:"proto"`
	// The rest is set while State is required.
	Issuer   string        `json:"issuer,omitempty"`
	ClientID string        `json:"client_id,omitempty"`
	Keys     []ApprovalKey `json:"keys,omitempty"`
	Users    int           `json:"users,omitempty"` // how many users may approve
	// FanWindowS: after an accepted approval of a fan change, further fan changes need none for this long (0: off).
	FanWindowS *int `json:"fan_window_s,omitempty"`
	// BootShutdownS: one shutdown without approval is accepted while the machine has been up for less than this
	// (0: off, the default).
	BootShutdownS *int `json:"boot_shutdown_s,omitempty"`
	// Error: why the trust file cannot be used (broken), or why the state is unknown.
	Error string `json:"error,omitempty"`
	// AgentChecks: on a machine where EnforcedBy is the helper, the requests (verbs) this agent process
	// carries out itself, without the helper, and therefore checks itself with the same trust file and the
	// same rules: a Windows agent that drives the fans over the network (ipmi.transport: ipmitool), or one
	// started before the helper was installed. Absent: none, the helper checks everything.
	AgentChecks []string `json:"agent_checks,omitempty"`
	// AgentError: why the agent's own check of AgentChecks cannot be used; those requests are refused.
	AgentError string `json:"agent_error,omitempty"`
}
