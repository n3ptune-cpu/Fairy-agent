// Package enroll is "Add host": the one-time join code that adds a machine to the Fairy panel without copying
// tokens by hand.
//
//  1. The panel makes a random code (NewCode, 160 bits) and shows it inside one install command.
//  2. The installer on the machine stores only the code's verifier (Verifier(Proof(code))) in the agent's
//     pairing state, with an expiry and the panel's Tailscale address.
//  3. The panel keeps only Proof(code) in memory and asks the agent `POST /pair {"proof": ...}` until it answers.
//     The agent compares the proof's hash with the verifier in constant time, answers once with its tokens
//     (Response) and closes pairing for good.
//
// The agent never connects to the panel: the panel always asks, as for /metrics.
package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// CodeBytes is the randomness of a join code: 160 bits.
	CodeBytes = 20
	// TTL is how long a join code works: on the panel from when it is made, on the agent from when the
	// installer stored it.
	TTL = 15 * time.Minute
	// Path is the agent's pairing endpoint.
	Path = "/pair"
	// MaxFailures wrong proofs close pairing (a new code is needed).
	MaxFailures = 10
	// RatePerMin is how many /pair requests the agent answers per minute (all callers together).
	RatePerMin = 5
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewCode returns a new join code: 32 characters A-Z / 2-7, in groups of four ("ABCD-EFGH-...").
func NewCode() (string, error) {
	b := make([]byte, CodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return Group(b32.EncodeToString(b)), nil
}

// Group writes a normalised code in groups of four, joined by "-".
func Group(code string) string {
	var parts []string
	for i := 0; i < len(code); i += 4 {
		parts = append(parts, code[i:min(i+4, len(code))])
	}
	return strings.Join(parts, "-")
}

// Normalize removes dashes and spaces, upper-cases and checks a code.
func Normalize(code string) (string, error) {
	c := strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "").Replace(strings.TrimSpace(code)))
	b, err := b32.DecodeString(c)
	if err != nil || len(b) != CodeBytes {
		return "", errors.New("not a Fairy join code (32 letters A-Z and digits 2-7, in groups of four)")
	}
	return c, nil
}

// Proof is what the panel sends to the agent for a code: hex SHA-256 over a fixed label and the code. Neither
// side stores the code itself.
func Proof(code string) (string, error) {
	c, err := Normalize(code)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte("fairy-enroll-v1\x00" + c))
	return hex.EncodeToString(h[:]), nil
}

// Verifier is what the agent stores for a proof (hex SHA-256 of the proof).
func Verifier(proof string) string {
	h := sha256.Sum256([]byte(proof))
	return hex.EncodeToString(h[:])
}

// Check compares a presented proof with a stored verifier in constant time.
func Check(proof, verifier string) bool {
	want, err := hex.DecodeString(verifier)
	if err != nil || len(want) != sha256.Size || len(proof) > 256 {
		return false
	}
	got := sha256.Sum256([]byte(proof))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

// Request is the panel's POST /pair body.
type Request struct {
	Proof string `json:"proof"`
}

// Response is the agent's answer to a correct proof. It is sent once.
type Response struct {
	AgentVersion string          `json:"agent_version"`
	Hostname     string          `json:"hostname,omitempty"`
	Platform     string          `json:"platform"` // linux, windows
	Features     map[string]bool `json:"features"`
	Token        string          `json:"token"`
	ControlToken string          `json:"control_token,omitempty"` // only when a control feature is on
	// Proxmox is the read-only API token a Proxmox VE node made for the panel during `install.sh --proxmox`;
	// sent once, with the tokens, then gone from the machine's pairing state.
	Proxmox *ProxmoxGrant `json:"proxmox,omitempty"`
}

// ProxmoxGrant is what the panel needs to poll a standalone Proxmox VE node: a PVEAuditor API token and how to
// verify the node's certificate (its own CA, and the name the certificate is issued for).
type ProxmoxGrant struct {
	TokenID     string `json:"token_id"`     // fairy@pve!panel-<node>
	TokenSecret string `json:"token_secret"` // the token's UUID secret
	CAPEM       string `json:"ca_pem"`       // /etc/pve/pve-root-ca.pem ("" when the node uses a publicly trusted certificate)
	Node        string `json:"node"`         // the node's name (hostname)
	URL         string `json:"url"`          // https://<Tailscale name>:8006
	ServerName  string `json:"server_name"`  // the name to check the certificate against (in its SAN)
}

// State is the agent's pairing state file (written by `fairy-agent join`, closed by the agent).
type State struct {
	Version   int    `json:"version"`
	Verifier  string `json:"verifier,omitempty"` // removed once pairing is closed
	Panel     string `json:"panel,omitempty"`    // the panel's address: /pair answers only requests from it
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	Failures  int    `json:"failures,omitempty"`
	PairedAt  int64  `json:"paired_at,omitempty"`
	PairedBy  string `json:"paired_by,omitempty"`
	Closed    string `json:"closed,omitempty"` // why pairing is over: "paired", "too many wrong codes"
	// Proxmox: the node's API token for the panel (install.sh --proxmox), handed out once with the tokens and
	// removed from this file before it leaves.
	Proxmox *ProxmoxGrant `json:"proxmox,omitempty"`
}

// Active reports whether /pair may answer.
func (s State) Active(now time.Time) bool {
	return s.Closed == "" && s.Verifier != "" && now.Unix() < s.ExpiresAt
}

// Describe is one line for `fairy-agent pair-status` and the installer.
func (s State) Describe(now time.Time) string {
	switch {
	case s.Closed == "paired":
		return fmt.Sprintf("paired with the panel (%s) at %s", s.PairedBy, time.Unix(s.PairedAt, 0).Format(time.RFC3339))
	case s.Closed != "":
		return "closed: " + s.Closed + " (make a new code in the panel)"
	case s.Verifier == "":
		return "no join code"
	case !s.Active(now):
		return "the join code expired at " + time.Unix(s.ExpiresAt, 0).Format(time.RFC3339) + " (make a new code in the panel)"
	}
	return fmt.Sprintf("waiting for the panel (%s) until %s", s.Panel, time.Unix(s.ExpiresAt, 0).Format(time.RFC3339))
}

// ReadState reads a pairing state file. A missing file is os.ErrNotExist.
func ReadState(path string) (State, error) {
	var s State
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if len(b) > 64<<10 {
		return s, errors.New(path + ": too large")
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// WriteState replaces a pairing state file in one step (0600).
func WriteState(path string, s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pairing-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
