package agent

// The BMC power-on relay: an always-on agent cabled to (or on the LAN of) a machine whose BMC it can reach powers
// that machine on through the BMC, for machines where Wake-on-LAN does not work (e.g. a BMC sharing the LAN port).
// POST /bmc/power {"target": "<id>", "action": "on" | "status"} with the control token. Two backends per target:
//
//	ipmitool: `ipmitool -I lanplus -H <host> -U <user> -E [-C <cipher suite>] chassis power on|status`, the
//	          password only in the child's IPMI_PASSWORD (never on the command line), minimal environment, 15 s
//	redfish:  GET /redfish/v1/Systems -> first member; POST <member>/Actions/ComputerSystem.Reset {"ResetType":"On"};
//	          basic auth, 10 s, the BMC's certificate pinned by SHA-256 (configured, or learned on first use)
//
// Only BMC addresses in private ranges are accepted (like Wake-on-LAN). Passwords come from the environment
// (env_file); neither they nor the BMC's answers with them are logged.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// BMCRelayConfig is the `bmc_relay:` block.
type BMCRelayConfig struct {
	Enabled bool        `yaml:"enabled"`
	Targets []BMCTarget `yaml:"targets"`
}

// BMCTarget is one BMC the relay may power on.
type BMCTarget struct {
	ID             string `yaml:"id"`
	Backend        string `yaml:"backend"`  // ipmitool | redfish (default: ipmitool with host:, redfish with url:)
	Host           string `yaml:"host"`     // ipmitool: the BMC's IP address
	URL            string `yaml:"url"`      // redfish: https://<BMC IP>[:port]
	Username       string `yaml:"username"` // the BMC account (a dedicated one)
	PasswordEnv    string `yaml:"password_env"`
	CipherSuite    *int   `yaml:"cipher_suite"`    // ipmitool -C (0-17); unset: ipmitool's default
	IpmitoolPath   string `yaml:"ipmitool_path"`   // default: C:\Program Files\ipmitool\ (Windows), /usr/bin etc. and PATH (Linux)
	TLSFingerprint string `yaml:"tls_fingerprint"` // redfish: SHA-256 of the BMC's certificate; empty: learned on first use
}

var (
	bmcIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	hexFPRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// EffectiveBackend is the backend used for t.
func (t BMCTarget) EffectiveBackend() string {
	if t.Backend != "" {
		return t.Backend
	}
	if t.Host != "" && t.URL == "" {
		return "ipmitool"
	}
	return "redfish"
}

// privateIP accepts private (RFC 1918 / ULA) and link-local addresses only, so the relay cannot reach the
// internet.
func privateIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

// normFingerprint lower-cases a SHA-256 fingerprint and drops ":" separators.
func normFingerprint(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
}

func (c BMCRelayConfig) validate(add func(string)) {
	seen := map[string]bool{}
	for i, t := range c.Targets {
		where := fmt.Sprintf("bmc_relay.targets[%d]", i)
		if !bmcIDRe.MatchString(t.ID) {
			add(where + ".id must be 1-40 characters a-z, 0-9 and -")
		} else if seen[t.ID] {
			add(where + ".id " + t.ID + " is used twice")
		}
		seen[t.ID] = true
		if t.Username == "" {
			add(where + ".username is required (a BMC account)")
		}
		if !envNameRe.MatchString(t.PasswordEnv) {
			add(where + ".password_env must name an environment variable (set in env_file, e.g. with `fairy-agent secret set`)")
		}
		switch t.EffectiveBackend() {
		case "ipmitool":
			if !privateIP(t.Host) {
				add(where + ".host must be the BMC's private IP address (e.g. 192.168.1.5)")
			}
			if t.CipherSuite != nil && (*t.CipherSuite < 0 || *t.CipherSuite > 17) {
				add(where + ".cipher_suite must be 0-17")
			}
			if t.IpmitoolPath != "" && collect.ExecPathProblem(t.IpmitoolPath, runtime.GOOS == "windows") != "" {
				add(where + ".ipmitool_path must be an absolute local path (e.g. C:\\Program Files\\ipmitool\\ipmitool.exe)")
			}
		case "redfish":
			u, err := url.Parse(t.URL)
			if err != nil || u.Scheme != "https" || !privateIP(u.Hostname()) || (u.Path != "" && u.Path != "/") {
				add(where + ".url must be https://<the BMC's private IP address>")
			}
			if t.TLSFingerprint != "" && !hexFPRe.MatchString(normFingerprint(t.TLSFingerprint)) {
				add(where + ".tls_fingerprint must be the certificate's SHA-256 (64 hex digits)")
			}
			if t.CipherSuite != nil {
				add(where + ".cipher_suite is for ipmitool only")
			}
		default:
			add(where + ".backend must be ipmitool or redfish")
		}
	}
	if c.Enabled && len(c.Targets) == 0 {
		add("bmc_relay.enabled needs at least one entry in bmc_relay.targets")
	}
}

// BMCRequest is the POST /bmc/power body.
type BMCRequest struct {
	Target      string `json:"target"`
	Action      string `json:"action"` // on | status
	RequestedBy any    `json:"requested_by"`
}

// BMCRelay powers machines on through their BMC.
type BMCRelay struct {
	targets map[string]BMCTarget
	order   []string
	pins    *pinStore
	// Run executes ipmitool (replaceable for tests): path, args, extra environment; returns combined output.
	Run func(ctx context.Context, path string, args, env []string) ([]byte, error)
	// FindIpmitool locates ipmitool when ipmitool_path is not set.
	FindIpmitool func() (string, error)
	// CheckExe refuses a configured ipmitool_path that anyone but administrators / root could replace.
	CheckExe func(path string) error
	mu       sync.Mutex
}

// NewBMCRelay builds the relay; pinFile keeps learned Redfish certificate fingerprints ("" = memory only).
func NewBMCRelay(c BMCRelayConfig, pinFile string) *BMCRelay {
	b := &BMCRelay{targets: map[string]BMCTarget{}, pins: &pinStore{path: pinFile}, Run: runIpmitool,
		FindIpmitool: collect.FindIpmitool, CheckExe: collect.TrustedExecutable}
	for _, t := range c.Targets {
		b.targets[t.ID] = t
		b.order = append(b.order, t.ID)
	}
	return b
}

// Targets lists the target ids (for /metrics: ids and backends only, never addresses or users).
func (b *BMCRelay) Targets() []map[string]string {
	out := []map[string]string{}
	for _, id := range b.order {
		out = append(out, map[string]string{"id": id, "backend": b.targets[id].EffectiveBackend()})
	}
	return out
}

type bmcError struct {
	status int
	code   string
	msg    string
}

func (e *bmcError) Error() string { return e.msg }

func bmcErr(status int, code, format string, a ...any) error {
	return &bmcError{status, code, fmt.Sprintf(format, a...)}
}

// Handle carries out one request and returns the HTTP status and body.
func (b *BMCRelay) Handle(ctx context.Context, req BMCRequest) (int, map[string]any) {
	t, ok := b.targets[req.Target]
	if !ok {
		return 404, map[string]any{"error": "no bmc_relay target " + strconv.Quote(req.Target) + " on this agent", "code": "unknown_target"}
	}
	if req.Action != "on" && req.Action != "status" {
		return 400, map[string]any{"error": "action must be on or status"}
	}
	who := cleanWho(req.RequestedBy)
	b.mu.Lock() // one BMC conversation at a time
	defer b.mu.Unlock()
	var power string
	var err error
	if t.EffectiveBackend() == "ipmitool" {
		power, err = b.ipmitool(ctx, t, req.Action)
	} else {
		power, err = b.redfish(ctx, t, req.Action)
	}
	if err != nil {
		var be *bmcError
		if !errors.As(err, &be) {
			be = &bmcError{502, "bmc_error", err.Error()}
		}
		slog.Warn("bmc relay: failed", "target", t.ID, "action", req.Action, "code", be.code, "error", be.msg, "requested_by", who)
		return be.status, map[string]any{"error": be.msg, "code": be.code, "target": t.ID}
	}
	if req.Action == "on" {
		slog.Warn("bmc relay: power on sent", "target", t.ID, "backend", t.EffectiveBackend(), "requested_by", who)
	}
	return 200, map[string]any{"target": t.ID, "action": req.Action, "power": power, "backend": t.EffectiveBackend()}
}

func (b *BMCRelay) password(t BMCTarget) (string, error) {
	pw := os.Getenv(t.PasswordEnv)
	if pw == "" {
		return "", bmcErr(409, "bmc_password_missing", "%s is not set (fairy-agent secret set %s, then restart the agent)", t.PasswordEnv, t.PasswordEnv)
	}
	return pw, nil
}

// ---- ipmitool

func runIpmitool(ctx context.Context, path string, args, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(collect.MinimalEnv(), env...)
	return cmd.CombinedOutput()
}

// IpmitoolArgs is the command line for a target (no password: it travels in IPMI_PASSWORD with -E).
func IpmitoolArgs(t BMCTarget, action string) []string {
	args := []string{"-I", "lanplus", "-H", t.Host, "-U", t.Username, "-E"}
	if t.CipherSuite != nil {
		args = append(args, "-C", strconv.Itoa(*t.CipherSuite))
	}
	if action == "on" {
		return append(args, "chassis", "power", "on")
	}
	return append(args, "chassis", "power", "status")
}

var (
	ipmiPowerIs = regexp.MustCompile(`(?i)chassis power is (on|off)`)
	ipmiCtlUp   = regexp.MustCompile(`(?i)chassis power control:\s*(up/on|on)`)
)

func (b *BMCRelay) ipmitool(ctx context.Context, t BMCTarget, action string) (string, error) {
	path := t.IpmitoolPath
	if path == "" {
		p, err := b.FindIpmitool()
		if err != nil {
			return "", bmcErr(409, "ipmitool_missing", "%s (or set ipmitool_path)", err.Error())
		}
		path = p
	} else if err := b.CheckExe(path); err != nil {
		return "", bmcErr(409, "ipmitool_untrusted", "ipmitool_path not used: %s", err.Error())
	}
	pw, err := b.password(t)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := b.Run(ctx, path, IpmitoolArgs(t, action), []string{"IPMI_PASSWORD=" + pw})
	text := cleanIpmitoolOutput(string(out), pw)
	switch {
	case ctx.Err() != nil:
		return "", bmcErr(504, "bmc_unreachable", "the BMC at %s did not answer within 15 s (is the relay cabled to it?)", t.Host)
	case action == "on" && ipmiCtlUp.MatchString(text):
		return "on", nil
	case action == "status" && ipmiPowerIs.MatchString(text):
		return strings.ToLower(ipmiPowerIs.FindStringSubmatch(text)[1]), nil
	case err == nil:
		return "", bmcErr(502, "bmc_error", "unexpected answer from ipmitool: %s", text)
	}
	return "", classifyIpmitool(t, text)
}

// ianaPENRe matches ipmitool's warning that it cannot read the IANA enterprise numbers file (newer ipmitool on
// systems without /usr/share/misc/enterprise-numbers, and every Windows build). It says nothing about the BMC.
var ianaPENRe = regexp.MustCompile(`(?i)\biana\b.*\b(pen|enterprise)\b|enterprise-numbers`)

// cleanIpmitoolOutput drops the IANA PEN warning lines and empty lines, hides the password, and keeps at most
// 300 characters.
func cleanIpmitoolOutput(out, pw string) string {
	if pw != "" {
		out = strings.ReplaceAll(out, pw, "***")
	}
	var keep []string
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || ianaPENRe.MatchString(l) {
			continue
		}
		keep = append(keep, l)
	}
	text := strings.Join(keep, "; ")
	if len(text) > 300 {
		text = text[:300]
	}
	return text
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// classifyIpmitool turns a failed ipmitool run into an error the panel can show. "Unable to establish IPMI v2 /
// RMCP+ session" is ipmitool's last line for almost every failure, so the specific line before it decides:
// a refused role / privilege, a cipher suite the BMC does not offer, a wrong user or password, a BMC out of
// sessions. Only when nothing more specific is there (or ipmitool says so) is the BMC called unreachable.
func classifyIpmitool(t BMCTarget, text string) error {
	l := strings.ToLower(text)
	suite := "ipmitool's default"
	if t.CipherSuite != nil {
		suite = strconv.Itoa(*t.CipherSuite)
	}
	switch {
	case containsAny(l, "invalid role", "unauthorized role", "privilege level", "insufficient privilege"):
		return bmcErr(502, "bmc_privilege",
			"the BMC at %s accepted the login but refused the privilege level: ipmitool asks for ADMINISTRATOR; give the BMC user %q the Administrator role (or an Operator user allowed chassis power control). ipmitool said: %s",
			t.Host, t.Username, text)
	case containsAny(l, "cipher suite", "no matching", "invalid authentication algorithm", "invalid integrity algorithm",
		"invalid confidentiality algorithm", "unsupported cipher"):
		return bmcErr(502, "bmc_cipher",
			"the BMC at %s does not accept cipher suite %s: set cipher_suite to one it offers (Supermicro: 3 or 17). ipmitool said: %s",
			t.Host, suite, text)
	case containsAny(l, "unauthorized name", "invalid name length", "invalid user", "hmac is invalid",
		"password", "unauthorized", "authentication", "invalid integrity check value", "unknown user"):
		return bmcErr(502, "bmc_refused",
			"the BMC at %s refused the login: check the user name %q and the password in %s. ipmitool said: %s",
			t.Host, t.Username, t.PasswordEnv, text)
	case containsAny(l, "insufficient resources", "no session slot", "session limit"):
		return bmcErr(502, "bmc_busy",
			"the BMC at %s has no free session (too many open logins): try again in a minute. ipmitool said: %s", t.Host, text)
	case containsAny(l, "invalid session", "inactive session", "session id", "session challenge", "activate session"):
		return bmcErr(502, "bmc_session",
			"the BMC at %s dropped the IPMI session (it answered, so it is reachable): try again; if it repeats, reset the BMC or try another cipher_suite. ipmitool said: %s",
			t.Host, text)
	case containsAny(l, "no route", "unreachable", "timeout", "timed out", "no response", "connection refused",
		"address lookup", "unknown host", "get auth capabilities"):
		return bmcErr(502, "bmc_unreachable", "the BMC at %s is not reachable (is the relay cabled to it?): %s", t.Host, text)
	case strings.Contains(l, "unable to establish"):
		return bmcErr(502, "bmc_unreachable",
			"no IPMI session with the BMC at %s: either it does not answer (is the relay cabled to it?) or it silently refused the login (user, password, cipher_suite). ipmitool said: %s",
			t.Host, text)
	}
	return bmcErr(502, "bmc_error", "ipmitool failed: %s", text)
}

// ---- Redfish

type pinStore struct {
	path string
	mu   sync.Mutex
	mem  map[string]string
}

func (p *pinStore) load() map[string]string {
	if p.mem != nil {
		return p.mem
	}
	p.mem = map[string]string{}
	if p.path != "" {
		if b, err := os.ReadFile(p.path); err == nil {
			_ = json.Unmarshal(b, &p.mem)
		}
	}
	return p.mem
}

func (p *pinStore) get(id string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.load()[id]
}

func (p *pinStore) set(id, fp string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.load()
	m[id] = fp
	if p.path == "" {
		return
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(p.path, b, 0o600); err != nil {
		slog.Warn("bmc relay: the learned certificate fingerprint is kept in memory only", "error", err.Error())
	}
}

// client returns an HTTP client that accepts only the pinned certificate (configured, learned, or - the first
// time - any, then learned).
func (b *BMCRelay) client(t BMCTarget) (*http.Client, *string) {
	want := normFingerprint(t.TLSFingerprint)
	if want == "" {
		want = b.pins.get(t.ID)
	}
	seen := new(string)
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // replaced by the fingerprint check below (BMCs have self-signed certificates)
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			sum := sha256.Sum256(raw[0])
			*seen = hex.EncodeToString(sum[:])
			if want != "" && *seen != want {
				return fmt.Errorf("certificate fingerprint %s is not the pinned %s", *seen, want)
			}
			return nil
		}},
		Proxy: nil, DisableKeepAlives: true}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, seen
}

func (b *BMCRelay) redfish(ctx context.Context, t BMCTarget, action string) (string, error) {
	pw, err := b.password(t)
	if err != nil {
		return "", err
	}
	c, seen := b.client(t)
	base := strings.TrimRight(t.URL, "/")
	do := func(method, path string, body any) (int, map[string]any, error) {
		var rd io.Reader
		if body != nil {
			j, _ := json.Marshal(body)
			rd = bytes.NewReader(j)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
		if err != nil {
			return 0, nil, err
		}
		req.SetBasicAuth(t.Username, pw)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer res.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&m)
		return res.StatusCode, m, nil
	}
	st, sys, err := do("GET", "/redfish/v1/Systems", nil)
	if err != nil {
		if strings.Contains(err.Error(), "fingerprint") {
			return "", bmcErr(502, "bmc_certificate_changed", "the BMC at %s shows a different certificate than the pinned one (%s); if that is expected, set tls_fingerprint", t.URL, *seen)
		}
		return "", bmcErr(502, "bmc_unreachable", "the BMC at %s is not reachable (is the relay cabled to it?): %v", t.URL, err)
	}
	if normFingerprint(t.TLSFingerprint) == "" && b.pins.get(t.ID) == "" && *seen != "" {
		b.pins.set(t.ID, *seen)
		slog.Info("bmc relay: certificate learned and pinned", "target", t.ID, "sha256", *seen)
	}
	switch {
	case st == 401 || st == 403:
		return "", bmcErr(502, "bmc_refused", "the BMC at %s refused the login (%d)", t.URL, st)
	case st != 200:
		return "", bmcErr(502, "bmc_error", "the BMC answered %d to /redfish/v1/Systems (Redfish not available? try backend: ipmitool)", st)
	}
	members, _ := sys["Members"].([]any)
	var member string
	if len(members) > 0 {
		if m, ok := members[0].(map[string]any); ok {
			member, _ = m["@odata.id"].(string)
		}
	}
	if !strings.HasPrefix(member, "/redfish/v1/") {
		return "", bmcErr(502, "bmc_error", "the BMC lists no system under /redfish/v1/Systems")
	}
	if action == "status" {
		st, m, err := do("GET", member, nil)
		if err != nil || st != 200 {
			return "", bmcErr(502, "bmc_error", "the BMC did not return the system's state (%d)", st)
		}
		ps, _ := m["PowerState"].(string)
		return strings.ToLower(ps), nil
	}
	st, _, err = do("POST", member+"/Actions/ComputerSystem.Reset", map[string]any{"ResetType": "On"})
	if err != nil {
		return "", bmcErr(502, "bmc_unreachable", "the BMC at %s stopped answering", t.URL)
	}
	if st < 200 || st > 204 {
		return "", bmcErr(502, "bmc_error", "the BMC answered %d to ComputerSystem.Reset On (already on?)", st)
	}
	return "on", nil
}
