package agent

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

// PairingPath is the agent's pairing state file (enroll.State): written by `fairy-agent join` (root /
// Administrator), closed by the running agent, so it lives where the service may write.
func PairingPath(cfg *Config) string {
	switch runtime.GOOS {
	case "linux":
		return "/var/lib/fairy-agent/pairing.json" // StateDirectory=fairy-agent of fairy-agent.service
	case "windows":
		return filepath.Join(cfg.Dir(), "state", "pairing.json") // install / setup-self-update make it writable
	}
	return filepath.Join(cfg.Dir(), "pairing.json")
}

// Pairer answers POST /pair: the panel's first contact after "Add host". It answers only while the state file
// holds an unexpired, unused join code, only to the panel's address stored with it, at most enroll.RatePerMin
// times a minute; a correct proof gets the tokens once and closes pairing for good.
type Pairer struct {
	Path   string
	Tokens func() (Tokens, error)
	Info   func() enroll.Response // version, hostname, platform, features (no tokens)
	Now    func() time.Time

	mu    sync.Mutex
	limit *limiter
}

// NewPairer builds the /pair handler for a state file.
func NewPairer(path string, tokens func() (Tokens, error), info func() enroll.Response) *Pairer {
	return &Pairer{Path: path, Tokens: tokens, Info: info, Now: time.Now, limit: newLimiter(enroll.RatePerMin, time.Minute)}
}

func pairErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": msg, "code": code})
}

// ServeHTTP is POST /pair.
func (p *Pairer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	if p == nil || p.Path == "" {
		pairErr(w, 404, "pairing_inactive", "pairing is not active on this agent")
		return
	}
	if !p.limit.allow("pair") {
		pairErr(w, 429, "rate_limited", "too many pairing requests; try again in a minute")
		return
	}
	var req enroll.Request
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || json.Unmarshal(b, &req) != nil || req.Proof == "" {
		pairErr(w, 400, "bad_request", `expected {"proof": "..."}`)
		return
	}
	ip := clientIP(r)
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.Now()
	st, err := enroll.ReadState(p.Path)
	if err != nil || !st.Active(now) {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("pairing state unreadable", "error", err.Error())
		}
		if err == nil && st.Proxmox != nil { // an expired code: the Proxmox token secret does not stay behind
			st.Proxmox = nil
			if werr := enroll.WriteState(p.Path, st); werr != nil {
				slog.Error("cannot write the pairing state", "error", werr.Error())
			}
		}
		pairErr(w, 404, "pairing_inactive", "pairing is not active on this agent")
		return
	}
	if st.Panel != "" && ip != st.Panel {
		slog.Warn("pairing request refused: not from the panel's address", "remote", ip, "panel", st.Panel)
		pairErr(w, 403, "wrong_address", "pairing is only open to the panel's address")
		return
	}
	if !enroll.Check(req.Proof, st.Verifier) {
		st.Failures++
		if st.Failures >= enroll.MaxFailures {
			st.Closed, st.Verifier, st.Proxmox = "too many wrong codes", "", nil
			slog.Warn("pairing closed after too many wrong codes", "remote", ip)
		} else {
			slog.Warn("pairing request with a wrong code", "remote", ip, "failures", st.Failures)
		}
		if err := enroll.WriteState(p.Path, st); err != nil {
			slog.Error("cannot write the pairing state", "error", err.Error())
		}
		pairErr(w, 403, "wrong_code", "wrong join code")
		return
	}
	tok, err := p.Tokens()
	if err != nil {
		slog.Error("pairing: cannot read this agent's tokens", "error", err.Error())
		pairErr(w, 500, "tokens_unreadable", "the agent cannot read its own tokens; see its log")
		return
	}
	// Close pairing on disk BEFORE the tokens leave: if that fails, nothing is handed out. The Proxmox token
	// secret leaves the file at the same moment (it is sent exactly once).
	grant := st.Proxmox
	st.Closed, st.Verifier, st.PairedAt, st.PairedBy, st.Proxmox = "paired", "", now.Unix(), ip, nil
	if err := enroll.WriteState(p.Path, st); err != nil {
		slog.Error("pairing: cannot close the join code, tokens not sent", "error", err.Error())
		pairErr(w, 500, "state_unwritable", "the agent cannot record the pairing; see its log")
		return
	}
	resp := p.Info()
	resp.Token, resp.ControlToken, resp.Proxmox = tok.Read, tok.Control, grant
	slog.Info("paired with panel", "remote", ip, "control_token", tok.Control != "", "proxmox_token", grant != nil)
	writeJSON(w, 200, resp)
}
