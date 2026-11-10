package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
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

// pairOthersPerMin is how many /pair requests from addresses other than the panel's are looked at per minute,
// all of them together (each such address has enroll.RatePerMin of its own inside that).
const pairOthersPerMin = 4 * enroll.RatePerMin

// Pairer answers POST /pair: the panel's first contact after "Add host". It answers only while the state file
// holds an unexpired, unused join code, only to the panel's address stored with it, at most enroll.RatePerMin
// times a minute; a correct proof gets the tokens once and closes pairing for good.
//
// Two versions, chosen by the join command and never by the request (enroll.State.PairVersion): v1 compares
// the proof with the stored verifier and answers with the tokens in clear (panels that do not know v2); v2
// checks the request's MAC under the stored key and answers with the tokens encrypted and authenticated for
// that request (enroll.SealAnswer). A request of the other version is refused with 400 wrong_version.
//
// Who is asking is settled before anything is counted: the panel's address has a budget of its own, which no
// other address can use up. Every other address is refused anyway and has its own small budget (so that one
// machine cannot fill the log), inside one shared budget (so that many addresses cannot either).
type Pairer struct {
	Path   string
	Tokens func() (Tokens, error)
	Info   func() enroll.Response // version, hostname, platform, features (no tokens)
	Now    func() time.Time

	mu     sync.Mutex
	limit  *limiter // the panel's address
	each   *limiter // any other address, per address
	others *limiter // all other addresses together
}

// NewPairer builds the /pair handler for a state file.
func NewPairer(path string, tokens func() (Tokens, error), info func() enroll.Response) *Pairer {
	return &Pairer{Path: path, Tokens: tokens, Info: info, Now: time.Now, limit: newLimiter(enroll.RatePerMin, time.Minute),
		each: newLimiter(enroll.RatePerMin, time.Minute), others: newLimiter(pairOthersPerMin, time.Minute)}
}

func pairErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": msg, "code": code})
}

// allow counts one request in the budget of who sent it. Another address gets an entry of its own only while
// the shared budget has room, so the per-address table stays small whatever arrives.
func (p *Pairer) allow(ip string, fromPanel bool) bool {
	if fromPanel {
		return p.limit.allow("panel")
	}
	return p.others.allowPeek("others") && p.each.allow(ip) && p.others.allow("others")
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
	// A browser can send a form or text body to this port without asking (no CORS preflight), JSON it cannot.
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		pairErr(w, 415, "unsupported_media_type", "expected Content-Type: application/json")
		return
	}
	ip := clientIP(r)
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.Now()
	st, err := enroll.ReadState(p.Path)
	// The caller's address first: only then is the request counted, in the panel's budget or the others'.
	if !p.allow(ip, err == nil && st.Panel != "" && ip == st.Panel) {
		pairErr(w, 429, "rate_limited", "too many pairing requests; try again in a minute")
		return
	}
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
	var req pairRequest
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || json.Unmarshal(b, &req) != nil {
		pairErr(w, 400, "bad_request", `expected {"proof": "..."} or a pairing v2 request`)
		return
	}
	// The join command chose the version (v1 verifier or v2 key in the state); the request cannot change it.
	// A v1 proof is never checked, and tokens never leave in clear, when the code was stored for v2.
	want := st.PairVersion()
	if got := req.version(); got != want {
		if got == 0 {
			pairErr(w, 400, "bad_request", `expected {"proof": "..."} or a pairing v2 request`)
			return
		}
		slog.Warn("pairing request refused: wrong pairing version", "remote", ip, "request", got, "join_code_for", want)
		writeJSON(w, 400, map[string]any{"error": fmt.Sprintf("this agent's join code is for pairing v%d, the request is v%d", want, got),
			"code": "wrong_version", "pair": want})
		return
	}
	var key []byte
	if want == enroll.V2 {
		if key, err = st.PairingKey2(); err == nil {
			err = enroll.CheckRequestV2(key, req.v2())
		}
		switch {
		case errors.Is(err, enroll.ErrNotV2):
			pairErr(w, 400, "bad_request", "malformed pairing v2 request")
			return
		case err != nil && !errors.Is(err, enroll.ErrWrongCode):
			slog.Error("pairing: the stored v2 key is unusable", "error", err.Error())
			pairErr(w, 500, "state_unreadable", "the agent cannot use its pairing state; run the join command again")
			return
		}
	} else if !enroll.Check(req.Proof, st.Verifier) {
		err = enroll.ErrWrongCode
	}
	if err != nil {
		st.Failures++
		if st.Failures >= enroll.MaxFailures {
			st.Closed, st.Verifier, st.Key2, st.Proxmox = "too many wrong codes", "", "", nil
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
	grant := st.Proxmox
	resp := p.Info()
	resp.Token, resp.ControlToken, resp.Proxmox = tok.Read, tok.Control, grant
	// v2: the answer is encrypted and authenticated for this request before anything is recorded, so a failure
	// here leaves the code usable.
	var answer any = resp
	if want == enroll.V2 {
		sealed, err := enroll.SealAnswer(key, req.v2(), resp)
		if err != nil {
			slog.Error("pairing: cannot seal the answer, tokens not sent", "error", err.Error())
			pairErr(w, 500, "seal_failed", "the agent cannot encrypt its answer; see its log")
			return
		}
		answer = sealed
	}
	// Close pairing on disk BEFORE the tokens leave: if that fails, nothing is handed out. The Proxmox token
	// secret leaves the file at the same moment (it is sent exactly once).
	st.Closed, st.Verifier, st.Key2, st.PairedAt, st.PairedBy, st.Proxmox = "paired", "", "", now.Unix(), ip, nil
	if err := enroll.WriteState(p.Path, st); err != nil {
		slog.Error("pairing: cannot close the join code, tokens not sent", "error", err.Error())
		pairErr(w, 500, "state_unwritable", "the agent cannot record the pairing; see its log")
		return
	}
	slog.Info("paired with panel", "remote", ip, "pairing", want, "control_token", tok.Control != "", "proxmox_token", grant != nil)
	writeJSON(w, 200, answer)
}

// pairRequest is a POST /pair body of either version: {"proof"} (v1, enroll.Request) or {"v":2,"nonce","mac"}
// (enroll.RequestV2).
type pairRequest struct {
	Proof string `json:"proof"`
	V     int    `json:"v"`
	Nonce []byte `json:"nonce"`
	MAC   []byte `json:"mac"`
}

// version is 1 for a v1 body, the body's "v" otherwise (0: neither).
func (q pairRequest) version() int {
	switch {
	case q.V != 0:
		return q.V
	case q.Proof != "":
		return 1
	}
	return 0
}

func (q pairRequest) v2() enroll.RequestV2 {
	return enroll.RequestV2{V: q.V, Nonce: q.Nonce, MAC: q.MAC}
}
