package enroll

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// Pairing v2. In v1 the panel sends the same proof every time and the agent answers with its tokens in clear,
// so the panel cannot tell the agent from anything else that answers, and whoever reads the answer has the
// tokens. In v2 both sides hold a key made from the join code, and the exchange is
//
//	panel -> agent  POST /pair  {"v":2,"nonce":Np,"mac":HMAC-SHA256(Kreq, Np)}
//	agent -> panel  200         {"v":2,"nonce":Na,"sealed":AES-256-GCM(Kans, IV, Response JSON, AAD)}
//
// with (HKDF is RFC 5869 with SHA-256, "|" is concatenation, Np and Na are 16 random bytes each):
//
//	K           = HKDF(secret = the normalised code (32 ASCII characters), salt = none, info = "fairy-enroll-v2 key", 32 bytes)
//	Kreq        = HKDF(secret = K, salt = none,    info = "fairy-enroll-v2 request", 32 bytes)
//	Kans | IV   = HKDF(secret = K, salt = Np | Na, info = "fairy-enroll-v2 answer",  32 + 12 bytes)
//	AAD         = "fairy-enroll-v2 answer" | Np | Na
//
// K is what `fairy-agent join --pair-v2` stores (State.Key2) and what the panel keeps instead of the code.
//
//   - The agent is authenticated: only a holder of K can make an answer that opens under the panel's fresh Np.
//   - The tokens are encrypted: a reader of the exchange sees two nonces, a MAC and a ciphertext.
//   - Replay: an old answer does not open for a new request (Np is new, so Kans is another key); an old request
//     sent again gets an answer its sender cannot read (and, as in v1, uses the code up: the agent answers once).
//   - Reflection: request and answer use different keys and different shapes (a MAC over 16 bytes, an AEAD
//     box), so neither can be sent back as the other.
//   - Downgrade: the version is not negotiated. The join command stores either the v1 verifier or K, never
//     both, and the agent refuses the other version's request; the labels above carry the version, so nothing
//     made for v2 means anything elsewhere. A panel that asked with v2 accepts only a sealed v2 answer.
//   - Kans and IV are used for one message only: Na is new for every answer, so a repeated Np never repeats them.
const (
	// V2 is the "v" of RequestV2 and AnswerV2.
	V2 = 2
	// NonceSize is the length of the panel's and of the agent's nonce.
	NonceSize = 16
	// KeySize is the length of a v2 pairing key (PairingKey) and of the request MAC.
	KeySize = 32

	labelKey     = "fairy-enroll-v2 key"
	labelRequest = "fairy-enroll-v2 request"
	labelAnswer  = "fairy-enroll-v2 answer"

	gcmNonceSize = 12
	gcmTagSize   = 16
	// maxAnswerV2 bounds the sealed part of an answer (the Response with a Proxmox CA certificate is a few KiB).
	maxAnswerV2 = 64 << 10
	// MaxAnswerBody is the largest v2 answer body the agent sends (the sealed part in base64 and the rest of
	// the JSON): the panel reads at most this much of a 200 answer before OpenAnswer.
	MaxAnswerBody = 96 << 10
)

var (
	// ErrBadKey: the pairing key is not KeySize bytes.
	ErrBadKey = errors.New("enroll: not a v2 pairing key")
	// ErrNotV2: the request or the answer is not a well-formed v2 message (wrong "v", nonce or MAC length, no
	// sealed part). An answer in the v1 shape (tokens in clear) is this error: it is never accepted for a v2
	// request.
	ErrNotV2 = errors.New("enroll: not a pairing v2 message")
	// ErrWrongCode: the request's MAC was not made with this agent's pairing key (another join code).
	ErrWrongCode = errors.New("enroll: the request was not made with this join code")
	// ErrUnauthentic: the answer does not open: it was not made with this join code for this request (an
	// impostor, a replayed or altered answer, an answer to another request).
	ErrUnauthentic = errors.New("enroll: the answer was not made by an agent that has this join code, for this request")
)

// PairingKey is the v2 pairing key K of a join code: the installer stores it (State.Key2, hex) and the panel
// keeps it in memory. Neither side stores the code itself.
func PairingKey(code string) ([]byte, error) {
	c, err := Normalize(code)
	if err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, []byte(c), nil, labelKey, KeySize)
}

// RequestV2 is the panel's POST /pair body in v2. Nonce and MAC are base64 in JSON (encoding/json's []byte).
type RequestV2 struct {
	V     int    `json:"v"`     // 2
	Nonce []byte `json:"nonce"` // Np: NonceSize random bytes, new for every request
	MAC   []byte `json:"mac"`   // HMAC-SHA256(Kreq, Np)
}

// AnswerV2 is the agent's answer to a correct RequestV2. It is sent once.
type AnswerV2 struct {
	V      int    `json:"v"`      // 2
	Nonce  []byte `json:"nonce"`  // Na: NonceSize random bytes
	Sealed []byte `json:"sealed"` // AES-256-GCM ciphertext and tag of the Response's JSON
}

func requestMAC(key, nonce []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrBadKey
	}
	k, err := hkdf.Key(sha256.New, key, nil, labelRequest, KeySize)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, k)
	m.Write(nonce)
	return m.Sum(nil), nil
}

// answerAEAD is the one-message cipher for the answer to the request with nonce np, given the agent's nonce na.
func answerAEAD(key, np, na []byte) (aead cipher.AEAD, iv, aad []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, nil, ErrBadKey
	}
	if len(np) != NonceSize || len(na) != NonceSize {
		return nil, nil, nil, ErrNotV2
	}
	salt := append(append(make([]byte, 0, 2*NonceSize), np...), na...)
	okm, err := hkdf.Key(sha256.New, key, salt, labelAnswer, KeySize+gcmNonceSize)
	if err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(okm[:KeySize])
	if err != nil {
		return nil, nil, nil, err
	}
	if aead, err = cipher.NewGCM(block); err != nil {
		return nil, nil, nil, err
	}
	return aead, okm[KeySize:], append([]byte(labelAnswer), salt...), nil
}

// NewRequestV2 makes the panel's next request for a pairing key, with a new nonce. The panel keeps the request
// until the answer arrives: OpenAnswer needs it.
func NewRequestV2(key []byte) (RequestV2, error) {
	np := make([]byte, NonceSize)
	if _, err := rand.Read(np); err != nil {
		return RequestV2{}, err
	}
	return newRequestV2(key, np)
}

func newRequestV2(key, np []byte) (RequestV2, error) {
	mac, err := requestMAC(key, np)
	if err != nil {
		return RequestV2{}, err
	}
	return RequestV2{V: V2, Nonce: np, MAC: mac}, nil
}

// CheckRequestV2 is the agent's check of a request against its pairing key: nil when the sender has the key,
// ErrNotV2 for a malformed request (not a guess at the code), ErrWrongCode for a wrong MAC (compared in
// constant time).
func CheckRequestV2(key []byte, req RequestV2) error {
	if req.V != V2 || len(req.Nonce) != NonceSize || len(req.MAC) != sha256.Size {
		return ErrNotV2
	}
	want, err := requestMAC(key, req.Nonce)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, req.MAC) {
		return ErrWrongCode
	}
	return nil
}

// SealAnswer is the agent's answer to a request that passed CheckRequestV2: the Response (tokens included)
// encrypted and authenticated for exactly that request, under a new agent nonce.
func SealAnswer(key []byte, req RequestV2, resp Response) (AnswerV2, error) {
	na := make([]byte, NonceSize)
	if _, err := rand.Read(na); err != nil {
		return AnswerV2{}, err
	}
	return sealAnswer(key, req, na, resp)
}

func sealAnswer(key []byte, req RequestV2, na []byte, resp Response) (AnswerV2, error) {
	if err := CheckRequestV2(key, req); err != nil {
		return AnswerV2{}, err
	}
	plain, err := json.Marshal(resp)
	if err != nil {
		return AnswerV2{}, err
	}
	if len(plain)+gcmTagSize > maxAnswerV2 {
		return AnswerV2{}, errors.New("enroll: the answer is too large")
	}
	aead, iv, aad, err := answerAEAD(key, req.Nonce, na)
	if err != nil {
		return AnswerV2{}, err
	}
	return AnswerV2{V: V2, Nonce: na, Sealed: aead.Seal(nil, iv, plain, aad)}, nil
}

// OpenAnswer is the panel's side: body is what the agent answered with status 200 to req (the request made by
// NewRequestV2 with the same key). It returns the agent's Response only when the answer was made by a holder
// of the key for this very request. ErrNotV2: the body is not a v2 answer (for one, an answer in the v1 shape
// with the tokens in clear: an old exchange is never accepted here). ErrUnauthentic: it does not open.
func OpenAnswer(key []byte, req RequestV2, body []byte) (Response, error) {
	var resp Response
	if len(key) != KeySize {
		return resp, ErrBadKey
	}
	if req.V != V2 || len(req.Nonce) != NonceSize {
		return resp, ErrNotV2
	}
	var ans AnswerV2
	if err := json.Unmarshal(body, &ans); err != nil {
		return resp, ErrNotV2
	}
	if ans.V != V2 || len(ans.Nonce) != NonceSize || len(ans.Sealed) < gcmTagSize || len(ans.Sealed) > maxAnswerV2 {
		return resp, ErrNotV2
	}
	aead, iv, aad, err := answerAEAD(key, req.Nonce, ans.Nonce)
	if err != nil {
		return resp, err
	}
	plain, err := aead.Open(nil, iv, ans.Sealed, aad)
	if err != nil {
		return resp, ErrUnauthentic
	}
	if err := json.Unmarshal(plain, &resp); err != nil {
		return Response{}, ErrUnauthentic
	}
	return resp, nil
}
