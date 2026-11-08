package tuya

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
)

func pkcs7Pad(b []byte) []byte {
	n := 16 - len(b)%16
	return append(append([]byte{}, b...), bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, ErrDecode
	}
	n := int(b[len(b)-1])
	if n < 1 || n > 16 || n > len(b) {
		return nil, ErrDecode
	}
	return b[:len(b)-n], nil
}

// EncryptECB encrypts with AES-128-ECB (Tuya's choice, not ours), PKCS#7-padded when pad is true.
func EncryptECB(key, data []byte, pad bool) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if pad {
		data = pkcs7Pad(data)
	}
	if len(data)%16 != 0 {
		return nil, ErrDecode
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		blk.Encrypt(out[i:i+16], data[i:i+16])
	}
	return out, nil
}

// DecryptECB decrypts AES-128-ECB, optionally removing PKCS#7 padding.
func DecryptECB(key, data []byte, unpad bool) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, ErrDecode
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		blk.Decrypt(out[i:i+16], data[i:i+16])
	}
	if unpad {
		return pkcs7Unpad(out)
	}
	return out, nil
}

func gcmSeal(key, iv, plain, aad []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk) // 12-byte nonce, 16-byte tag
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, iv, plain, aad), nil // ciphertext || tag
}

func gcmOpen(key, iv, ctAndTag, aad []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, iv, ctAndTag, aad)
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}
