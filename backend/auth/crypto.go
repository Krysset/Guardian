package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
)

// Signing keys are encrypted at rest with AES-256-GCM using KEY_ENCRYPTION_KEY
// (generate with: openssl rand -base64 32). Losing it means losing the signing keys.
func encryptionKey() ([]byte, error) {
	raw := os.Getenv("KEY_ENCRYPTION_KEY")
	if raw == "" {
		return nil, errors.New("KEY_ENCRYPTION_KEY is not set (generate one with: openssl rand -base64 32)")
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("KEY_ENCRYPTION_KEY must be 32 bytes, base64 encoded")
	}
	return key, nil
}

func newGCM() (cipher.AEAD, error) {
	key, err := encryptionKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encrypt(plain []byte) (string, error) {
	gcm, err := newGCM()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plain, nil)), nil
}

func decrypt(encoded string) ([]byte, error) {
	gcm, err := newGCM()
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
}
