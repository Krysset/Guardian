package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// Signing keys are encrypted at rest with AES-256-GCM. The key comes from KEY_ENCRYPTION_KEY (see the
// config package). Losing it means losing the signing keys.
var encryptionKey []byte

// SetEncryptionKey sets the key used to encrypt and decrypt signing keys. Call it once at startup,
// before LoadKeys. The key must be 32 bytes.
func SetEncryptionKey(key []byte) error {
	if len(key) != 32 {
		return errors.New("the key encryption key must be 32 bytes")
	}
	encryptionKey = append([]byte(nil), key...)
	return nil
}

func newGCM() (cipher.AEAD, error) {
	if encryptionKey == nil {
		return nil, errors.New("the key encryption key is not set")
	}
	block, err := aes.NewCipher(encryptionKey)
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

// Seal encrypts a small secret (a TOTP secret, a setup token) with the key encryption key.
func Seal(plain []byte) (string, error) { return encrypt(plain) }

// Open decrypts what Seal produced. Tampered or foreign ciphertext fails.
func Open(sealed string) ([]byte, error) { return decrypt(sealed) }
