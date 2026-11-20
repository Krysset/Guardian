package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// The encryption keyring encrypts what Guardian stores secretly: the signing keys' private halves and the
// authenticator-app secrets. It is read from KEY_ENCRYPTION_KEYS_FILE (or KEY_ENCRYPTION_KEYS), written
// "k2:<base64>,k1:<base64>": 32-byte AES keys with ids. The first key encrypts; every key decrypts.
//
// A stored value is "v1:<key id>:<base64 of nonce and ciphertext>", AES-256-GCM, with the table, column and
// row as associated data, so a value copied to another row or column does not decrypt.
//
// Rotating: add the new key at the end (it decrypts only), let every replica load it, then move it to the
// front (it encrypts). Re-encryption moves the stored values to it in the background; once
// guardian_keyring_values reports none under the old key, remove the old key.

// Key is one key of the keyring.
type Key struct {
	ID  string
	key []byte
}

// Fingerprint identifies a key's material without revealing it: the first 8 bytes of its SHA-256, in hex.
func (k Key) Fingerprint() string {
	sum := sha256.Sum256(k.key)
	return hex.EncodeToString(sum[:8])
}

// Keyring is an ordered set of keys; the first one encrypts.
type Keyring struct {
	keys []Key
}

var keyIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ParseKeyring reads "k2:<base64>,k1:<base64>" (spaces and newlines around the parts are ignored).
func ParseKeyring(spec string) (*Keyring, error) {
	ring := &Keyring{}
	for _, part := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == '\n' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, b64, ok := strings.Cut(part, ":")
		if !ok || !keyIDRe.MatchString(id) {
			return nil, fmt.Errorf("keyring entry %q: expected <id>:<base64 key>, the id in lower case letters, digits, - and _", short(part))
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("keyring key %s must be 32 bytes, base64 encoded (generate one with: openssl rand -base64 32)", id)
		}
		if ring.Has(id) {
			return nil, fmt.Errorf("keyring key id %s appears twice", id)
		}
		ring.keys = append(ring.keys, Key{ID: id, key: key})
	}
	if len(ring.keys) == 0 {
		return nil, errors.New("the keyring is empty (write it as k1:<base64>, generating the key with: openssl rand -base64 32)")
	}
	return ring, nil
}

func short(s string) string {
	if i := strings.Index(s, ":"); i >= 0 {
		return s[:i] + ":..."
	}
	return "..."
}

// Primary is the key that encrypts.
func (r *Keyring) Primary() Key { return r.keys[0] }

// Keys returns the keys, the primary first.
func (r *Keyring) Keys() []Key { return slices.Clone(r.keys) }

// Has reports whether the keyring has a key with this id.
func (r *Keyring) Has(id string) bool {
	_, ok := r.get(id)
	return ok
}

func (r *Keyring) get(id string) (Key, bool) {
	for _, k := range r.keys {
		if k.ID == id {
			return k, true
		}
	}
	return Key{}, false
}

// Fingerprints maps each key id to its fingerprint.
func (r *Keyring) Fingerprints() map[string]string {
	out := map[string]string{}
	for _, k := range r.keys {
		out[k.ID] = k.Fingerprint()
	}
	return out
}

var (
	ringMu sync.RWMutex
	ring   *Keyring
)

// SetKeyring makes r the keyring.
func SetKeyring(r *Keyring) {
	ringMu.Lock()
	ring = r
	ringMu.Unlock()
}

// CurrentKeyring returns the keyring, or nil before SetKeyring.
func CurrentKeyring() *Keyring {
	ringMu.RLock()
	defer ringMu.RUnlock()
	return ring
}

// SetEncryptionKey makes a keyring of one key with the id "k1". For tests and tools.
func SetEncryptionKey(key []byte) error {
	if len(key) != 32 {
		return errors.New("the key encryption key must be 32 bytes")
	}
	SetKeyring(&Keyring{keys: []Key{{ID: "k1", key: append([]byte(nil), key...)}}})
	return nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ErrUnknownKey means a value was encrypted with a key the keyring does not have.
var ErrUnknownKey = errors.New("the value is encrypted with a key that is not in the keyring")

// Encrypt encrypts with the primary key. aad names where the value is stored (see AAD).
func Encrypt(plain []byte, aad string) (string, error) {
	r := CurrentKeyring()
	if r == nil {
		return "", errors.New("the encryption keyring is not set")
	}
	k := r.Primary()
	aead, err := gcm(k.key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return "v1:" + k.ID + ":" + base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, []byte(aad))), nil
}

// KeyIDOf returns the id of the key a value is encrypted with, or "" if it is not a keyring value.
func KeyIDOf(value string) string {
	parts := strings.SplitN(value, ":", 3)
	if len(parts) != 3 || parts[0] != "v1" {
		return ""
	}
	return parts[1]
}

// Decrypt decrypts a value with the key named in it.
func Decrypt(value, aad string) ([]byte, error) {
	parts := strings.SplitN(value, ":", 3)
	if len(parts) != 3 || parts[0] != "v1" {
		return nil, errors.New("not an encrypted value")
	}
	r := CurrentKeyring()
	if r == nil {
		return nil, errors.New("the encryption keyring is not set")
	}
	k, ok := r.get(parts[1])
	if !ok {
		return nil, fmt.Errorf("%w (key id %s)", ErrUnknownKey, parts[1])
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	aead, err := gcm(k.key)
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(aad))
}

// AAD is the associated data of a stored value: its table, column and row.
func AAD(table, column, row string) string { return table + "." + column + ":" + row }

// sealAAD is the associated data of sealed tokens and cookies, which are never stored.
const sealAAD = "sealed"

// Seal encrypts a small secret that the browser carries (a sign-in flow, a setup token).
func Seal(plain []byte) (string, error) { return Encrypt(plain, sealAAD) }

// Open decrypts what Seal produced. Tampered or foreign ciphertext fails.
func Open(sealed string) ([]byte, error) { return Decrypt(sealed, sealAAD) }
