package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"

	"github.com/golang-jwt/jwt/v5"

	db "guardian/internal/store"
)

// Keys holds the active signing key plus every published public key (for verification and JWKS). Reload
// reads them again; the key maintenance (RunKeyMaintenance) does so every minute, so every replica follows
// a rotation within a minute.
type Keys struct {
	mu   sync.RWMutex
	set  keySet
	load func() (keySet, error)
}

type keySet struct {
	kid  string
	priv *rsa.PrivateKey
	pub  map[string]*rsa.PublicKey
	jwks []byte
}

// LoadKeys makes sure an active signing key exists (creating one on first run) and loads the keys.
func LoadKeys() (*Keys, error) {
	if err := db.EnsureSigningKey(NewSigningKey); err != nil {
		return nil, fmt.Errorf("ensuring signing key: %w", err)
	}
	k := &Keys{load: loadKeySet}
	return k, k.Reload()
}

// Reload reads the keys from the database again. On failure the keys stay as they were.
func (k *Keys) Reload() error {
	set, err := k.load()
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.set = set
	k.mu.Unlock()
	return nil
}

func (k *Keys) current() keySet {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.set
}

// ActiveKID is the id of the key that signs.
func (k *Keys) ActiveKID() string { return k.current().kid }

func loadKeySet() (keySet, error) {
	active, err := db.GetActiveSigningKey()
	if err != nil {
		return keySet{}, err
	}
	der, err := Decrypt(active.PrivateKeyEncrypted, signingKeyAAD(active.KID))
	if err != nil {
		return keySet{}, fmt.Errorf("decrypting signing key %s: %w", active.KID, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return keySet{}, err
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return keySet{}, errors.New("signing key is not RSA")
	}

	published, err := db.GetPublishedSigningKeys()
	if err != nil {
		return keySet{}, err
	}
	k := keySet{kid: active.KID, priv: priv, pub: map[string]*rsa.PublicKey{}}
	var jwks []json.RawMessage
	for _, pk := range published {
		pub, err := jwkToPublicKey(pk.PublicJWK)
		if err != nil {
			slog.Warn("skipping an unreadable public key", "kid", pk.KID, "error", err)
			continue
		}
		k.pub[pk.KID] = pub
		jwks = append(jwks, json.RawMessage(pk.PublicJWK))
	}
	if k.jwks, err = json.Marshal(map[string]any{"keys": jwks}); err != nil {
		return keySet{}, err
	}
	return k, nil
}

func signingKeyAAD(kid string) string { return AAD("signing_key", "private_key_encrypted", kid) }

// Sign signs claims with RS256. typ overrides the JWT "typ" header when non-empty
// (e.g. "at+jwt" for access tokens, "logout+jwt" for back-channel logout tokens).
func (k *Keys) Sign(claims jwt.MapClaims, typ string) (string, error) {
	set := k.current()
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = set.kid
	if typ != "" {
		t.Header["typ"] = typ
	}
	return t.SignedString(set.priv)
}

// Keyfunc is a jwt.Keyfunc that selects the public key by the token's kid header.
func (k *Keys) Keyfunc(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	if key, ok := k.current().pub[kid]; ok {
		return key, nil
	}
	return nil, errors.New("unknown signing key")
}

// JWKS returns the JSON served at jwks_uri.
func (k *Keys) JWKS() []byte { return k.current().jwks }

// NewSigningKey makes a new RSA-2048 signing key, its private half encrypted with the keyring.
func NewSigningKey() (db.SigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return db.SigningKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return db.SigningKey{}, err
	}
	kid, err := RandomToken(12)
	if err != nil {
		return db.SigningKey{}, err
	}
	enc, err := Encrypt(der, signingKeyAAD(kid))
	if err != nil {
		return db.SigningKey{}, err
	}
	jwk, err := json.Marshal(map[string]string{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
	})
	if err != nil {
		return db.SigningKey{}, err
	}
	return db.SigningKey{KID: kid, Alg: "RS256", PublicJWK: jwk, PrivateKeyEncrypted: enc, Status: "active"}, nil
}

func jwkToPublicKey(raw []byte) (*rsa.PublicKey, error) {
	var j struct {
		N string `json:"n"`
		E string `json:"e"`
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, err
	}
	n, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
}
