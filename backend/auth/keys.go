package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/golang-jwt/jwt/v5"

	db "guardian/database"
)

// Keys holds the active signing key plus every published public key (for verification and JWKS).
// Keys are loaded once at startup; to rotate, insert a new 'active' key, set the old one to
// 'retiring', and restart.
type Keys struct {
	kid  string
	priv *rsa.PrivateKey
	pub  map[string]*rsa.PublicKey
	jwks []byte
}

// LoadKeys makes sure an active signing key exists (creating one on first run) and loads it.
func LoadKeys() (*Keys, error) {
	if err := db.EnsureSigningKey(generateSigningKey); err != nil {
		return nil, fmt.Errorf("ensuring signing key: %w", err)
	}
	active, err := db.GetActiveSigningKey()
	if err != nil {
		return nil, err
	}
	der, err := decrypt(active.PrivateKeyEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypting signing key (wrong KEY_ENCRYPTION_KEY?): %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not RSA")
	}

	published, err := db.GetPublishedSigningKeys()
	if err != nil {
		return nil, err
	}
	k := &Keys{kid: active.KID, priv: priv, pub: map[string]*rsa.PublicKey{}}
	var jwks []json.RawMessage
	for _, pk := range published {
		pub, err := jwkToPublicKey(pk.PublicJWK)
		if err != nil {
			log.Printf("skipping unreadable public key %s: %v", pk.KID, err)
			continue
		}
		k.pub[pk.KID] = pub
		jwks = append(jwks, json.RawMessage(pk.PublicJWK))
	}
	if k.jwks, err = json.Marshal(map[string]any{"keys": jwks}); err != nil {
		return nil, err
	}
	return k, nil
}

// Sign signs claims with RS256. typ overrides the JWT "typ" header when non-empty
// (e.g. "at+jwt" for access tokens, "logout+jwt" for back-channel logout tokens).
func (k *Keys) Sign(claims jwt.MapClaims, typ string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = k.kid
	if typ != "" {
		t.Header["typ"] = typ
	}
	return t.SignedString(k.priv)
}

// Keyfunc is a jwt.Keyfunc that selects the public key by the token's kid header.
func (k *Keys) Keyfunc(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	if key, ok := k.pub[kid]; ok {
		return key, nil
	}
	return nil, errors.New("unknown signing key")
}

// JWKS returns the JSON served at jwks_uri.
func (k *Keys) JWKS() []byte { return k.jwks }

func generateSigningKey() (db.SigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return db.SigningKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return db.SigningKey{}, err
	}
	enc, err := encrypt(der)
	if err != nil {
		return db.SigningKey{}, err
	}
	kid, err := RandomToken(12)
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
