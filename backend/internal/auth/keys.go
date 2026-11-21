package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// Keys holds the active signing key of each algorithm plus every published public key (for verification
// and JWKS). Reload reads them again; the key maintenance (RunKeyMaintenance) does so every minute, so every
// replica follows a rotation within a minute.
type Keys struct {
	mu   sync.RWMutex
	set  keySet
	load func() (keySet, error)
}

type signer struct {
	kid  string
	priv crypto.Signer
}

type keySet struct {
	active map[string]signer // by algorithm
	pub    map[string]crypto.PublicKey
	jwks   []byte
}

// Algorithms are the JWT signing methods Guardian signs with, and the only ones it accepts back.
var Algorithms = db.SigningAlgs

// LoadKeys makes sure every algorithm has an active signing key (creating them on first run) and loads the
// keys.
func LoadKeys() (*Keys, error) {
	if err := db.EnsureSigningKeys(NewSigningKey); err != nil {
		return nil, fmt.Errorf("ensuring signing keys: %w", err)
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

// ActiveKID is the id of the key that signs with alg ("" if there is none).
func (k *Keys) ActiveKID(alg string) string { return k.current().active[alg].kid }

func loadKeySet() (keySet, error) {
	actives, err := db.GetActiveSigningKeys()
	if err != nil {
		return keySet{}, err
	}
	set := keySet{active: map[string]signer{}, pub: map[string]crypto.PublicKey{}}
	for _, a := range actives {
		der, err := Decrypt(a.PrivateKeyEncrypted, signingKeyAAD(a.KID))
		if err != nil {
			return keySet{}, fmt.Errorf("decrypting signing key %s: %w", a.KID, err)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return keySet{}, err
		}
		priv, ok := parsed.(crypto.Signer)
		if !ok || algOf(priv.Public()) != a.Alg {
			return keySet{}, fmt.Errorf("signing key %s is not an %s key", a.KID, a.Alg)
		}
		set.active[a.Alg] = signer{a.KID, priv}
	}
	if _, ok := set.active["RS256"]; !ok {
		return keySet{}, errors.New("there is no active RS256 signing key")
	}

	published, err := db.GetPublishedSigningKeys()
	if err != nil {
		return keySet{}, err
	}
	var jwks []json.RawMessage
	for _, pk := range published {
		pub, err := jwkToPublicKey(pk.PublicJWK)
		if err != nil || algOf(pub) != pk.Alg {
			slog.Warn("skipping an unreadable public key", "kid", pk.KID, "error", err)
			continue
		}
		set.pub[pk.KID] = pub
		jwks = append(jwks, json.RawMessage(pk.PublicJWK))
	}
	if set.jwks, err = json.Marshal(map[string]any{"keys": jwks}); err != nil {
		return keySet{}, err
	}
	return set, nil
}

// algOf is the algorithm a public key signs with here: RS256 for RSA, ES256 for P-256.
func algOf(pub crypto.PublicKey) string {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return "RS256"
	case *ecdsa.PublicKey:
		if p.Curve == elliptic.P256() {
			return "ES256"
		}
	}
	return ""
}

func signingKeyAAD(kid string) string { return AAD("signing_key", "private_key_encrypted", kid) }

// Sign signs claims with alg (RS256 or ES256, the app's choice; anything else signs with RS256). typ
// overrides the JWT "typ" header when non-empty (e.g. "at+jwt" for access tokens, "logout+jwt" for
// back-channel logout tokens).
func (k *Keys) Sign(alg string, claims jwt.MapClaims, typ string) (string, error) {
	set := k.current()
	key, ok := set.active[alg]
	if !ok {
		alg, key = "RS256", set.active["RS256"]
	}
	method := jwt.SigningMethod(jwt.SigningMethodRS256)
	if alg == "ES256" {
		method = jwt.SigningMethodES256
	}
	t := jwt.NewWithClaims(method, claims)
	t.Header["kid"] = key.kid
	if typ != "" {
		t.Header["typ"] = typ
	}
	return t.SignedString(key.priv)
}

// Keyfunc is a jwt.Keyfunc that selects the public key by the token's kid header. The key's type must fit
// the token's algorithm, so a token cannot name an RSA key and claim another algorithm.
func (k *Keys) Keyfunc(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	key, ok := k.current().pub[kid]
	if !ok {
		return nil, errors.New("unknown signing key")
	}
	if t.Method == nil || algOf(key) != t.Method.Alg() {
		return nil, errors.New("the token's algorithm does not fit its key")
	}
	return key, nil
}

// JWKS returns the JSON served at jwks_uri.
func (k *Keys) JWKS() []byte { return k.current().jwks }

// NewSigningKey makes a new signing key for alg (RSA-2048 for RS256, P-256 for ES256), its private half
// encrypted with the keyring.
func NewSigningKey(alg string) (db.SigningKey, error) {
	var priv crypto.Signer
	var err error
	switch alg {
	case "RS256":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ES256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return db.SigningKey{}, fmt.Errorf("unknown signing algorithm %q", alg)
	}
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
	b64 := base64.RawURLEncoding.EncodeToString
	jwk := map[string]string{"use": "sig", "alg": alg, "kid": kid}
	switch p := priv.Public().(type) {
	case *rsa.PublicKey:
		jwk["kty"], jwk["n"], jwk["e"] = "RSA", b64(p.N.Bytes()), b64(big.NewInt(int64(p.E)).Bytes())
	case *ecdsa.PublicKey:
		x, y := make([]byte, 32), make([]byte, 32) // fixed length, as RFC 7518 requires
		p.X.FillBytes(x)
		p.Y.FillBytes(y)
		jwk["kty"], jwk["crv"], jwk["x"], jwk["y"] = "EC", "P-256", b64(x), b64(y)
	}
	raw, err := json.Marshal(jwk)
	if err != nil {
		return db.SigningKey{}, err
	}
	return db.SigningKey{KID: kid, Alg: alg, PublicJWK: raw, PrivateKeyEncrypted: enc, Status: "active"}, nil
}

func jwkToPublicKey(raw []byte) (crypto.PublicKey, error) {
	var j struct {
		Kty, Crv, N, E, X, Y string
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, err
	}
	dec := base64.RawURLEncoding.DecodeString
	switch j.Kty {
	case "RSA":
		n, err := dec(j.N)
		if err != nil {
			return nil, err
		}
		e, err := dec(j.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		if j.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported curve %q", j.Crv)
		}
		x, err := dec(j.X)
		if err != nil {
			return nil, err
		}
		y, err := dec(j.Y)
		if err != nil {
			return nil, err
		}
		// Through the uncompressed point encoding, so a point off the curve is refused.
		point := append(append([]byte{4}, x...), y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return nil, err
		}
		return pub, nil
	}
	return nil, fmt.Errorf("unsupported key type %q", j.Kty)
}
