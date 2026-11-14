package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// newTestKeys generates a signing key exactly as production does and builds a Keys value from it.
func newTestKeys(t *testing.T) (*Keys, *rsa.PrivateKey, []byte) {
	t.Helper()
	t.Setenv("KEY_ENCRYPTION_KEY", testKey(9))
	sk, err := generateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := decrypt(sk.PrivateKeyEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	priv := parsed.(*rsa.PrivateKey)
	pub, err := jwkToPublicKey(sk.PublicJWK)
	if err != nil {
		t.Fatal(err)
	}
	return &Keys{kid: sk.KID, priv: priv, pub: map[string]*rsa.PublicKey{sk.KID: pub}}, priv, sk.PublicJWK
}

func TestGeneratedKeyPublishesOnlyPublicParameters(t *testing.T) {
	_, priv, jwk := newTestKeys(t)
	var m map[string]any
	if err := json.Unmarshal(jwk, &m); err != nil {
		t.Fatal(err)
	}
	if m["kty"] != "RSA" || m["alg"] != "RS256" || m["use"] != "sig" || m["kid"] == "" {
		t.Fatalf("unexpected JWK: %v", m)
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, leaked := m[private]; leaked {
			t.Fatalf("JWK leaks private parameter %q", private)
		}
	}
	pub, err := jwkToPublicKey(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if pub.N.Cmp(priv.N) != 0 || pub.E != priv.E {
		t.Fatal("JWK does not round-trip to the original public key")
	}
}

func TestSignAndVerifyWithKeyfunc(t *testing.T) {
	k, _, _ := newTestKeys(t)
	signed, err := k.Sign(jwt.MapClaims{"sub": "user-1", "iss": "https://auth.test"}, "")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Parse(signed, k.Keyfunc, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("https://auth.test"))
	if err != nil || !tok.Valid {
		t.Fatalf("valid token rejected: %v", err)
	}
	if tok.Header["kid"] != k.kid || tok.Header["typ"] != "JWT" {
		t.Fatalf("unexpected header: %v", tok.Header)
	}
}

func TestSignTypeOverride(t *testing.T) {
	k, _, _ := newTestKeys(t)
	signed, _ := k.Sign(jwt.MapClaims{"sub": "x"}, "logout+jwt")
	tok, err := jwt.Parse(signed, k.Keyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatal(err)
	}
	if tok.Header["typ"] != "logout+jwt" {
		t.Fatalf("typ = %v", tok.Header["typ"])
	}
}

func TestVerificationRejectsForgeries(t *testing.T) {
	k, _, _ := newTestKeys(t)
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"})}

	// signed by an attacker's key but claiming our kid
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "admin"})
	forged.Header["kid"] = k.kid
	s, _ := forged.SignedString(attacker)
	if _, err := jwt.Parse(s, k.Keyfunc, opts...); err == nil {
		t.Error("token signed by a foreign key was accepted")
	}

	// unknown kid
	unknown := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "admin"})
	unknown.Header["kid"] = "nope"
	s, _ = unknown.SignedString(attacker)
	if _, err := jwt.Parse(s, k.Keyfunc, opts...); err == nil {
		t.Error("token with unknown kid was accepted")
	}

	// alg=none
	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "admin"})
	none.Header["kid"] = k.kid
	s, _ = none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := jwt.Parse(s, k.Keyfunc, opts...); err == nil {
		t.Error("unsigned (alg=none) token was accepted")
	}

	// HS256 using the public key as the secret (algorithm confusion)
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "admin"})
	hs.Header["kid"] = k.kid
	s, _ = hs.SignedString([]byte("anything"))
	if _, err := jwt.Parse(s, k.Keyfunc, opts...); err == nil {
		t.Error("HS256 token was accepted")
	}
}

func TestExpiredTokensAreRejected(t *testing.T) {
	k, _, _ := newTestKeys(t)
	s, _ := k.Sign(jwt.MapClaims{"sub": "x", "exp": 1}, "")
	if _, err := jwt.Parse(s, k.Keyfunc, jwt.WithValidMethods([]string{"RS256"})); err == nil {
		t.Fatal("expired token accepted")
	}
}
