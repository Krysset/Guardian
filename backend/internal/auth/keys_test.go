package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// newTestKeys generates one signing key per algorithm exactly as production does and builds a Keys value
// from them. It returns the private keys and JWKs by algorithm.
func newTestKeys(t *testing.T) (*Keys, map[string]crypto.Signer, map[string][]byte) {
	t.Helper()
	useRing(t, "k1:"+keyB64(9))
	set := keySet{active: map[string]signer{}, pub: map[string]crypto.PublicKey{}}
	privs, jwks := map[string]crypto.Signer{}, map[string][]byte{}
	for _, alg := range Algorithms {
		sk, err := NewSigningKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		der, err := Decrypt(sk.PrivateKeyEncrypted, signingKeyAAD(sk.KID))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatal(err)
		}
		priv := parsed.(crypto.Signer)
		pub, err := jwkToPublicKey(sk.PublicJWK)
		if err != nil {
			t.Fatal(err)
		}
		set.active[alg] = signer{sk.KID, priv}
		set.pub[sk.KID] = pub
		privs[alg], jwks[alg] = priv, sk.PublicJWK
	}
	return &Keys{set: set}, privs, jwks
}

func TestGeneratedKeysPublishOnlyPublicParameters(t *testing.T) {
	_, privs, jwks := newTestKeys(t)
	for alg, want := range map[string]map[string]string{
		"RS256": {"kty": "RSA", "alg": "RS256"},
		"ES256": {"kty": "EC", "alg": "ES256", "crv": "P-256"},
	} {
		var m map[string]any
		if err := json.Unmarshal(jwks[alg], &m); err != nil {
			t.Fatal(err)
		}
		for k, v := range want {
			if m[k] != v {
				t.Errorf("%s JWK: %s = %v, want %s", alg, k, m[k], v)
			}
		}
		if m["use"] != "sig" || m["kid"] == "" {
			t.Errorf("%s JWK: %v", alg, m)
		}
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, leaked := m[private]; leaked {
				t.Errorf("%s JWK leaks private parameter %q", alg, private)
			}
		}
		pub, err := jwkToPublicKey(jwks[alg])
		if err != nil {
			t.Fatal(err)
		}
		if !privs[alg].Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(pub) {
			t.Errorf("%s JWK does not round-trip to the original public key", alg)
		}
	}
}

// An EC point that is not on the curve is refused, so a crafted JWK cannot become a key.
func TestOffCurveECKeyIsRefused(t *testing.T) {
	bad := []byte(`{"kty":"EC","crv":"P-256","x":"AQ","y":"Ag"}`)
	if _, err := jwkToPublicKey(bad); err == nil {
		t.Error("a point off the curve was accepted")
	}
	if _, err := jwkToPublicKey([]byte(`{"kty":"EC","crv":"P-384","x":"AQ","y":"Ag"}`)); err == nil {
		t.Error("an unsupported curve was accepted")
	}
}

func TestSignAndVerifyWithKeyfunc(t *testing.T) {
	k, _, _ := newTestKeys(t)
	for _, alg := range Algorithms {
		signed, err := k.Sign(alg, jwt.MapClaims{"sub": "user-1", "iss": "https://auth.test"}, "")
		if err != nil {
			t.Fatal(err)
		}
		tok, err := jwt.Parse(signed, k.Keyfunc, jwt.WithValidMethods(Algorithms), jwt.WithIssuer("https://auth.test"))
		if err != nil || !tok.Valid {
			t.Fatalf("%s: valid token rejected: %v", alg, err)
		}
		if tok.Method.Alg() != alg || tok.Header["kid"] != k.ActiveKID(alg) || tok.Header["typ"] != "JWT" {
			t.Fatalf("%s: unexpected header: %v", alg, tok.Header)
		}
	}
	// An unknown algorithm falls back to RS256, which every app handles.
	signed, _ := k.Sign("", jwt.MapClaims{"sub": "x"}, "")
	if tok, err := jwt.Parse(signed, k.Keyfunc, jwt.WithValidMethods(Algorithms)); err != nil || tok.Method.Alg() != "RS256" {
		t.Errorf("fallback: %v", err)
	}
}

func TestSignTypeOverride(t *testing.T) {
	k, _, _ := newTestKeys(t)
	signed, _ := k.Sign("ES256", jwt.MapClaims{"sub": "x"}, "logout+jwt")
	tok, err := jwt.Parse(signed, k.Keyfunc, jwt.WithValidMethods(Algorithms))
	if err != nil {
		t.Fatal(err)
	}
	if tok.Header["typ"] != "logout+jwt" {
		t.Fatalf("typ = %v", tok.Header["typ"])
	}
}

func TestVerificationRejectsForgeries(t *testing.T) {
	k, _, _ := newTestKeys(t)
	opts := []jwt.ParserOption{jwt.WithValidMethods(Algorithms)}
	parse := func(what string, tok *jwt.Token, key any) {
		t.Helper()
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jwt.Parse(s, k.Keyfunc, opts...); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
	withKID := func(m jwt.SigningMethod, kid string) *jwt.Token {
		tok := jwt.NewWithClaims(m, jwt.MapClaims{"sub": "admin"})
		tok.Header["kid"] = kid
		return tok
	}

	// signed by an attacker's key but claiming our kid, for each algorithm
	rsaAttacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecAttacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	parse("an RS256 token signed by a foreign key", withKID(jwt.SigningMethodRS256, k.ActiveKID("RS256")), rsaAttacker)
	parse("an ES256 token signed by a foreign key", withKID(jwt.SigningMethodES256, k.ActiveKID("ES256")), ecAttacker)
	parse("a token with an unknown kid", withKID(jwt.SigningMethodRS256, "nope"), rsaAttacker)
	// an algorithm that does not fit the named key
	parse("an ES256 token naming the RSA key", withKID(jwt.SigningMethodES256, k.ActiveKID("RS256")), ecAttacker)
	parse("an RS256 token naming the EC key", withKID(jwt.SigningMethodRS256, k.ActiveKID("ES256")), rsaAttacker)
	parse("an unsigned (alg=none) token", withKID(jwt.SigningMethodNone, k.ActiveKID("RS256")), jwt.UnsafeAllowNoneSignatureType)
	// HS256 using anything as the secret (algorithm confusion)
	parse("an HS256 token", withKID(jwt.SigningMethodHS256, k.ActiveKID("RS256")), []byte("anything"))
}

func TestExpiredTokensAreRejected(t *testing.T) {
	k, _, _ := newTestKeys(t)
	for _, alg := range Algorithms {
		s, _ := k.Sign(alg, jwt.MapClaims{"sub": "x", "exp": 1}, "")
		if _, err := jwt.Parse(s, k.Keyfunc, jwt.WithValidMethods(Algorithms)); err == nil {
			t.Fatalf("%s: expired token accepted", alg)
		}
	}
}
