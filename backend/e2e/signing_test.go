package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	db "guardian/internal/store"
	"guardian/internal/testutil"
)

// publishedECKey finds the ES256 key with this kid in the JWKS, the way an app would: only from what is
// published.
func publishedECKey(t *testing.T, b *browser, kid string) *ecdsa.PublicKey {
	t.Helper()
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal([]byte(readBody(t, b.get("/jwks.json"))), &jwks); err != nil {
		t.Fatal(err)
	}
	for _, k := range jwks.Keys {
		if k["kid"] != kid {
			continue
		}
		if k["kty"] != "EC" || k["crv"] != "P-256" || k["alg"] != "ES256" {
			t.Fatalf("published key %s = %v", kid, k)
		}
		x, _ := base64.RawURLEncoding.DecodeString(k["x"])
		y, _ := base64.RawURLEncoding.DecodeString(k["y"])
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			t.Fatal(err)
		}
		return pub
	}
	t.Fatalf("kid %s is not in the JWKS", kid)
	return nil
}

// Each app's tokens are signed with the algorithm it chose: RS256 by default, ES256 on request. Both keys
// are published, an app verifies its tokens from the JWKS alone, and a change applies at the next refresh
// while tokens already issued keep working.
//
// Covers: A30
func TestE2EAppsChooseTheirSigningAlgorithm(t *testing.T) {
	testutil.Reset(t)
	testutil.CreateAccount(t, "alice")
	endpoint, logoutTokens := startReceiver(t)
	es, esSecret := testutil.CreateApp(t, "modern", testutil.AppOptions{FirstParty: true, SigningAlg: "ES256", BackchannelURI: endpoint})
	rs, rsSecret := testutil.CreateApp(t, "classic", testutil.AppOptions{FirstParty: true})
	b := newBrowser(t)

	resp := b.get("/.well-known/openid-configuration")
	disc := decodeMap(t, resp)
	if algs := groupList(map[string]any{"groups": disc["id_token_signing_alg_values_supported"]}); !slices.Equal(algs, []string{"RS256", "ES256"}) {
		t.Errorf("id_token_signing_alg_values_supported = %v", algs)
	}

	esTok := b.signIn(es, esSecret, "alice", "openid")
	for name, raw := range map[string]string{"ID": esTok.ID, "access": esTok.Access} {
		unverified, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
		if err != nil {
			t.Fatal(err)
		}
		if unverified.Method.Alg() != "ES256" {
			t.Fatalf("%s token alg = %s, want ES256", name, unverified.Method.Alg())
		}
		kid, _ := unverified.Header["kid"].(string)
		pub := publishedECKey(t, b, kid)
		if _, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"ES256"}),
			jwt.WithIssuer(testIssuer), jwt.WithAudience(es.ClientID)); err != nil {
			t.Errorf("the %s token does not verify against the published JWKS: %v", name, err)
		}
	}
	if status, _ := userinfoStatus(t, esTok.Access); status != http.StatusOK {
		t.Errorf("userinfo with an ES256 access token = %d", status)
	}

	// The default stays RS256 (parseJWT accepts RS256 only).
	rsTok := b.signIn(rs, rsSecret, "alice", "openid")
	verifyAccessToken(t, rs, rsTok.Access)
	parseJWT(t, rsTok.ID, jwt.WithAudience(rs.ClientID))

	// Switching an app applies at its next refresh; the token it already has keeps working.
	alg := "ES256"
	if _, err := db.UpdateApp(rs.ID, db.AppUpdate{SigningAlg: &alg}); err != nil {
		t.Fatal(err)
	}
	next := refreshed(t, rs, rsSecret, rsTok.Refresh)
	if unverified, _, _ := jwt.NewParser().ParseUnverified(next.Access, jwt.MapClaims{}); unverified.Method.Alg() != "ES256" {
		t.Errorf("after the switch the access token is %s", unverified.Method.Alg())
	}
	if status, _ := userinfoStatus(t, rsTok.Access); status != http.StatusOK {
		t.Errorf("the RS256 token issued before the switch = %d at userinfo", status)
	}

	// The back-channel logout token follows the app's choice too.
	drain(b.logout())
	raw := waitToken(t, logoutTokens)
	lt, err := jwt.Parse(raw, testKeys.Keyfunc, jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience(es.ClientID))
	if err != nil || lt.Header["typ"] != "logout+jwt" {
		t.Errorf("logout token: %v %v", err, lt)
	}
}
