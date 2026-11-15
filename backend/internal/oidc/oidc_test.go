package oidc

import (
	"reflect"
	"strings"
	"testing"

	db "guardian/internal/store"
)

func TestSliceHelpers(t *testing.T) {
	if !subset([]string{"a"}, []string{"a", "b"}) || subset([]string{"a", "c"}, []string{"a", "b"}) || !subset(nil, nil) {
		t.Error("subset")
	}
	in := []string{"a", "b", "a"}
	if got := without(in, "a"); !reflect.DeepEqual(got, []string{"b"}) {
		t.Errorf("without = %v", got)
	}
	if !reflect.DeepEqual(in, []string{"a", "b", "a"}) {
		t.Error("without mutated its input")
	}
	base := []string{"a", "b"}
	if got := union(base, []string{"b", "c", "c"}); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("union = %v", got)
	}
	if !reflect.DeepEqual(base, []string{"a", "b"}) {
		t.Error("union mutated its input")
	}
}

// RFC 7636 appendix B test vector.
func TestVerifyPKCE(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !verifyPKCE(verifier, challenge) {
		t.Fatal("RFC 7636 vector rejected")
	}
	if verifyPKCE(verifier+"x", challenge) || verifyPKCE(challenge, challenge) {
		t.Error("wrong verifier accepted")
	}
	if verifyPKCE("short", challenge) {
		t.Error("verifier shorter than 43 characters must be rejected")
	}
	if verifyPKCE(strings.Repeat("a", 129), challenge) {
		t.Error("verifier longer than 128 characters must be rejected")
	}
	if verifyPKCE(verifier, "") {
		t.Error("empty challenge accepted")
	}
}

func TestBuildClaimsReleasesOnlyWhatScopesAllow(t *testing.T) {
	acct := db.Account{
		ID: "11111111-1111-1111-1111-111111111111", Username: "alice", DisplayName: "Alice A", GivenName: "Alice",
		Email: "alice@example.com", EmailVerified: true,
		PictureURL: "https://x.test/a.png", Locale: "sv-SE",
	}
	keys := func(m map[string]any) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		return out
	}

	only := BuildClaims(acct, nil)
	if len(only) != 1 || only["sub"] != acct.ID {
		t.Fatalf("with no scopes only sub may be released, got %v", keys(only))
	}

	email := BuildClaims(acct, []string{"email", "email_verified"})
	if email["email"] != "alice@example.com" || email["email_verified"] != true {
		t.Errorf("email claims = %v", email)
	}
	for _, leaked := range []string{"name", "preferred_username", "phone_number", "picture", "locale"} {
		if _, ok := email[leaked]; ok {
			t.Errorf("email scope leaked %q", leaked)
		}
	}

	profile := BuildClaims(acct, []string{"name", "given_name", "preferred_username", "picture", "locale", "updated_at"})
	if profile["name"] != "Alice A" || profile["preferred_username"] != "alice" || profile["given_name"] != "Alice" {
		t.Errorf("profile claims = %v", profile)
	}
	if _, ok := profile["updated_at"]; !ok {
		t.Error("updated_at missing")
	}
	if _, ok := profile["email"]; ok {
		t.Error("profile scope leaked email")
	}
	if _, ok := profile["family_name"]; ok {
		t.Error("empty values must be omitted")
	}

	// phone claims were removed; even if a scope listed them, nothing is released
	if got := BuildClaims(acct, []string{"phone_number", "phone_number_verified", "birthdate"}); len(got) != 1 {
		t.Errorf("removed claims were released: %v", keys(got))
	}

	// email_verified alone must not reveal the address, and an account without email releases no email claims
	if got := BuildClaims(acct, []string{"email_verified"}); len(got) != 1 {
		t.Errorf("email_verified without email leaked %v", keys(got))
	}
	acct.Email = ""
	if got := BuildClaims(acct, []string{"email", "email_verified"}); len(got) != 1 {
		t.Errorf("account without email released %v", keys(got))
	}
}
