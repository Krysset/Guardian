package auth_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"guardian/internal/auth"
	db "guardian/internal/store"
	"guardian/internal/testutil"
)

func spec(parts ...string) string {
	var out []string
	for _, p := range parts {
		out = append(out, p+":"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{p[1]}, 32)))
	}
	return strings.Join(out, ",")
}

func ring(t *testing.T, s string) *auth.Keyring {
	t.Helper()
	r, err := auth.ParseKeyring(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The whole keyring rotation: add a key decrypt-only, promote it, let re-encryption move every value,
// then drop the old key. Guardian refuses a keyring that lacks a key still in use.
//
// Covers: P3
func TestKeyringRotationReencryptsEverything(t *testing.T) {
	testutil.RequireTestDB(t)
	testutil.Reset(t)
	testutil.DeleteSigningKeys()
	previous := auth.CurrentKeyring()
	// Leave nothing encrypted under this test's keys: the next test process checks its keyring against
	// the database before it starts.
	t.Cleanup(func() {
		auth.SetKeyring(previous)
		testutil.DeleteSigningKeys()
		testutil.Reset(t)
	})
	auth.SetKeyring(ring(t, spec("k1")))
	keys, err := auth.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	acct := testutil.CreateAccount(t, "zora")
	secret := testutil.EnableTOTP(t, acct.ID)
	token, err := keys.Sign(jwt.MapClaims{"sub": "x"}, "")
	if err != nil {
		t.Fatal(err)
	}
	counts := func() string {
		c, err := auth.ValuesPerKey()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, id := range []string{"k1", "k2", "k3"} {
			if c[id] > 0 {
				out = append(out, id+"="+string(rune('0'+c[id])))
			}
		}
		return strings.Join(out, " ")
	}
	if got := counts(); got != "k1=2" {
		t.Fatalf("values per key = %s, want the signing key and the app secret under k1", got)
	}

	file := filepath.Join(t.TempDir(), "keys")
	write := func(s string) {
		if err := os.WriteFile(file, []byte(s+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sched := auth.DefaultSchedule

	// 1. Add k2 at the end: it may decrypt, nothing moves.
	write(spec("k1", "k2"))
	auth.MaintainKeys(keys, sched, file)
	if auth.CurrentKeyring().Primary().ID != "k1" || counts() != "k1=2" {
		t.Fatalf("after adding k2: primary %s, %s", auth.CurrentKeyring().Primary().ID, counts())
	}
	// 2. Promote k2: re-encryption moves every value to it.
	write(spec("k2", "k1"))
	auth.MaintainKeys(keys, sched, file)
	if auth.CurrentKeyring().Primary().ID != "k2" || counts() != "k2=2" {
		t.Fatalf("after promoting k2: primary %s, %s", auth.CurrentKeyring().Primary().ID, counts())
	}
	// 3. A keyring without the key in use is refused; the previous one stays.
	write(spec("k3"))
	auth.MaintainKeys(keys, sched, file)
	if !auth.CurrentKeyring().Has("k2") {
		t.Fatal("a keyring lacking a needed key was accepted")
	}
	if err := auth.CheckKeyring(ring(t, spec("k3"))); err == nil || !strings.Contains(err.Error(), "k2") {
		t.Errorf("CheckKeyring: %v", err)
	}
	// 4. Drop k1: everything still works.
	write(spec("k2"))
	auth.MaintainKeys(keys, sched, file)
	if auth.CurrentKeyring().Has("k1") {
		t.Fatal("k1 was not dropped")
	}
	if _, err := jwt.Parse(token, keys.Keyfunc); err != nil {
		t.Errorf("a token signed before the rotation: %v", err)
	}
	f, _ := db.GetTOTP(acct.ID)
	if got, err := auth.Decrypt(f.SealedSecret, auth.AAD("account_mfa", "secret", acct.ID)); err != nil || string(got) != secret {
		t.Errorf("the authenticator secret after the rotation: %v", err)
	}
	if fresh, err := auth.LoadKeys(); err != nil || fresh.ActiveKID() != keys.ActiveKID() {
		t.Errorf("loading the keys again: %v", err)
	}
}

// After an emergency rotation every replica signs with the new key within a minute, and tokens signed
// with the revoked key no longer verify.
//
// Covers: P3
func TestKeysFollowARotation(t *testing.T) {
	testutil.RequireTestDB(t)
	testutil.Reset(t)
	testutil.DeleteSigningKeys()
	previous := auth.CurrentKeyring()
	// Leave nothing encrypted under this test's keys: the next test process checks its keyring against
	// the database before it starts.
	t.Cleanup(func() {
		auth.SetKeyring(previous)
		testutil.DeleteSigningKeys()
		testutil.Reset(t)
	})
	auth.SetKeyring(ring(t, spec("k1")))
	keys, err := auth.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	old := keys.ActiveKID()
	before, _ := keys.Sign(jwt.MapClaims{"sub": "x"}, "")
	k, err := auth.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.EmergencyRotate(k); err != nil {
		t.Fatal(err)
	}
	if keys.ActiveKID() != old {
		t.Fatal("the keys changed before a reload")
	}
	auth.MaintainKeys(keys, auth.DefaultSchedule, "")
	if keys.ActiveKID() != k.KID {
		t.Fatalf("active = %s after the reload, want %s", keys.ActiveKID(), k.KID)
	}
	if _, err := jwt.Parse(before, keys.Keyfunc); err == nil {
		t.Error("a token signed with the revoked key still verifies")
	}
	if !strings.Contains(string(keys.JWKS()), k.KID) || strings.Contains(string(keys.JWKS()), old) {
		t.Errorf("JWKS = %s", keys.JWKS())
	}
}
