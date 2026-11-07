package database_test

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"guardian/auth"
	db "guardian/database"
	"guardian/internal/testutil"
)

// ---- Sessions ---------------------------------------------------------------

func TestSessionLookupAndExpiry(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "gina")
	sess, cookie := testutil.Session(t, acct.ID)

	got, err := db.GetSessionByHash(auth.HashToken(cookie))
	if err != nil || got.ID != sess.ID || got.AccountID != acct.ID {
		t.Fatalf("lookup failed: %+v, %v", got, err)
	}
	if !db.SessionActive(sess.ID) {
		t.Error("SessionActive = false for a live session")
	}
	if _, err := db.GetSessionByHash(auth.HashToken("some-other-cookie")); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown cookie: %v", err)
	}
	if db.SessionActive("not-a-uuid") || db.SessionActive("00000000-0000-0000-0000-000000000000") {
		t.Error("SessionActive must be false for malformed or unknown ids")
	}

	// the raw cookie value is never stored, only its hash
	if n := testutil.Count(t, `SELECT count(*) FROM session WHERE session_hash = $1`, cookie); n != 0 {
		t.Error("plaintext session cookie found in the database")
	}
	if n := testutil.Count(t, `SELECT count(*) FROM session WHERE session_hash = $1`, auth.HashToken(cookie)); n != 1 {
		t.Error("hashed session cookie not stored")
	}

	expired, err := db.CreateSession(acct.ID, auth.HashToken("expired"), "203.0.113.5", "ua", -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetSessionByHash(auth.HashToken("expired")); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expired session accepted: %v", err)
	}
	if db.SessionActive(expired.ID) {
		t.Error("expired session reported active")
	}

	testutil.Exec(t, `UPDATE account SET status = 'disabled' WHERE id = $1`, acct.ID)
	if _, err := db.GetSessionByHash(auth.HashToken(cookie)); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("session of a disabled account accepted: %v", err)
	}
}

func TestSessionLastSeenIsWrittenSparingly(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "hank")
	sess, cookie := testutil.Session(t, acct.ID)
	hash := auth.HashToken(cookie)

	testutil.Exec(t, `UPDATE session SET last_seen_at = now() - interval '2 minutes' WHERE id = $1`, sess.ID)
	if _, err := db.GetSessionByHash(hash); err != nil {
		t.Fatal(err)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM session WHERE id = $1 AND last_seen_at < now() - interval '90 seconds'`, sess.ID); n != 1 {
		t.Error("last_seen_at was rewritten on a read that happened within the touch interval")
	}

	testutil.Exec(t, `UPDATE session SET last_seen_at = now() - interval '10 minutes' WHERE id = $1`, sess.ID)
	if _, err := db.GetSessionByHash(hash); err != nil {
		t.Fatal(err)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM session WHERE id = $1 AND last_seen_at > now() - interval '1 minute'`, sess.ID); n != 1 {
		t.Error("stale last_seen_at was not refreshed")
	}
}

func TestRevokeSessionEndsEverythingUnderIt(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "iris")
	withHook, _ := testutil.CreateApp(t, "hooked", testutil.AppOptions{BackchannelURI: "http://127.0.0.1:9/bcl"})
	noHook, _ := testutil.CreateApp(t, "plain", testutil.AppOptions{})
	sess, cookie := testutil.Session(t, acct.ID)
	db.TrackSessionApp(sess.ID, withHook.ID)
	db.TrackSessionApp(sess.ID, noHook.ID)
	token := testutil.Token(t, withHook, acct.ID, sess.ID, time.Hour)

	family, _ := auth.NewUUID()
	refresh := auth.HashToken("refresh-1")
	if err := db.SaveRefreshToken(refresh, family, withHook.ID, acct.ID, sess.ID, []string{"openid"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	targets, err := db.RevokeSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].ClientID != withHook.ClientID || targets[0].URI != "http://127.0.0.1:9/bcl" {
		t.Fatalf("only apps with a back-channel URI must be notified, got %+v", targets)
	}
	if _, err := db.GetSessionByHash(auth.HashToken(cookie)); !errors.Is(err, sql.ErrNoRows) {
		t.Error("revoked session still resolves")
	}
	if db.SessionActive(sess.ID) {
		t.Error("revoked session still active")
	}
	if _, err := db.IntrospectAccessToken(auth.HashToken(token), withHook.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Error("access token of a revoked session is still active")
	}
	if _, err := db.RotateRefreshToken(refresh, withHook.ID, auth.HashToken("refresh-2"), time.Now().Add(time.Hour)); !errors.Is(err, db.ErrInvalidGrant) {
		t.Errorf("refresh token of a revoked session still works: %v", err)
	}

	// revoking again (double logout) is harmless and notifies nobody a second time
	again, err := db.RevokeSession(sess.ID)
	if err != nil || len(again) != 0 {
		t.Errorf("second revoke = %v, %v", again, err)
	}
	if none, err := db.RevokeSession("00000000-0000-0000-0000-000000000000"); err != nil || len(none) != 0 {
		t.Errorf("revoking an unknown session = %v, %v", none, err)
	}
}

// ---- Authorization codes ----------------------------------------------------

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "jane")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	sess, _ := testutil.Session(t, acct.ID)

	save := func(code string, ttl time.Duration, sessionID, nonce, challenge string) {
		t.Helper()
		err := db.SaveAuthCode(auth.HashToken(code), db.AuthCode{
			AppID: app.ID, AccountID: acct.ID, SessionID: sessionID, RedirectURI: "https://billing.test/callback",
			Scopes: []string{"openid", "email"}, Nonce: nonce, CodeChallenge: challenge, AuthTime: time.Now(),
		}, ttl)
		if err != nil {
			t.Fatal(err)
		}
	}

	save("code-1", time.Minute, sess.ID, "nonce-1", "challenge-1")
	got, err := db.ConsumeAuthCode(auth.HashToken("code-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got.AppID != app.ID || got.AccountID != acct.ID || got.SessionID != sess.ID || got.RedirectURI != "https://billing.test/callback" ||
		got.Nonce != "nonce-1" || got.CodeChallenge != "challenge-1" || len(got.Scopes) != 2 {
		t.Fatalf("stored code did not round-trip: %+v", got)
	}
	if _, err := db.ConsumeAuthCode(auth.HashToken("code-1")); !errors.Is(err, db.ErrInvalidGrant) {
		t.Errorf("second redemption: %v", err)
	}
	if _, err := db.ConsumeAuthCode(auth.HashToken("never-issued")); !errors.Is(err, db.ErrInvalidGrant) {
		t.Errorf("unknown code: %v", err)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM authorization_code WHERE code_hash = $1`, "code-1"); n != 0 {
		t.Error("plaintext code stored")
	}

	save("code-expired", -time.Second, sess.ID, "", "")
	if _, err := db.ConsumeAuthCode(auth.HashToken("code-expired")); !errors.Is(err, db.ErrInvalidGrant) {
		t.Errorf("expired code: %v", err)
	}

	save("code-bare", time.Minute, "", "", "")
	bare, err := db.ConsumeAuthCode(auth.HashToken("code-bare"))
	if err != nil || bare.SessionID != "" || bare.Nonce != "" || bare.CodeChallenge != "" {
		t.Errorf("optional fields: %+v, %v", bare, err)
	}
}

func TestConcurrentRedemptionsOfOneCodeYieldExactlyOneWinner(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "kim")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	hash := auth.HashToken("contested")
	if err := db.SaveAuthCode(hash, db.AuthCode{AppID: app.ID, AccountID: acct.ID, RedirectURI: "https://billing.test/callback",
		Scopes: []string{"openid"}, AuthTime: time.Now()}, time.Minute); err != nil {
		t.Fatal(err)
	}
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.ConsumeAuthCode(hash); err == nil {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent redemptions succeeded, want exactly 1", wins)
	}
}

// ---- Refresh tokens ---------------------------------------------------------

func TestRefreshTokenRotationAndReuseDetection(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "liam")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	other, _ := testutil.CreateApp(t, "other", testutil.AppOptions{})
	sess, _ := testutil.Session(t, acct.ID)
	family, _ := auth.NewUUID()
	h := func(s string) string { return auth.HashToken(s) }
	in := func() time.Time { return time.Now().Add(time.Hour) }

	if err := db.SaveRefreshToken(h("r1"), family, app.ID, acct.ID, sess.ID, []string{"openid", "offline_access"}, in()); err != nil {
		t.Fatal(err)
	}

	// a different app cannot redeem it, and that does not burn it
	if _, err := db.RotateRefreshToken(h("r1"), other.ID, h("x"), in()); !errors.Is(err, db.ErrInvalidGrant) {
		t.Fatalf("redeemed by the wrong app: %v", err)
	}
	old, err := db.RotateRefreshToken(h("r1"), app.ID, h("r2"), in())
	if err != nil {
		t.Fatal(err)
	}
	if old.AccountID != acct.ID || old.SessionID != sess.ID || old.FamilyID != family || len(old.Scopes) != 2 {
		t.Fatalf("rotation lost context: %+v", old)
	}
	if _, err := db.RotateRefreshToken(h("r2"), app.ID, h("r3"), in()); err != nil {
		t.Fatalf("the rotated token must be usable: %v", err)
	}

	// presenting an already-rotated token = theft signal: revoke the whole family
	if _, err := db.RotateRefreshToken(h("r1"), app.ID, h("r4"), in()); !errors.Is(err, db.ErrTokenReuse) {
		t.Fatalf("reuse not detected: %v", err)
	}
	if _, err := db.RotateRefreshToken(h("r3"), app.ID, h("r5"), in()); !errors.Is(err, db.ErrInvalidGrant) {
		t.Fatalf("the newest token of a compromised family must be revoked, got %v", err)
	}
	if _, err := db.RotateRefreshToken(h("unknown"), app.ID, h("r6"), in()); !errors.Is(err, db.ErrInvalidGrant) {
		t.Errorf("unknown token: %v", err)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM refresh_token WHERE token_hash = $1`, "r1"); n != 0 {
		t.Error("plaintext refresh token stored")
	}
}

func TestExpiredRefreshTokenIsRejected(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "mia")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	family, _ := auth.NewUUID()
	if err := db.SaveRefreshToken(auth.HashToken("old"), family, app.ID, acct.ID, "", []string{"openid"}, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RotateRefreshToken(auth.HashToken("old"), app.ID, auth.HashToken("new"), time.Now().Add(time.Hour)); !errors.Is(err, db.ErrInvalidGrant) {
		t.Fatalf("expired refresh token accepted: %v", err)
	}
}

func TestConcurrentRotationOfOneRefreshTokenHasOneWinner(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "noah")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	family, _ := auth.NewUUID()
	if err := db.SaveRefreshToken(auth.HashToken("shared"), family, app.ID, acct.ID, "", []string{"openid"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			next := auth.HashToken("next-" + string(rune('a'+i)))
			if _, err := db.RotateRefreshToken(auth.HashToken("shared"), app.ID, next, time.Now().Add(time.Hour)); err == nil {
				atomic.AddInt32(&wins, 1)
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent rotations succeeded, want exactly 1", wins)
	}
}

// ---- Rate limiting ----------------------------------------------------------

// A window of a century never rolls over, so counts are deterministic.
const stableWindow = 100 * 365 * 24 * time.Hour

func TestRateLimitCounters(t *testing.T) {
	testutil.Reset(t)
	if n, err := db.RateLimitCount("k", stableWindow); err != nil || n != 0 {
		t.Fatalf("initial count = %d, %v", n, err)
	}
	for want := 1; want <= 3; want++ {
		if n, err := db.RateLimitHit("k", stableWindow); err != nil || n != want {
			t.Fatalf("hit %d returned %d, %v", want, n, err)
		}
	}
	if n, _ := db.RateLimitCount("k", stableWindow); n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
	if n, _ := db.RateLimitCount("other", stableWindow); n != 0 {
		t.Error("counters of different keys must be independent")
	}
	if err := db.RateLimitReset("k", stableWindow); err != nil {
		t.Fatal(err)
	}
	if n, _ := db.RateLimitCount("k", stableWindow); n != 0 {
		t.Error("reset did not clear the counter")
	}
	if n, _ := db.RateLimitHit("k", stableWindow); n != 1 {
		t.Error("counting must restart after a reset")
	}
}

func TestRateLimitConcurrentHitsAreNotLost(t *testing.T) {
	testutil.Reset(t)
	const n = 25
	results := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = db.RateLimitHit("burst", stableWindow)
		}(i)
	}
	wg.Wait()
	sort.Ints(results)
	for i, got := range results {
		if got != i+1 {
			t.Fatalf("hits must be counted atomically (1..%d), got %v", n, results)
		}
	}
}

func TestRateLimitWindowsRollOver(t *testing.T) {
	testutil.Reset(t)
	db.RateLimitHit("roll", time.Second)
	db.RateLimitHit("roll", time.Second)
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)) + 150*time.Millisecond)
	if n, _ := db.RateLimitHit("roll", time.Second); n != 1 {
		t.Fatalf("a new window must start at 1, got %d", n)
	}
}

// ---- Accounts ---------------------------------------------------------------

func TestUsernamesAndEmailsAreUniqueCaseInsensitively(t *testing.T) {
	testutil.Reset(t)
	a := testutil.CreateAccount(t, "Alice")
	if _, err := db.CreateAccount("alice", "hash"); !db.IsUniqueViolation(err) {
		t.Errorf("usernames differing only in case: %v", err)
	}
	got, hash, err := db.GetAccountByUsername("aLiCe")
	if err != nil || got.ID != a.ID || hash == "" {
		t.Errorf("case-insensitive lookup: %v %v", got.ID, err)
	}
	if _, _, err := db.GetAccountByUsername("nobody"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown user: %v", err)
	}

	b := testutil.CreateAccount(t, "bob")
	if _, err := db.UpdateProfile(db.Account{ID: a.ID, Email: "Shared@Example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateProfile(db.Account{ID: b.ID, Email: "shared@example.com"}); !db.IsUniqueViolation(err) {
		t.Errorf("emails differing only in case: %v", err)
	}
	if err := db.UpdateUsername(b.ID, "ALICE"); !db.IsUniqueViolation(err) {
		t.Errorf("rename onto an existing username: %v", err)
	}
	if err := db.UpdateUsername(b.ID, "robert"); err != nil {
		t.Errorf("valid rename: %v", err)
	}
	if _, err := db.GetAccount("not-a-uuid"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("malformed id: %v", err)
	}
}

func TestChangingEmailClearsItsVerification(t *testing.T) {
	testutil.Reset(t)
	a := testutil.CreateAccount(t, "cara")
	if _, err := db.UpdateProfile(db.Account{ID: a.ID, Email: "cara@example.com", DisplayName: "Cara"}); err != nil {
		t.Fatal(err)
	}
	testutil.Exec(t, `UPDATE account SET email_verified_at = now() WHERE id = $1`, a.ID)

	same, err := db.UpdateProfile(db.Account{ID: a.ID, Email: "cara@example.com", DisplayName: "Cara C"})
	if err != nil || !same.EmailVerified || same.DisplayName != "Cara C" {
		t.Fatalf("unchanged email must stay verified: %+v, %v", same, err)
	}
	changed, err := db.UpdateProfile(db.Account{ID: a.ID, Email: "new@example.com"})
	if err != nil || changed.EmailVerified {
		t.Fatalf("a new email must not inherit verification: %+v, %v", changed, err)
	}
	cleared, err := db.UpdateProfile(db.Account{ID: a.ID})
	if err != nil || cleared.Email != "" || cleared.DisplayName != "" {
		t.Fatalf("empty values must clear the fields: %+v, %v", cleared, err)
	}
}

func TestSeededAdminHasNoPasswordUntilBootstrapped(t *testing.T) {
	testutil.Reset(t)
	admin, hash, err := db.GetAccountByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	if hash != "" || !admin.MustChangePassword || admin.Status != "active" {
		t.Fatalf("seed must not ship a usable password: hash=%q %+v", hash, admin)
	}
	newHash, _ := auth.HashPassword("a-real-password")
	if set, err := db.SetAdminPasswordIfUnset(newHash); err != nil || !set {
		t.Fatalf("first bootstrap = %v, %v", set, err)
	}
	if set, _ := db.SetAdminPasswordIfUnset("another"); set {
		t.Fatal("bootstrap must never overwrite an existing admin password")
	}
	_, stored, _ := db.GetAccountByUsername("admin")
	if !auth.VerifyPassword("a-real-password", stored) {
		t.Fatal("stored hash does not verify")
	}
	if err := db.UpdatePasswordHash(admin.ID, newHash); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetAccount(admin.ID); got.MustChangePassword {
		t.Error("changing the password must clear must_change_password")
	}
}

func TestSoftDeleteLocksTheAccountOutEverywhere(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "olga")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	sess, cookie := testutil.Session(t, acct.ID)
	token := testutil.Token(t, app, acct.ID, sess.ID, time.Hour)
	family, _ := auth.NewUUID()
	db.SaveRefreshToken(auth.HashToken("rt"), family, app.ID, acct.ID, sess.ID, []string{"openid"}, time.Now().Add(time.Hour))

	if err := db.SoftDeleteAccount(acct.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetAccount(acct.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Error("deleted account still readable")
	}
	if _, _, err := db.GetAccountByUsername("olga"); !errors.Is(err, sql.ErrNoRows) {
		t.Error("deleted account still found by username (login must fail)")
	}
	if _, err := db.GetSessionByHash(auth.HashToken(cookie)); !errors.Is(err, sql.ErrNoRows) {
		t.Error("session survived account deletion")
	}
	if _, err := db.IntrospectAccessToken(auth.HashToken(token), app.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Error("access token survived account deletion")
	}
	if _, err := db.RotateRefreshToken(auth.HashToken("rt"), app.ID, auth.HashToken("rt2"), time.Now().Add(time.Hour)); !errors.Is(err, db.ErrInvalidGrant) {
		t.Error("refresh token survived account deletion")
	}
	// current behaviour: the username stays reserved by the soft-deleted row
	if _, err := db.CreateAccount("olga", "hash"); !db.IsUniqueViolation(err) {
		t.Errorf("username reuse after soft delete: %v", err)
	}
}

// ---- Apps, secrets, scopes, consent -------------------------------------------

func TestAppRegistrationDefaults(t *testing.T) {
	testutil.Reset(t)
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{Scopes: []string{"openid", "email", "bogus"}})
	if secret == "" {
		t.Fatal("confidential app needs a secret")
	}
	if len(app.Scopes) != 2 || app.Scopes[0] != "email" || app.Scopes[1] != "openid" {
		t.Errorf("scopes = %v (unknown scopes must be ignored)", app.Scopes)
	}
	if app.AccessTokenTTL != 900 || app.RefreshTokenTTL <= 0 || !app.RequirePKCE || !app.Enabled || app.IsFirstParty {
		t.Errorf("unexpected defaults: %+v", app)
	}
	if app.TokenEndpointAuthMethod != "client_secret_basic" || len(app.GrantTypes) != 2 {
		t.Errorf("auth method / grants: %+v", app)
	}
	custom, _ := testutil.CreateApp(t, "slow", testutil.AppOptions{TTLSeconds: 3600})
	if custom.AccessTokenTTL != 3600 {
		t.Errorf("custom ttl = %d", custom.AccessTokenTTL)
	}
	pub, pubSecret := testutil.CreateApp(t, "spa", testutil.AppOptions{Public: true})
	if pubSecret != "" || pub.ClientType != "public" || pub.TokenEndpointAuthMethod != "none" {
		t.Errorf("public app: %+v", pub)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM app_secret WHERE app_id = $1`, pub.ID); n != 0 {
		t.Error("public apps must have no secret")
	}
	if n := testutil.Count(t, `SELECT count(*) FROM app_secret WHERE secret_hash = $1`, secret); n != 0 {
		t.Error("plaintext secret stored")
	}
	dup := db.App{Name: "billing", PrettyName: "x", ClientType: "public",
		RedirectURIs: []string{"https://x.test/cb"}, PostLogoutRedirectURIs: []string{}}
	if _, err := db.AddApp(dup, nil, ""); !db.IsUniqueViolation(err) {
		t.Errorf("duplicate app name: %v", err)
	}

	byID, err := db.GetApp(app.ID)
	byClient, err2 := db.GetAppByClientID(app.ClientID)
	if err != nil || err2 != nil || byID.ClientID != byClient.ClientID || byClient.ID != app.ID {
		t.Fatalf("lookups disagree: %v %v", err, err2)
	}
	if _, err := db.GetApp("nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("malformed app id: %v", err)
	}
	if _, err := db.GetAppByClientID("00000000-0000-0000-0000-000000000000"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown client id: %v", err)
	}
	apps, err := db.GetApps()
	if err != nil || len(apps) < 4 { // guardian + three above
		t.Fatalf("GetApps = %d apps, %v", len(apps), err)
	}
}

func TestClientAuthenticationByHashedSecret(t *testing.T) {
	testutil.Reset(t)
	app, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	good := auth.HashToken(secret)

	if got, err := db.GetAppByClientIDAndSecret(app.ClientID, good); err != nil || got.ID != app.ID {
		t.Fatalf("correct secret rejected: %v", err)
	}
	for name, h := range map[string]string{"wrong": auth.HashToken("wrong"), "empty": "", "plaintext": secret} {
		if _, err := db.GetAppByClientIDAndSecret(app.ClientID, h); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("%s secret accepted: %v", name, err)
		}
	}
	if _, err := db.GetAppByClientIDAndSecret("not-a-uuid", good); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("malformed client id: %v", err)
	}

	// rotation with overlap: a second active secret works next to the first
	testutil.Exec(t, `INSERT INTO app_secret (app_id, secret_hash) VALUES ($1, $2)`, app.ID, auth.HashToken("second"))
	if _, err := db.GetAppByClientIDAndSecret(app.ClientID, auth.HashToken("second")); err != nil {
		t.Errorf("second secret rejected: %v", err)
	}
	testutil.Exec(t, `UPDATE app_secret SET revoked_at = now() WHERE secret_hash = $1`, good)
	if _, err := db.GetAppByClientIDAndSecret(app.ClientID, good); !errors.Is(err, sql.ErrNoRows) {
		t.Error("revoked secret accepted")
	}
	testutil.Exec(t, `UPDATE app_secret SET expires_at = now() - interval '1 minute' WHERE secret_hash = $1`, auth.HashToken("second"))
	if _, err := db.GetAppByClientIDAndSecret(app.ClientID, auth.HashToken("second")); !errors.Is(err, sql.ErrNoRows) {
		t.Error("expired secret accepted")
	}

	other, otherSecret := testutil.CreateApp(t, "other", testutil.AppOptions{})
	if _, err := db.GetAppByClientIDAndSecret(app.ClientID, auth.HashToken(otherSecret)); !errors.Is(err, sql.ErrNoRows) {
		t.Error("another app's secret accepted")
	}
	testutil.Exec(t, `UPDATE app SET enabled = FALSE WHERE id = $1`, other.ID)
	if _, err := db.GetAppByClientIDAndSecret(other.ClientID, auth.HashToken(otherSecret)); !errors.Is(err, sql.ErrNoRows) {
		t.Error("disabled app authenticated")
	}
	pub, _ := testutil.CreateApp(t, "spa", testutil.AppOptions{Public: true})
	if _, err := db.GetAppByClientIDAndSecret(pub.ClientID, good); !errors.Is(err, sql.ErrNoRows) {
		t.Error("public app authenticated with a secret")
	}
}

func TestConsentAndScopeClaims(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "pat")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})

	if got, err := db.GetConsent(acct.ID, app.ID); err != nil || len(got) != 0 {
		t.Fatalf("no consent expected: %v, %v", got, err)
	}
	if err := db.SaveConsent(acct.ID, app.ID, []string{"openid", "email"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetConsent(acct.ID, app.ID); len(got) != 2 {
		t.Errorf("consent = %v", got)
	}
	if err := db.SaveConsent(acct.ID, app.ID, []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetConsent(acct.ID, app.ID); len(got) != 1 {
		t.Errorf("a new decision replaces the old one, got %v", got)
	}
	testutil.Exec(t, `UPDATE account_consent SET revoked_at = now()`)
	if got, _ := db.GetConsent(acct.ID, app.ID); len(got) != 0 {
		t.Errorf("revoked consent still returned: %v", got)
	}

	claims, err := db.GetScopeClaims([]string{"openid", "email"})
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, c := range claims {
		set[c] = true
	}
	if !set["sub"] || !set["email"] || !set["email_verified"] || set["name"] || set["phone_number"] {
		t.Errorf("claims for openid+email = %v", claims)
	}
	if none, _ := db.GetScopeClaims([]string{"no-such-scope"}); len(none) != 0 {
		t.Errorf("unknown scope released claims: %v", none)
	}
	scopes, _ := db.GetScopes([]string{"email", "openid"})
	if len(scopes) != 2 || scopes[0].Description == "" {
		t.Errorf("scope descriptions for the consent screen: %+v", scopes)
	}
}

// ---- Schema script ----------------------------------------------------------

func TestSchemaSeedsAndStructure(t *testing.T) {
	testutil.Reset(t)
	checks := map[string]int{
		`SELECT count(*) FROM scope WHERE app_id IS NULL`:                                                   5,
		`SELECT count(*) FROM app WHERE name = 'guardian' AND is_first_party`:                                1,
		`SELECT count(*) FROM app_permission p JOIN app a ON a.id = p.app_id WHERE a.name = 'guardian'`:      4,
		`SELECT count(*) FROM app_scope s JOIN app a ON a.id = s.app_id WHERE a.name = 'guardian'`:           5,
		`SELECT count(*) FROM role WHERE name = 'admin' AND all_permissions AND is_system`:                   1,
		`SELECT count(*) FROM account WHERE username = 'admin'`:                                              1,
		`SELECT count(*) FROM pg_views WHERE viewname = 'account_effective_permission'`:                      1,
		`SELECT count(*) FROM pg_class WHERE relname = 'rate_limit' AND relpersistence = 'u'`:                1,
	}
	for q, want := range checks {
		if got := testutil.Count(t, q); got != want {
			t.Errorf("%s = %d, want %d", q, got, want)
		}
	}
	admin, _, _ := db.GetAccountByUsername("admin")
	if ok, _ := db.AccountHasRole(admin.ID, "admin"); !ok {
		t.Error("seeded admin does not hold the admin role")
	}
	if ok, _ := db.AccountHasPermission(admin.ID, "guardian", "permissions.manage"); !ok {
		t.Error("seeded admin cannot manage permissions")
	}
}

func TestSchemaScriptIsIdempotentAndNeverOverwrites(t *testing.T) {
	testutil.Reset(t)
	count := func(q string) int { return testutil.Count(t, q) }
	tables := []string{"role", "app", "account", "scope", "app_permission", "app_scope", "account_role"}
	before := map[string]int{}
	for _, tbl := range tables {
		before[tbl] = count(`SELECT count(*) FROM ` + tbl)
	}
	testutil.RunSchema(t)
	testutil.RunSchema(t)
	for _, tbl := range tables {
		if got := count(`SELECT count(*) FROM ` + tbl); got != before[tbl] {
			t.Errorf("%s: %d rows -> %d after re-running the script", tbl, before[tbl], got)
		}
	}

	// admin edits and deletions survive a restart: seeds only run into EMPTY tables
	testutil.Exec(t, `UPDATE account SET display_name = 'Changed' WHERE username = 'admin'`)
	testutil.Exec(t, `DELETE FROM account_role`)
	testutil.Exec(t, `UPDATE app SET pretty_name = 'Renamed' WHERE name = 'guardian'`)
	testutil.RunSchema(t)
	if n := count(`SELECT count(*) FROM account WHERE display_name = 'Changed'`); n != 1 {
		t.Error("account edit was overwritten by the seed")
	}
	if n := count(`SELECT count(*) FROM account_role`); n != 0 {
		t.Error("a deleted grant was re-created by the seed")
	}
	if n := count(`SELECT count(*) FROM app WHERE pretty_name = 'Renamed'`); n != 1 {
		t.Error("app edit was overwritten by the seed")
	}
}

// Several replicas starting at once must not race (advisory lock) or double-seed.
func TestSchemaScriptSurvivesConcurrentStartups(t *testing.T) {
	testutil.Reset(t)
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- testutil.RunSchemaErr()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent schema run failed: %v", err)
		}
	}
	if n := testutil.Count(t, `SELECT count(*) FROM role WHERE name = 'admin'`); n != 1 {
		t.Errorf("admin role count = %d", n)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM account WHERE username = 'admin'`); n != 1 {
		t.Errorf("admin account count = %d", n)
	}
}

// ---- Signing keys -----------------------------------------------------------

func TestEnsureSigningKeyCreatesExactlyOneUnderConcurrency(t *testing.T) {
	testutil.Reset(t)
	testutil.DeleteSigningKeys()
	t.Cleanup(testutil.DeleteSigningKeys)

	var calls int32
	generate := func() (db.SigningKey, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(25 * time.Millisecond)
		return db.SigningKey{KID: "k1", Alg: "RS256", PublicJWK: []byte(`{"kty":"RSA","kid":"k1"}`), PrivateKeyEncrypted: "x", Status: "active"}, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := db.EnsureSigningKey(generate); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Fatalf("generate ran %d times, want 1", calls)
	}
	if err := db.EnsureSigningKey(generate); err != nil || calls != 1 {
		t.Fatalf("an existing active key must not be replaced (calls=%d, %v)", calls, err)
	}
	active, err := db.GetActiveSigningKey()
	if err != nil || active.KID != "k1" {
		t.Fatalf("active key = %+v, %v", active, err)
	}

	testutil.Exec(t, `INSERT INTO signing_key (kid, alg, public_jwk, private_key_encrypted, status) VALUES
		('k2', 'RS256', '{"kid":"k2"}', 'x', 'retiring'), ('k3', 'RS256', '{"kid":"k3"}', 'x', 'retired')`)
	published, err := db.GetPublishedSigningKeys()
	if err != nil {
		t.Fatal(err)
	}
	var kids []string
	for _, k := range published {
		kids = append(kids, k.KID)
	}
	sort.Strings(kids)
	if len(kids) != 2 || kids[0] != "k1" || kids[1] != "k2" {
		t.Fatalf("published keys = %v, want active + retiring only", kids)
	}
}

// ---- Maintenance ------------------------------------------------------------

func TestMaintenanceRemovesOnlyOldExpiredRows(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "quinn")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})

	oldToken := testutil.Token(t, app, acct.ID, "", -48*time.Hour)
	recentlyExpired := testutil.Token(t, app, acct.ID, "", -time.Hour)
	liveToken := testutil.Token(t, app, acct.ID, "", time.Hour)
	ancient, _ := db.CreateSession(acct.ID, auth.HashToken("ancient"), "", "ua", -31*24*time.Hour)
	recentSession, _ := db.CreateSession(acct.ID, auth.HashToken("recent"), "", "ua", -24*time.Hour)
	db.SaveAuthCode(auth.HashToken("old-code"), db.AuthCode{AppID: app.ID, AccountID: acct.ID, RedirectURI: "https://billing.test/callback",
		Scopes: []string{"openid"}, AuthTime: time.Now()}, -48*time.Hour)
	testutil.Exec(t, `INSERT INTO rate_limit (key, window_start, hits) VALUES ('old', now() - interval '2 days', 3), ('fresh', now(), 1)`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db.StartMaintenance(ctx) // runs a cleanup pass immediately

	deadline := time.Now().Add(10 * time.Second)
	// the rate_limit delete is the LAST statement of a cleanup pass, so once it has happened all earlier ones have too
	for testutil.Count(t, `SELECT count(*) FROM rate_limit WHERE key = 'old'`) != 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	exists := func(q string, args ...any) bool { return testutil.Count(t, q, args...) == 1 }
	if exists(`SELECT count(*) FROM access_token WHERE token_hash = $1`, auth.HashToken(oldToken)) {
		t.Error("an access token expired 2 days ago was kept")
	}
	if !exists(`SELECT count(*) FROM access_token WHERE token_hash = $1`, auth.HashToken(recentlyExpired)) ||
		!exists(`SELECT count(*) FROM access_token WHERE token_hash = $1`, auth.HashToken(liveToken)) {
		t.Error("recent or live tokens were removed")
	}
	if exists(`SELECT count(*) FROM session WHERE id = $1`, ancient.ID) {
		t.Error("a session expired 31 days ago was kept")
	}
	if !exists(`SELECT count(*) FROM session WHERE id = $1`, recentSession.ID) {
		t.Error("a recently expired session was removed")
	}
	if exists(`SELECT count(*) FROM authorization_code WHERE code_hash = $1`, auth.HashToken("old-code")) {
		t.Error("an old authorization code was kept")
	}
	if exists(`SELECT count(*) FROM rate_limit WHERE key = 'old'`) || !exists(`SELECT count(*) FROM rate_limit WHERE key = 'fresh'`) {
		t.Error("rate limit rows were not cleaned correctly")
	}
}
