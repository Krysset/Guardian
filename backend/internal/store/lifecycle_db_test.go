package store_test

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"guardian/internal/auth"
	db "guardian/internal/store"
	"guardian/internal/testutil"
)

// ---- Sessions ---------------------------------------------------------------

const idle = time.Hour // idle timeout used by these tests

func TestSessionLookupAndExpiry(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "gina")
	sess, cookie := testutil.Session(t, acct.ID)

	got, err := db.GetSessionByHash(auth.HashToken(cookie), idle)
	if err != nil || got.ID != sess.ID || got.AccountID != acct.ID {
		t.Fatalf("lookup failed: %+v, %v", got, err)
	}
	if strings.Join(got.AMR, " ") != "pwd otp" {
		t.Errorf("amr = %v, want the test session's [pwd otp]", got.AMR)
	}
	if s, err := db.CreateSession(acct.ID, auth.HashToken("plain"), "", "", time.Hour); err != nil || strings.Join(s.AMR, " ") != "pwd" {
		t.Errorf("a session without amr: %v %v, want [pwd]", s.AMR, err)
	}
	if byID, err := db.GetLiveSession(sess.ID, idle); err != nil || byID.ID != sess.ID {
		t.Errorf("GetLiveSession: %+v, %v", byID, err)
	}
	if _, err := db.GetSessionByHash(auth.HashToken("some-other-cookie"), idle); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown cookie: %v", err)
	}
	for _, id := range []string{"not-a-uuid", "00000000-0000-0000-0000-000000000000", ""} {
		if _, err := db.GetLiveSession(id, idle); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("GetLiveSession(%q): %v, want sql.ErrNoRows", id, err)
		}
	}

	// the raw cookie value is never stored, only its hash
	if n := testutil.Count(t, `SELECT count(*) FROM session WHERE session_hash = $1`, cookie); n != 0 {
		t.Error("plaintext session cookie found in the database")
	}
	if n := testutil.Count(t, `SELECT count(*) FROM session WHERE session_hash = $1`, auth.HashToken(cookie)); n != 1 {
		t.Error("hashed session cookie not stored")
	}

	// past its absolute end
	expired, err := db.CreateSession(acct.ID, auth.HashToken("expired"), "203.0.113.5", "ua", -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetSessionByHash(auth.HashToken("expired"), idle); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expired session accepted: %v", err)
	}
	if _, err := db.GetLiveSession(expired.ID, idle); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expired session accepted by id: %v", err)
	}

	testutil.Exec(t, `UPDATE account SET status = 'disabled' WHERE id = $1`, acct.ID)
	if _, err := db.GetSessionByHash(auth.HashToken(cookie), idle); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("session of a disabled account accepted: %v", err)
	}
	if _, err := db.GetLiveSession(sess.ID, idle); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("session of a disabled account accepted by id: %v", err)
	}
}

func TestIdleSessionsEndAndUseKeepsThemAlive(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "ivy")
	sess, cookie := testutil.Session(t, acct.ID)

	// unused for longer than the idle timeout: over, however far away the absolute end is
	testutil.Exec(t, `UPDATE session SET last_seen_at = now() - interval '61 minutes' WHERE id = $1`, sess.ID)
	if _, err := db.GetSessionByHash(auth.HashToken(cookie), idle); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("an idle session was accepted: %v", err)
	}
	if _, err := db.GetLiveSession(sess.ID, idle); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("an idle session was accepted by id: %v", err)
	}
	// with a longer idle timeout the same session is fine, and using it resets the clock
	if _, err := db.GetLiveSession(sess.ID, 2*time.Hour); err != nil {
		t.Fatalf("within a longer idle timeout: %v", err)
	}
	if _, err := db.GetLiveSession(sess.ID, idle); err != nil {
		t.Errorf("using the session must keep it from going idle: %v", err)
	}
}

func TestSessionLastSeenIsWrittenSparingly(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "hank")
	sess, cookie := testutil.Session(t, acct.ID)
	hash := auth.HashToken(cookie)

	testutil.Exec(t, `UPDATE session SET last_seen_at = now() - interval '2 minutes' WHERE id = $1`, sess.ID)
	if _, err := db.GetSessionByHash(hash, idle); err != nil {
		t.Fatal(err)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM session WHERE id = $1 AND last_seen_at < now() - interval '90 seconds'`, sess.ID); n != 1 {
		t.Error("last_seen_at was rewritten on a read that happened within the touch interval")
	}

	testutil.Exec(t, `UPDATE session SET last_seen_at = now() - interval '10 minutes' WHERE id = $1`, sess.ID)
	if _, err := db.GetLiveSession(sess.ID, idle); err != nil {
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

	refresh := auth.HashToken("refresh-1")
	if err := db.SaveRefreshToken(refresh, withHook.ID, acct.ID, sess.ID, []string{"openid"}); err != nil {
		t.Fatal(err)
	}

	targets, err := db.RevokeSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].ClientID != withHook.ClientID || targets[0].URI != "http://127.0.0.1:9/bcl" {
		t.Fatalf("only apps with a back-channel URI must be notified, got %+v", targets)
	}
	if _, err := db.GetSessionByHash(auth.HashToken(cookie), idle); !errors.Is(err, sql.ErrNoRows) {
		t.Error("revoked session still resolves")
	}
	if _, err := db.GetLiveSession(sess.ID, idle); !errors.Is(err, sql.ErrNoRows) {
		t.Error("revoked session still live")
	}
	if _, err := db.GetRefreshToken(refresh, withHook.ID); !errors.Is(err, db.ErrInvalidGrant) {
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

func TestRefreshTokensAreStableAndBoundToTheirApp(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "liam")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	other, _ := testutil.CreateApp(t, "other", testutil.AppOptions{})
	sess, _ := testutil.Session(t, acct.ID)
	h := auth.HashToken("r1")

	if err := db.SaveRefreshToken(h, app.ID, acct.ID, sess.ID, []string{"openid", "groups"}); err != nil {
		t.Fatal(err)
	}
	// using it does not use it up: it is the same token every time
	for i := 0; i < 3; i++ {
		rt, err := db.GetRefreshToken(h, app.ID)
		if err != nil || rt.AccountID != acct.ID || rt.SessionID != sess.ID || len(rt.Scopes) != 2 {
			t.Fatalf("use %d: %+v, %v", i+1, rt, err)
		}
	}
	// another app cannot use it
	if _, err := db.GetRefreshToken(h, other.ID); !errors.Is(err, db.ErrInvalidGrant) {
		t.Errorf("used by the wrong app: %v", err)
	}
	if _, err := db.GetRefreshToken(auth.HashToken("unknown"), app.ID); !errors.Is(err, db.ErrInvalidGrant) {
		t.Errorf("unknown token: %v", err)
	}
	// only the hash is stored
	if n := testutil.Count(t, `SELECT count(*) FROM refresh_token WHERE token_hash = $1`, "r1"); n != 0 {
		t.Error("plaintext refresh token stored")
	}
}

func TestRevokingARefreshToken(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "mia")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	other, _ := testutil.CreateApp(t, "other", testutil.AppOptions{})
	sess, _ := testutil.Session(t, acct.ID)
	h := auth.HashToken("r1")
	if err := db.SaveRefreshToken(h, app.ID, acct.ID, sess.ID, []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	// another app cannot revoke it
	if ok, err := db.RevokeRefreshToken(h, other.ID); err != nil || ok {
		t.Errorf("revoked by another app: %v, %v", ok, err)
	}
	if ok, err := db.RevokeRefreshToken(h, app.ID); err != nil || !ok {
		t.Fatalf("revoke: %v, %v", ok, err)
	}
	if _, err := db.GetRefreshToken(h, app.ID); !errors.Is(err, db.ErrInvalidGrant) {
		t.Errorf("a revoked token still works: %v", err)
	}
	// revoking twice reports that nothing changed
	if ok, err := db.RevokeRefreshToken(h, app.ID); err != nil || ok {
		t.Errorf("second revoke: %v, %v", ok, err)
	}
	// the session itself is untouched: revoking one app's token does not sign the user out elsewhere
	if _, err := db.GetLiveSession(sess.ID, idle); err != nil {
		t.Errorf("the session ended with the token: %v", err)
	}
}

func TestConcurrentUseOfOneRefreshTokenAllSucceeds(t *testing.T) {
	testutil.Reset(t)
	acct := testutil.CreateAccount(t, "noah")
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	sess, _ := testutil.Session(t, acct.ID)
	h := auth.HashToken("shared")
	if err := db.SaveRefreshToken(h, app.ID, acct.ID, sess.ID, []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	// several replicas of an app, or a retry after a lost answer, use the token at the same time
	var ok int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.GetRefreshToken(h, app.ID); err == nil {
				atomic.AddInt32(&ok, 1)
			}
		}()
	}
	wg.Wait()
	if ok != 8 {
		t.Fatalf("%d of 8 concurrent uses succeeded, want all", ok)
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
	hooked, _ := testutil.CreateApp(t, "hooked", testutil.AppOptions{BackchannelURI: "http://127.0.0.1:9/bcl"})
	plain, _ := testutil.CreateApp(t, "plain", testutil.AppOptions{})
	sess, cookie := testutil.Session(t, acct.ID)
	db.TrackSessionApp(sess.ID, hooked.ID)
	db.TrackSessionApp(sess.ID, plain.ID)
	if err := db.SaveRefreshToken(auth.HashToken("rt"), hooked.ID, acct.ID, sess.ID, []string{"openid"}); err != nil {
		t.Fatal(err)
	}

	notices, err := db.SoftDeleteAccount(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(notices) != 1 || notices[0].ClientID != hooked.ClientID || notices[0].SessionID != sess.ID || notices[0].AccountID != acct.ID {
		t.Errorf("only the app with a back-channel URI must be told, got %+v", notices)
	}
	if _, err := db.GetAccount(acct.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Error("deleted account still readable")
	}
	if _, _, err := db.GetAccountByUsername("olga"); !errors.Is(err, sql.ErrNoRows) {
		t.Error("deleted account still found by username (login must fail)")
	}
	if _, err := db.GetSessionByHash(auth.HashToken(cookie), idle); !errors.Is(err, sql.ErrNoRows) {
		t.Error("session survived account deletion")
	}
	if _, err := db.GetRefreshToken(auth.HashToken("rt"), hooked.ID); !errors.Is(err, db.ErrInvalidGrant) {
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
	if app.AccessTokenTTL != 300 || !app.RequirePKCE || !app.Enabled || app.IsFirstParty {
		t.Errorf("unexpected defaults: %+v", app)
	}
	if app.TokenEndpointAuthMethod != "client_secret_basic" || len(app.GrantTypes) != 2 || app.RefreshMode != "stable" {
		t.Errorf("auth method / grants / refresh mode: %+v", app)
	}
	custom, _ := testutil.CreateApp(t, "slow", testutil.AppOptions{TTLSeconds: 3600})
	if custom.AccessTokenTTL != 3600 {
		t.Errorf("custom ttl = %d", custom.AccessTokenTTL)
	}
	pub, pubSecret := testutil.CreateApp(t, "spa", testutil.AppOptions{Public: true})
	if pubSecret != "" || pub.ClientType != "public" || pub.TokenEndpointAuthMethod != "none" {
		t.Errorf("public app: %+v", pub)
	}
	// an app without a secret gets no refresh tokens (for now)
	if pub.RefreshMode != "none" || len(pub.GrantTypes) != 1 || pub.GrantTypes[0] != "authorization_code" {
		t.Errorf("public app refresh: mode %q, grants %v", pub.RefreshMode, pub.GrantTypes)
	}
	// the token lifetime cannot go below 15 seconds, whatever writes the row
	if _, err := db.GetDatabaseConnection().Exec(`UPDATE app SET access_token_ttl_seconds = 14 WHERE id = $1`, app.ID); err == nil {
		t.Error("the database accepted a token lifetime below 15 seconds")
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
	if err != nil || len(apps) != 3 { // the three created above; Guardian seeds no app of its own
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
		`SELECT count(*) FROM scope WHERE app_id IS NULL`:                                     5,
		`SELECT count(*) FROM app`:                                                            0,
		`SELECT count(*) FROM user_group`:                                                     1,
		`SELECT count(*) FROM user_group WHERE key = 'guardian-admins' AND is_system`:         1,
		`SELECT count(*) FROM account WHERE username = 'admin'`:                               1,
		`SELECT count(*) FROM group_member`:                                                   1,
		`SELECT count(*) FROM pg_class WHERE relname = 'rate_limit' AND relpersistence = 'u'`: 1,
		// the permission model that groups replaced is gone
		`SELECT count(*) FROM pg_class WHERE relname IN ('role', 'app_permission', 'role_permission',
		   'account_role', 'account_app_permission', 'account_effective_permission')`: 0,
	}
	for q, want := range checks {
		if got := testutil.Count(t, q); got != want {
			t.Errorf("%s = %d, want %d", q, got, want)
		}
	}
	admin, _, _ := db.GetAccountByUsername("admin")
	if ok, _ := db.IsAdmin(admin.ID); !ok {
		t.Error("the seeded admin is not a member of the administrators group")
	}
}

func TestSchemaScriptIsIdempotentAndNeverOverwrites(t *testing.T) {
	testutil.Reset(t)
	count := func(q string) int { return testutil.Count(t, q) }
	testutil.CreateApp(t, "billing", testutil.AppOptions{})
	tables := []string{"user_group", "group_member", "app", "account", "scope", "app_scope"}
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
	testutil.Exec(t, `DELETE FROM group_member`)
	testutil.Exec(t, `UPDATE user_group SET description = 'Edited' WHERE key = 'guardian-admins'`)
	testutil.RunSchema(t)
	if n := count(`SELECT count(*) FROM account WHERE display_name = 'Changed'`); n != 1 {
		t.Error("account edit was overwritten by the seed")
	}
	if n := count(`SELECT count(*) FROM group_member`); n != 0 {
		t.Error("a deleted membership was re-created by the seed")
	}
	if n := count(`SELECT count(*) FROM user_group WHERE description = 'Edited'`); n != 1 {
		t.Error("group edit was overwritten by the seed")
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
	if n := testutil.Count(t, `SELECT count(*) FROM user_group WHERE key = 'guardian-admins'`); n != 1 {
		t.Errorf("administrators group count = %d", n)
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

	ancient, _ := db.CreateSession(acct.ID, auth.HashToken("ancient"), "", "ua", -31*24*time.Hour)
	recentSession, _ := db.CreateSession(acct.ID, auth.HashToken("recent"), "", "ua", -24*time.Hour)
	live, _ := db.CreateSession(acct.ID, auth.HashToken("live"), "", "ua", time.Hour)
	db.SaveRefreshToken(auth.HashToken("rt-ancient"), app.ID, acct.ID, ancient.ID, []string{"openid"})
	db.SaveRefreshToken(auth.HashToken("rt-revoked-long-ago"), app.ID, acct.ID, live.ID, []string{"openid"})
	db.SaveRefreshToken(auth.HashToken("rt-live"), app.ID, acct.ID, live.ID, []string{"openid"})
	testutil.Exec(t, `UPDATE refresh_token SET revoked_at = now() - interval '8 days' WHERE token_hash = $1`, auth.HashToken("rt-revoked-long-ago"))
	db.SaveAuthCode(auth.HashToken("old-code"), db.AuthCode{AppID: app.ID, AccountID: acct.ID, RedirectURI: "https://billing.test/callback",
		Scopes: []string{"openid"}, AuthTime: time.Now()}, -48*time.Hour)
	testutil.Exec(t, `INSERT INTO rate_limit (key, window_start, hits) VALUES ('old', now() - interval '2 days', 3), ('fresh', now(), 1)`)
	// Sign-ups that never confirmed their address go after 48 hours; a recent one stays.
	if _, err := db.CreatePendingAccount("abandoned", "h"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreatePendingAccount("waiting", "h"); err != nil {
		t.Fatal(err)
	}
	testutil.Exec(t, `UPDATE account SET created_at = now() - interval '49 hours' WHERE username = 'abandoned'`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db.StartMaintenance(ctx) // runs a cleanup pass immediately

	deadline := time.Now().Add(10 * time.Second)
	// removing abandoned sign-ups is the LAST statement of a cleanup pass, so once it has happened all earlier ones have too
	for testutil.Count(t, `SELECT count(*) FROM account WHERE username = 'abandoned'`) != 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	exists := func(q string, args ...any) bool { return testutil.Count(t, q, args...) == 1 }
	rt := func(name string) bool {
		return exists(`SELECT count(*) FROM refresh_token WHERE token_hash = $1`, auth.HashToken(name))
	}
	if exists(`SELECT count(*) FROM session WHERE id = $1`, ancient.ID) || rt("rt-ancient") {
		t.Error("a session expired 31 days ago, or its refresh token, was kept")
	}
	if !exists(`SELECT count(*) FROM session WHERE id = $1`, recentSession.ID) {
		t.Error("a recently expired session was removed")
	}
	if rt("rt-revoked-long-ago") || !rt("rt-live") {
		t.Error("refresh tokens were not cleaned correctly")
	}
	if !exists(`SELECT count(*) FROM account WHERE username = 'waiting'`) || exists(`SELECT count(*) FROM account WHERE username = 'abandoned'`) {
		t.Error("abandoned sign-ups were not removed correctly")
	}
	if exists(`SELECT count(*) FROM authorization_code WHERE code_hash = $1`, auth.HashToken("old-code")) {
		t.Error("an old authorization code was kept")
	}
	if exists(`SELECT count(*) FROM rate_limit WHERE key = 'old'`) || !exists(`SELECT count(*) FROM rate_limit WHERE key = 'fresh'`) {
		t.Error("rate limit rows were not cleaned correctly")
	}
}

// ---- Migrations -------------------------------------------------------------

const migrationOneRecords = `SELECT count(*) FROM goose_db_version WHERE version_id = 1 AND is_applied`

func TestMigrationsAreRecordedAndRunOnce(t *testing.T) {
	testutil.RequireTestDB(t)
	// Opening the database already migrated it.
	if n := testutil.Count(t, migrationOneRecords); n != 1 {
		t.Fatalf("migration 1 is recorded %d times after startup, want 1", n)
	}
	// A second run finds nothing to do.
	if err := db.Migrate(context.Background(), db.GetDatabaseConnection()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if n := testutil.Count(t, migrationOneRecords); n != 1 {
		t.Errorf("migration 1 is recorded %d times after a second run, want 1", n)
	}
}

func TestMigrateSurvivesConcurrentStartups(t *testing.T) {
	testutil.Reset(t)
	// Forget that migration 1 ran, so every "replica" below wants to apply it. The migration is
	// idempotent, so applying it to the existing schema is safe.
	testutil.Exec(t, `DELETE FROM goose_db_version WHERE version_id = 1`)

	const replicas = 6
	errs := make(chan error, replicas)
	for i := 0; i < replicas; i++ {
		go func() { errs <- db.Migrate(context.Background(), db.GetDatabaseConnection()) }()
	}
	for i := 0; i < replicas; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Migrate: %v", err)
		}
	}
	if n := testutil.Count(t, migrationOneRecords); n != 1 {
		t.Errorf("migration 1 was applied %d times by %d replicas starting together, want 1", n, replicas)
	}
}

func TestADatabaseFromAnotherSchemaRevisionIsRefused(t *testing.T) {
	testutil.RequireTestDB(t)
	ctx := context.Background()
	conn := db.GetDatabaseConnection()
	if err := db.VerifySchemaRevision(ctx, conn); err != nil {
		t.Fatalf("a database created by this version must be accepted: %v", err)
	}
	original := ""
	if err := conn.QueryRow(`SELECT fingerprint FROM schema_revision`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		testutil.Exec(t, `DELETE FROM schema_revision`)
		testutil.Exec(t, `INSERT INTO schema_revision (fingerprint) VALUES ($1)`, original)
	}
	t.Cleanup(restore)

	// created by another revision of the first migration
	testutil.Exec(t, `UPDATE schema_revision SET fingerprint = 'an-older-revision'`)
	err := db.VerifySchemaRevision(ctx, conn)
	if !errors.Is(err, db.ErrSchemaRevision) {
		t.Fatalf("another revision: %v, want ErrSchemaRevision", err)
	}
	for _, want := range []string{"an-older-revision", "recreate", "docker compose down -v"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must say what to do, missing %q in: %v", want, err)
		}
	}

	// created before revisions were recorded: running the script again must not mark it as current
	testutil.Exec(t, `DELETE FROM schema_revision`)
	testutil.RunSchema(t)
	if err := db.VerifySchemaRevision(ctx, conn); !errors.Is(err, db.ErrSchemaRevision) {
		t.Errorf("a database without a recorded revision: %v, want ErrSchemaRevision", err)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM schema_revision`); n != 0 {
		t.Error("re-running the script on an existing database recorded a revision")
	}
}

func TestLastBackupTimeComesFromTheAuditLog(t *testing.T) {
	testutil.Reset(t)
	if got, err := db.LastBackupTime(); err != nil || !got.IsZero() {
		t.Fatalf("no backup yet: %v, %v", got, err)
	}
	testutil.Exec(t, `INSERT INTO audit_log (event_type, occurred_at) VALUES
		('backup.created', now() - interval '2 days'), ('backup.created', now() - interval '1 hour'), ('backup.restored', now())`)
	got, err := db.LastBackupTime()
	if err != nil || time.Since(got) < 59*time.Minute || time.Since(got) > 61*time.Minute {
		t.Errorf("last backup = %v (%v), want an hour ago", got, err)
	}
}
