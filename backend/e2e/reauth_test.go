package e2e

import (
	"net/http"
	"testing"
	"time"

	"guardian/internal/testutil"
)

// Protected changes need a recent sign-in, or the password again (docs/ROADMAP.md, "Re-authentication").

// ageSessions makes the account's sessions look signed in long ago.
func ageSessions(t *testing.T, accountID string) {
	t.Helper()
	testutil.Exec(t, `UPDATE session SET auth_time = now() - interval '10 minutes' WHERE account_id = $1`, accountID)
}

func TestE2EProtectedChangesNeedARecentSignIn(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "mipha")
	setEmail(t, "mipha", "mipha@zora.example")
	br := newBrowser(t)
	br.mustLogin("mipha")
	ageSessions(t, acct.ID)

	protected := []struct {
		method, path string
		body         map[string]any
	}{
		{"PATCH", "/api/v1/me", map[string]any{"username": "mipha2"}},
		{"PUT", "/api/v1/me/password", map[string]any{"new_password": "brand-new-password"}},
		{"PUT", "/api/v1/me/email", map[string]any{"email": "mipha@domain.example"}},
	}
	for _, c := range protected {
		if m := br.call(c.method, c.path, c.body, http.StatusForbidden); m["error"] != "reauth_required" {
			t.Errorf("%s %s without a recent sign-in: %v", c.method, c.path, m)
		}
	}
	// The rest of the profile is not protected.
	br.call("PATCH", "/api/v1/me", map[string]any{"display_name": "Mipha"}, 200)

	if m := br.call("POST", "/api/v1/me/reauth", map[string]any{"password": "wrong-password-1"}, 403); m["error"] != "wrong_password" {
		t.Errorf("wrong password: %v", m)
	}
	m := br.call("POST", "/api/v1/me/reauth", map[string]any{"password": testutil.DefaultPassword}, 200)
	until, err := time.Parse(time.RFC3339, str(m["reauthenticated_until"]))
	if err != nil || time.Until(until) < 4*time.Minute || time.Until(until) > 6*time.Minute {
		t.Errorf("reauthenticated_until = %v (%v)", m["reauthenticated_until"], err)
	}
	for _, c := range protected {
		want := 200
		switch c.path {
		case "/api/v1/me/password":
			want = 204
		case "/api/v1/me/email":
			want = 202
		}
		br.call(c.method, c.path, c.body, want)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE actor_account_id = $1 AND event_type IN ('reauth.success', 'reauth.failure')`, acct.ID); n != 2 {
		t.Errorf("%d re-authentications audited, want 2", n)
	}

	// The window is per session: another session of the same account still has to confirm.
	other := newBrowser(t)
	other.mustLoginWith("mipha2", "brand-new-password")
	ageSessions(t, acct.ID)
	other.call("PATCH", "/api/v1/me", map[string]any{"username": "mipha3"}, http.StatusForbidden)

	resp := newBrowser(t).sendJSON("POST", "/api/v1/me/reauth", map[string]any{"password": "x"})
	wantStatus(t, resp, http.StatusUnauthorized)
	drain(resp)
}

func TestE2EReauthIsLimited(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "revali")
	br := newBrowser(t)
	br.mustLogin("revali")
	ageSessions(t, acct.ID)
	for i := 0; i < 5; i++ {
		br.call("POST", "/api/v1/me/reauth", map[string]any{"password": "guess-number-1"}, 403)
	}
	// Even the right password waits now.
	resp := br.sendJSON("POST", "/api/v1/me/reauth", map[string]any{"password": testutil.DefaultPassword})
	wantStatus(t, resp, http.StatusTooManyRequests)
	if resp.Header.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	drain(resp)
	br.call("PATCH", "/api/v1/me", map[string]any{"username": "revali2"}, http.StatusForbidden)
}
