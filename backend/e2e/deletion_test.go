package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"

	db "guardian/internal/store"
	"guardian/internal/testutil"
)

// Deleting accounts (0.3 part 4): self-service and by an administrator, the grace period, restoring,
// erasing now, and "download my data".

// Covers: U15, A8
func TestE2EDeletingYourOwnAccountAndRestoringIt(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "zelda")
	acct := testutil.CreateAccount(t, "mineru")
	keep := testutil.Group(t, "sages", "")
	gone := testutil.Group(t, "temporary", "")
	testutil.AddMember(t, keep, acct.ID)
	testutil.AddMember(t, gone, acct.ID)
	br := newBrowser(t)
	br.mustLogin("mineru")

	if m := br.call("DELETE", "/api/v1/me", map[string]any{"username": "someone-else"}, 400); !strings.Contains(str(m["message"]), "username") {
		t.Errorf("a wrong confirmation: %v", m)
	}
	ageSessions(t, acct.ID)
	br.call("DELETE", "/api/v1/me", map[string]any{"username": "mineru"}, http.StatusForbidden)
	br.call("POST", "/api/v1/me/reauth", map[string]any{"password": testutil.DefaultPassword}, 200)
	m := br.call("DELETE", "/api/v1/me", map[string]any{"username": "Mineru"}, 200)
	until, _ := time.Parse(time.RFC3339, str(m["erase_after"]))
	if d := time.Until(until); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Errorf("erase_after = %v, want about 30 days ahead", m["erase_after"])
	}
	resp := br.get("/api/v1/me")
	wantStatus(t, resp, http.StatusUnauthorized)
	drain(resp)
	resp = newBrowser(t).login("mineru", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusUnauthorized)
	drain(resp)

	admin := newBrowser(t)
	admin.mustLogin("zelda")
	list := admin.call("GET", "/api/v1/accounts/deleted", nil, 200)["items"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["username"] != "mineru" || list[0].(map[string]any)["deleted_by_itself"] != true {
		t.Fatalf("deleted accounts = %v", list)
	}
	admin.call("GET", "/api/v1/accounts/"+acct.ID, nil, 404)

	// While it waits, a group goes away; restoring gives back the memberships that still can be.
	admin.call("DELETE", "/api/v1/groups/"+gone, nil, 204)
	restored := admin.call("POST", "/api/v1/accounts/"+acct.ID+"/restore", nil, 200)
	if restored["status"] != "active" {
		t.Errorf("restored account = %v", restored)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM group_member WHERE account_id = $1`, acct.ID); n != 1 {
		t.Errorf("%d memberships after the restore, want the one in a group that still exists", n)
	}
	newBrowser(t).mustLogin("mineru")
	admin.call("POST", "/api/v1/accounts/"+acct.ID+"/restore", nil, 404)
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type IN ('account.deleted', 'account.restored') AND metadata->>'target' = $1`, acct.ID); n != 2 {
		t.Errorf("%d deletion and restore entries in the audit log, want 2", n)
	}
}

// Covers: A7
func TestE2EErasingAnAccountNow(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "zelda")
	acct := testutil.CreateAccount(t, "yunobo")
	setEmail(t, "yunobo", "yunobo@goron.example")
	// Audit entries that name the account: a failed sign-in records the typed username and the IP address.
	drain(newBrowser(t).login("yunobo", "wrong-password-1", ""))
	newBrowser(t).mustLogin("yunobo")

	admin := newBrowser(t)
	admin.mustLogin("zelda")
	path := "/api/v1/accounts/" + acct.ID + "/erase"
	admin.call("POST", path, map[string]any{"username": "zelda"}, 400)
	admin.call("POST", path, map[string]any{"username": "yunobo"}, 204)

	if n := testutil.Count(t, `SELECT count(*) FROM account WHERE id = $1`, acct.ID); n != 0 {
		t.Fatal("the account still exists")
	}
	if n := testutil.Count(t, `SELECT count(*) FROM deletion_log WHERE account_id = $1`, acct.ID); n != 1 {
		t.Error("the erased account is not in the deletion log")
	}
	// (The erasure's own entry keeps the administrator's address: it is about the administrator.)
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE (actor_account_id = $1 OR metadata->>'target' = $1::text)
		AND event_type <> 'account.erased' AND (ip_address IS NOT NULL OR metadata ? 'username' OR metadata ? 'email')`, acct.ID); n != 0 {
		t.Errorf("%d audit entries still hold an IP address or personal details", n)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'login.failure' AND actor_account_id = $1`, acct.ID); n != 1 {
		t.Error("the audit entries themselves must stay")
	}
	admin.call("POST", "/api/v1/accounts/"+acct.ID+"/restore", nil, 404)
	// The username and address are free again.
	newBrowser(t).postJSON("/api/v1/signup", map[string]any{"username": "yunobo", "password": "long-enough-pw-1"})
	if n := testutil.Count(t, `SELECT count(*) FROM account WHERE username = 'yunobo'`); n != 1 {
		t.Error("the username of an erased account cannot be used again")
	}
}

// Covers: U14
func TestE2EDownloadMyData(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "teba")
	testutil.AddMember(t, testutil.Group(t, "rito", ""), acct.ID)
	br := newBrowser(t)
	br.mustLogin("teba")
	resp := br.get("/api/v1/me/export")
	wantStatus(t, resp, http.StatusOK)
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="guardian-data-`) {
		t.Errorf("Content-Disposition = %q", cd)
	}
	body := readBody(t, resp)
	for _, want := range []string{`"username":"teba"`, `"key":"rito"`, `"sessions":[{`, `"event_type":"login.success"`, `"two_factor":`} {
		if !strings.Contains(body, want) {
			t.Errorf("the export lacks %s", want)
		}
	}
	for _, secret := range []string{"argon2", "password_hash", "session_hash", "token_hash"} {
		if strings.Contains(body, secret) {
			t.Errorf("the export contains %s", secret)
		}
	}
}

// Covers: U15
func TestE2ETheLastAdministratorCannotDeleteItself(t *testing.T) {
	newTestEnv(t)
	// The seeded admin plus one more would make two; remove the seeded one's membership first.
	testutil.Exec(t, `DELETE FROM group_member`)
	acct := testutil.AdminAccount(t, "rhoam")
	br := newBrowser(t)
	br.mustLogin("rhoam")
	if m := br.call("DELETE", "/api/v1/me", map[string]any{"username": "rhoam"}, 409); m["error"] != "last_admin" {
		t.Errorf("the last administrator deleting itself: %v", m)
	}
	if _, err := db.GetAccount(acct.ID); err != nil {
		t.Error("the account was deleted")
	}
}
