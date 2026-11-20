package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"guardian/internal/testutil"
)

// The routes behind the admin area's overview and accounts (0.4 part 3), and the two-factor step-up the
// management UI sends a session to when a page needs it.

func TestE2EAdminOverviewCountsWithoutNamingAnyone(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "purah")
	testutil.CreateAccount(t, "robbie")
	off := testutil.CreateAccount(t, "kohga")
	testutil.Exec(t, `UPDATE account SET status = 'disabled' WHERE id = $1`, off.ID)
	temp := testutil.CreateAccount(t, "hudson")
	testutil.Exec(t, `UPDATE account SET must_change_password = true WHERE id = $1`, temp.ID)
	testutil.CreateApp(t, "notes", testutil.AppOptions{})

	// A failed sign-in, and one refused by the limit.
	guesser := newBrowser(t)
	for i := 0; i < 6; i++ {
		drain(guesser.login("robbie", "wrong-password-1", ""))
	}
	br := newBrowser(t)
	br.mustLogin("purah")

	o := br.call("GET", "/api/v1/overview", nil, 200)
	accounts := o["accounts"].(map[string]any)
	// The built-in admin counts too: active, with its first password still to change.
	if accounts["active"] != 4.0 || accounts["disabled"] != 1.0 || accounts["must_change_password"] != 2.0 {
		t.Errorf("accounts: %v", accounts)
	}
	day := o["last_day"].(map[string]any)
	if day["sign_ins"] != 1.0 || day["failed_sign_ins"] != 5.0 || day["rate_limited"] != 1.0 {
		t.Errorf("last day: %v", day)
	}
	admins := o["admins"].(map[string]any)
	if admins["total"] != 2.0 || admins["with_two_factor"] != 1.0 || admins["permanent"] != 2.0 {
		t.Errorf("admins: %v", admins)
	}
	if apps := o["apps"].(map[string]any); apps["enabled"] != 1.0 {
		t.Errorf("apps: %v", apps)
	}
	raw := readBody(t, br.sendJSON("GET", "/api/v1/overview", nil))
	for _, name := range []string{"purah", "robbie", "kohga", "hudson"} {
		if strings.Contains(raw, name) {
			t.Errorf("the overview names %s", name)
		}
	}

	// Not for anyone else.
	other := newBrowser(t)
	other.ip = "203.0.113.5" // robbie is refused from the guesser's address
	other.mustLogin("robbie")
	other.call("GET", "/api/v1/overview", nil, 403)
}

func TestE2EAdminAccountsPagesFiltersAndActivity(t *testing.T) {
	newTestEnv(t)
	admin := testutil.AdminAccount(t, "impa")
	for _, n := range []string{"paya", "dorian", "koko", "cottla"} {
		testutil.CreateAccount(t, n)
	}
	temp := testutil.AccountID(t, "koko")
	testutil.Exec(t, `UPDATE account SET must_change_password = true WHERE id = $1`, temp)
	br := newBrowser(t)
	br.mustLogin("impa")

	page := br.call("GET", "/api/v1/accounts?limit=2", nil, 200)
	// Five accounts here, and the built-in admin (who still has its first password).
	if page["total"] != 6.0 || len(items(t, page)) != 2 || page["next_cursor"] == nil {
		t.Fatalf("first page: %v", page)
	}
	if m := br.call("GET", "/api/v1/accounts?status=must_change_password", nil, 200); m["total"] != 2.0 || !strings.Contains(usernames(items(t, m)), "koko") {
		t.Errorf("must change password: %v", m)
	}
	if m := br.call("GET", "/api/v1/accounts?q=o&status=active", nil, 200); m["total"] != 3.0 {
		t.Errorf("search with a status: %v", m)
	}
	br.call("GET", "/api/v1/accounts?status=locked", nil, 400)

	detail := br.call("GET", "/api/v1/accounts/"+admin.ID, nil, 200)
	if detail["is_admin"] != true || detail["mfa"].(map[string]any)["totp"] != true {
		t.Errorf("an administrator's details: is_admin %v, mfa %v", detail["is_admin"], detail["mfa"])
	}

	// Signing paya out everywhere ends her sessions without disabling her.
	paya := testutil.AccountID(t, "paya")
	user := newBrowser(t)
	user.mustLogin("paya")
	br.call("DELETE", "/api/v1/accounts/"+paya+"/sessions", nil, 204)
	user.call("GET", "/api/v1/me", nil, 401)
	user.mustLogin("paya")
	br.call("DELETE", "/api/v1/accounts/00000000-0000-0000-0000-000000000000/sessions", nil, 404)

	// Activity about an account: what it did and what was done to it, with who did it.
	about := items(t, br.call("GET", "/api/v1/audit?about="+paya, nil, 200))
	var events []string
	for _, e := range about {
		events = append(events, str(e["event_type"]))
		if e["event_type"] == "account.signed_out_everywhere" && e["actor_username"] != "impa" {
			t.Errorf("the actor is not named: %v", e)
		}
	}
	if !contains(events, "account.signed_out_everywhere") || !contains(events, "login.success") {
		t.Errorf("activity about paya: %v", events)
	}
	br.call("GET", "/api/v1/audit?about=nope", nil, 400)

	// The deleted list says who deleted an account.
	br.call("DELETE", "/api/v1/accounts/"+paya, nil, 204)
	deleted := items(t, br.call("GET", "/api/v1/accounts/deleted", nil, 200))
	if len(deleted) != 1 || deleted[0]["deleted_by_username"] != "impa" {
		t.Errorf("deleted: %v", deleted)
	}
}

// A session that has not passed two-factor is refused admin rights; /mfa/stepup asks for a code and
// returns to the management UI, after which the rights work.
func TestE2EStepUpForTheManagementUI(t *testing.T) {
	newTestEnv(t)
	admin := testutil.AdminAccount(t, "zelda")
	br := newBrowser(t)
	br.mustLogin("zelda")
	testutil.Exec(t, `UPDATE session SET amr = '{pwd}' WHERE account_id = $1`, admin.ID)
	if m := br.call("GET", "/api/v1/overview", nil, 403); m["error"] != "mfa_required" {
		t.Fatalf("without two-factor: %v", m)
	}

	resp := br.get("/mfa/stepup?return_to=" + url.QueryEscape("/admin/accounts?q=link"))
	wantStatus(t, resp, http.StatusSeeOther)
	if loc := resp.Header.Get("Location"); loc != "/mfa" {
		t.Fatalf("step-up goes to %q", loc)
	}
	drain(resp)
	done := br.passMFA("zelda")
	if loc := done.Header.Get("Location"); loc != "/admin/accounts?q=link" {
		t.Errorf("after the code: %q", loc)
	}
	br.call("GET", "/api/v1/overview", nil, 200)

	// Already stepped up: straight back. Not signed in: the sign-in page, which returns there too.
	resp = br.get("/mfa/stepup?return_to=/admin")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/admin" {
		t.Errorf("already stepped up: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	drain(resp)
	resp = newBrowser(t).get("/mfa/stepup?return_to=/admin")
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || loc != "/login?return_to=%2Fadmin" {
		t.Errorf("not signed in: %d %q", resp.StatusCode, loc)
	}
	drain(resp)
	// Only the management UI and /authorize are allowed as places to return to.
	testutil.Exec(t, `UPDATE session SET amr = '{pwd}' WHERE account_id = $1`, admin.ID)
	drain(br.get("/mfa/stepup?return_to=https://evil.example/"))
	if done := br.passMFA("zelda"); done.Header.Get("Location") != "/" {
		t.Errorf("a foreign return_to was kept: %q", done.Header.Get("Location"))
	}
}
