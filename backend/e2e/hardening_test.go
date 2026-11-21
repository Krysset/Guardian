package e2e

// Tests for the fixes from the security review before 1.0: limits that hold against attempts sent from many
// addresses, admin actions that could take over an account, and temporary passwords on the API.

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"guardian/internal/testutil"
)

// Guessing one account's password from many addresses, each failing less than the per-address limit, makes
// every sign-in to that account answer a puzzle. The owner still signs in, and that clears the count.
//
// Covers: V2, V9
func TestE2EGuessingFromManyAddressesMakesTheAccountAskForAPuzzle(t *testing.T) {
	newTestEnv(t)
	testutil.CreateAccount(t, "sidon")
	for i := 0; i < 10; i++ {
		guesser := newBrowser(t)
		guesser.ip = fmt.Sprintf("198.51.100.%d", i+1)
		resp := guesser.login("sidon", "wrong-password-1", "")
		wantStatus(t, resp, http.StatusUnauthorized)
		drain(resp)
	}

	owner := newBrowser(t)
	owner.ip = "192.0.2.77" // an address that never failed
	resp := owner.postForm("/login", url.Values{"csrf": {owner.csrf()}, "username": {"sidon"}, "password": {testutil.DefaultPassword}, "pow": {"-"}})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "quick check") {
		t.Fatalf("after guesses from many addresses, a sign-in without a puzzle: %d", resp.StatusCode)
	}
	m := powRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the refused sign-in's page carries no puzzle to answer")
	}
	resp = owner.postForm("/login", url.Values{"csrf": {owner.csrf()}, "username": {"sidon"}, "password": {testutil.DefaultPassword},
		"pow": {html.UnescapeString(m[1])}, "pow_number": {solvePoW(t, m[2], m[3], m[4])}})
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if n := testutil.Count(t, `SELECT count(*) FROM rate_limit WHERE key = $1`, "login:account:"+testutil.AccountID(t, "sidon")); n != 0 {
		t.Error("the owner's sign-in did not clear the account's count of failures")
	}
}

// IPv6 addresses count per /64, the block one home or server gets, so cycling through it does not escape
// the per-address limits.
//
// Covers: V2
func TestE2EIPv6AddressesCountPerBlock(t *testing.T) {
	newTestEnv(t)
	testutil.CreateAccount(t, "yunobo")
	for i := 1; i <= 3; i++ {
		guesser := newBrowser(t)
		guesser.ip = fmt.Sprintf("2001:db8:1:2::%x", i)
		drain(guesser.login("yunobo", "wrong-password-1", ""))
	}
	neighbour := newBrowser(t)
	neighbour.ip = "2001:db8:1:2:ffff::9"
	if !strings.Contains(readBody(t, neighbour.get("/login")), `name="pow"`) {
		t.Error("another address in the same /64 is not asked for a puzzle")
	}
	elsewhere := newBrowser(t)
	elsewhere.ip = "2001:db8:1:3::1"
	if strings.Contains(readBody(t, elsewhere.get("/login")), `name="pow"`) {
		t.Error("an address in another /64 is asked for a puzzle")
	}
}

// Admin actions that could hand an account to someone else, or lock its owner out, need a recent sign-in,
// like a person's own protected changes. So does downloading one's data.
//
// Covers: U16, A7
func TestE2EAdminActionsThatTakeOverAccountsNeedARecentSignIn(t *testing.T) {
	newTestEnv(t)
	root := testutil.AdminAccount(t, "root")
	bob := testutil.CreateAccount(t, "bob")
	admin := newBrowser(t)
	admin.mustLogin("root")
	ageSessions(t, root.ID)

	refused := func(method, path string, body any) {
		t.Helper()
		resp := admin.sendJSON(method, path, body)
		wantStatus(t, resp, http.StatusForbidden)
		if e := decodeMap(t, resp); e["error"] != "reauth_required" {
			t.Errorf("%s %s from an old sign-in: %v", method, path, e)
		}
	}
	account := "/api/v1/accounts/" + bob.ID
	refused("PUT", account+"/password", map[string]any{"new_password": "temporary-pw-123"})
	refused("POST", account+"/mfa/reset", map[string]any{"reason": "Lost phone"})
	refused("PATCH", account, map[string]any{"status": "disabled"})
	refused("PATCH", account, map[string]any{"email": "mallory@evil.example"})
	refused("DELETE", account, nil)
	refused("POST", account+"/erase", map[string]any{"username": "bob"})
	refused("GET", "/api/v1/me/export", nil)
	admin.call("PATCH", account, map[string]any{"display_name": "Bob"}, http.StatusOK) // not protected
	if n := testutil.Count(t, `SELECT count(*) FROM account WHERE id = $1 AND status = 'active' AND email IS NULL`, bob.ID); n != 1 {
		t.Error("a refused change was made anyway")
	}

	admin.call("POST", "/api/v1/me/reauth", map[string]any{"password": testutil.DefaultPassword}, http.StatusOK)
	admin.call("PUT", account+"/password", map[string]any{"new_password": "temporary-pw-123"}, http.StatusNoContent)
	admin.call("GET", "/api/v1/me/export", nil, http.StatusOK)
}

// An account with a temporary password may only read who it is and choose its own password through the API,
// as on the sign-in pages.
//
// Covers: A6
func TestE2ETemporaryPasswordsBlockTheAPI(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "root")
	bob := testutil.CreateAccount(t, "bob")
	admin := newBrowser(t)
	admin.mustLogin("root")
	admin.call("PUT", "/api/v1/accounts/"+bob.ID+"/password", map[string]any{"new_password": "temporary-pw-123"}, http.StatusNoContent)

	br := newBrowser(t)
	resp := br.login("bob", "temporary-pw-123", "")
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if me := br.call("GET", "/api/v1/me", nil, http.StatusOK); me["must_change_password"] != true {
		t.Fatalf("GET /me: %v", me)
	}
	for _, c := range [][2]string{{"GET", "/api/v1/me/sessions"}, {"PATCH", "/api/v1/me"}, {"GET", "/api/v1/me/export"}} {
		resp := br.sendJSON(c[0], c[1], map[string]any{})
		wantStatus(t, resp, http.StatusForbidden)
		if e := decodeMap(t, resp); e["error"] != "password_change_required" {
			t.Errorf("%s %s with a temporary password: %v", c[0], c[1], e)
		}
	}
	br.call("PUT", "/api/v1/me/password", map[string]any{"new_password": "my-own-password-1"}, http.StatusNoContent)
	br2 := newBrowser(t)
	br2.mustLoginWith("bob", "my-own-password-1")
	br2.call("GET", "/api/v1/me/sessions", nil, http.StatusOK)
}
