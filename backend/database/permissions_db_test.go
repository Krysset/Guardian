package database_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"guardian/auth"
	db "guardian/database"
	"guardian/internal/testutil"
)

func hasPerm(t *testing.T, a db.Account, appName, perm string) bool {
	t.Helper()
	ok, err := db.AccountHasPermission(a.ID, appName, perm)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestDirectGrantsAreScopedToTheirApp(t *testing.T) {
	testutil.Reset(t)
	billing, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	wiki, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{})
	read := testutil.Permission(t, billing.ID, "invoices.read")
	testutil.Permission(t, billing.ID, "invoices.approve")
	testutil.Permission(t, wiki.ID, "invoices.read") // same name, different app
	alice := testutil.CreateAccount(t, "alice")

	if hasPerm(t, alice, "billing", "invoices.read") {
		t.Fatal("a new account must hold nothing")
	}
	if err := db.GrantPermission(alice.ID, read, "", "", nil); err != nil {
		t.Fatal(err)
	}
	if !hasPerm(t, alice, "billing", "invoices.read") {
		t.Error("granted permission not effective")
	}
	if hasPerm(t, alice, "billing", "invoices.approve") {
		t.Error("another permission of the same app leaked")
	}
	if hasPerm(t, alice, "wiki", "invoices.read") {
		t.Error("a permission with the same name in another app leaked")
	}
	if err := db.RevokePermission(alice.ID, read); err != nil {
		t.Fatal(err)
	}
	if hasPerm(t, alice, "billing", "invoices.read") {
		t.Error("revoked permission still effective")
	}
}

func TestRolesSpanAppsAndChangesApplyImmediately(t *testing.T) {
	testutil.Reset(t)
	billing, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	wiki, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{})
	read := testutil.Permission(t, billing.ID, "invoices.read")
	approve := testutil.Permission(t, billing.ID, "invoices.approve")
	edit := testutil.Permission(t, wiki.ID, "pages.edit")
	role := testutil.Role(t, "support", false, read, edit)
	bob := testutil.CreateAccount(t, "bob")

	if err := db.GrantRole(bob.ID, role, "", nil); err != nil {
		t.Fatal(err)
	}
	if !hasPerm(t, bob, "billing", "invoices.read") || !hasPerm(t, bob, "wiki", "pages.edit") {
		t.Fatal("a role must grant permissions in every app it lists")
	}
	if hasPerm(t, bob, "billing", "invoices.approve") {
		t.Fatal("permission outside the role leaked")
	}

	// editing the role's permission set is effective for existing holders at once
	if err := db.SetRolePermissions(role, []string{approve}); err != nil {
		t.Fatal(err)
	}
	if !hasPerm(t, bob, "billing", "invoices.approve") || hasPerm(t, bob, "billing", "invoices.read") || hasPerm(t, bob, "wiki", "pages.edit") {
		t.Fatal("SetRolePermissions must replace the set for all holders immediately")
	}

	if err := db.RevokeRole(bob.ID, role); err != nil {
		t.Fatal(err)
	}
	if hasPerm(t, bob, "billing", "invoices.approve") {
		t.Fatal("revoked role still effective")
	}

	// deleting a role removes it from its holders
	if err := db.GrantRole(bob.ID, role, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteRole(role); err != nil {
		t.Fatal(err)
	}
	if hasPerm(t, bob, "billing", "invoices.approve") {
		t.Fatal("deleted role still effective")
	}
}

func TestCatchallRoleHoldsEverythingIncludingFutureAndAppsAreNotLeakedAcrossAccounts(t *testing.T) {
	testutil.Reset(t)
	billing, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	testutil.Permission(t, billing.ID, "invoices.read")
	admin := testutil.AdminAccount(t, "root")
	other := testutil.CreateAccount(t, "other")

	if !hasPerm(t, admin, "billing", "invoices.read") || !hasPerm(t, admin, "guardian", "apps.manage") {
		t.Fatal("the admin role must hold every permission of every app")
	}
	// a permission and an app created AFTER the grant are covered without any new grant
	late := testutil.Permission(t, billing.ID, "invoices.delete")
	_ = late
	wiki, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{})
	testutil.Permission(t, wiki.ID, "pages.edit")
	if !hasPerm(t, admin, "billing", "invoices.delete") || !hasPerm(t, admin, "wiki", "pages.edit") {
		t.Fatal("catchall must cover permissions created later")
	}
	if hasPerm(t, other, "billing", "invoices.read") || hasPerm(t, other, "guardian", "apps.manage") {
		t.Fatal("catchall of one account leaked to another")
	}
	if ok, _ := db.AccountHasRole(admin.ID, "admin"); !ok {
		t.Error("AccountHasRole(admin) = false")
	}
	if ok, _ := db.AccountHasRole(other.ID, "admin"); ok {
		t.Error("non-admin reported as admin")
	}
}

func TestExpiredGrantsAreIgnored(t *testing.T) {
	testutil.Reset(t)
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	perm := testutil.Permission(t, app.ID, "invoices.read")
	role := testutil.Role(t, "reader", false, perm)
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)

	viaRole := testutil.CreateAccount(t, "via-role")
	if err := db.GrantRole(viaRole.ID, role, "", &past); err != nil {
		t.Fatal(err)
	}
	if hasPerm(t, viaRole, "billing", "invoices.read") {
		t.Error("expired role grant is still effective")
	}
	if ok, _ := db.AccountHasRole(viaRole.ID, "reader"); ok {
		t.Error("AccountHasRole true for an expired grant")
	}
	// re-granting with a future expiry revives it (upsert)
	if err := db.GrantRole(viaRole.ID, role, "", &future); err != nil {
		t.Fatal(err)
	}
	if !hasPerm(t, viaRole, "billing", "invoices.read") {
		t.Error("re-granted role not effective")
	}

	direct := testutil.CreateAccount(t, "direct")
	if err := db.GrantPermission(direct.ID, perm, "", "", &past); err != nil {
		t.Fatal(err)
	}
	if hasPerm(t, direct, "billing", "invoices.read") {
		t.Error("expired direct grant is still effective")
	}
	if err := db.GrantPermission(direct.ID, perm, "", "", &future); err != nil {
		t.Fatal(err)
	}
	if !hasPerm(t, direct, "billing", "invoices.read") {
		t.Error("direct grant with a future expiry not effective")
	}
}

func TestSystemRolesAreProtected(t *testing.T) {
	testutil.Reset(t)
	adminRole := testutil.RoleID(t, "admin")
	if err := db.DeleteRole(adminRole); !errors.Is(err, db.ErrSystemRole) {
		t.Errorf("DeleteRole(admin) = %v, want ErrSystemRole", err)
	}
	if err := db.SetRolePermissions(adminRole, nil); !errors.Is(err, db.ErrSystemRole) {
		t.Errorf("SetRolePermissions(admin) = %v, want ErrSystemRole", err)
	}
	if err := db.DeleteRole("00000000-0000-0000-0000-000000000000"); !errors.Is(err, db.ErrSystemRole) {
		t.Errorf("DeleteRole(unknown) = %v, want the not-found/system error", err)
	}
	roles, _ := db.ListRoles()
	var admin *db.Role
	for i := range roles {
		if roles[i].Name == "admin" {
			admin = &roles[i]
		}
	}
	if admin == nil || !admin.AllPermissions || !admin.IsSystem {
		t.Fatalf("admin role = %+v", admin)
	}
}

func TestRoleAndPermissionUniqueness(t *testing.T) {
	testutil.Reset(t)
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	testutil.Permission(t, app.ID, "invoices.read")
	if _, err := db.CreateAppPermission(app.ID, "invoices.read", "dup", ""); !db.IsUniqueViolation(err) {
		t.Errorf("duplicate permission in one app: %v", err)
	}
	testutil.Role(t, "support", false)
	if _, err := db.CreateRole("support", "dup", "", false, nil); !db.IsUniqueViolation(err) {
		t.Errorf("duplicate role name: %v", err)
	}
}

// The core requirement: a revoke is visible to the very next token introspection, with no delay.
func TestRevokingARoleIsVisibleToTheNextIntrospection(t *testing.T) {
	testutil.Reset(t)
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	perm := testutil.Permission(t, app.ID, "invoices.approve")
	role := testutil.Role(t, "approvers", false, perm)
	user := testutil.CreateAccount(t, "carol")
	sess, _ := testutil.Session(t, user.ID)
	token := testutil.Token(t, app, user.ID, sess.ID, time.Hour)
	hash := auth.HashToken(token)

	perms := func() []string {
		info, err := db.IntrospectAccessToken(hash, app.ID)
		if err != nil {
			t.Fatal(err)
		}
		return info.Permissions
	}
	if len(perms()) != 0 {
		t.Fatal("no permissions expected yet")
	}
	if err := db.GrantRole(user.ID, role, "", nil); err != nil {
		t.Fatal(err)
	}
	if got := perms(); len(got) != 1 || got[0] != "invoices.approve" {
		t.Fatalf("after grant: %v", got)
	}
	if err := db.RevokeRole(user.ID, role); err != nil {
		t.Fatal(err)
	}
	if got := perms(); len(got) != 0 {
		t.Fatalf("after revoke the permission must be gone immediately, got %v", got)
	}
}

func TestIntrospectionReturnsPermissionsOfTheCallerNotTheTokenApp(t *testing.T) {
	testutil.Reset(t)
	billing, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	wiki, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{})
	pb := testutil.Permission(t, billing.ID, "invoices.read")
	pw := testutil.Permission(t, wiki.ID, "pages.edit")
	user := testutil.CreateAccount(t, "dave")
	for _, p := range []string{pb, pw} {
		if err := db.GrantPermission(user.ID, p, "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	token := testutil.Token(t, billing, user.ID, "", time.Hour) // issued to billing
	hash := auth.HashToken(token)

	asBilling, err := db.IntrospectAccessToken(hash, billing.ID)
	if err != nil || len(asBilling.Permissions) != 1 || asBilling.Permissions[0] != "invoices.read" {
		t.Fatalf("billing sees %v (%v)", asBilling.Permissions, err)
	}
	asWiki, err := db.IntrospectAccessToken(hash, wiki.ID)
	if err != nil || len(asWiki.Permissions) != 1 || asWiki.Permissions[0] != "pages.edit" {
		t.Fatalf("wiki sees %v (%v)", asWiki.Permissions, err)
	}
	if asWiki.ClientID != billing.ClientID || asWiki.AppID != billing.ID {
		t.Error("the token's own app must be reported so callers can refuse tokens they do not trust")
	}
	none, err := db.IntrospectAccessToken(hash, "")
	if err != nil || len(none.Permissions) != 0 {
		t.Fatalf("no caller app must yield no permissions, got %v (%v)", none.Permissions, err)
	}
}

func TestAttributesOfDirectGrantsAreReturnedForTheCallerOnly(t *testing.T) {
	testutil.Reset(t)
	billing, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	wiki, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{})
	approve := testutil.Permission(t, billing.ID, "invoices.approve")
	plain := testutil.Permission(t, billing.ID, "invoices.read")
	edit := testutil.Permission(t, wiki.ID, "pages.edit")
	user := testutil.CreateAccount(t, "erin")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(db.GrantPermission(user.ID, approve, "", `{"limit": 5000}`, nil))
	must(db.GrantPermission(user.ID, plain, "", "", nil)) // no attributes
	must(db.GrantPermission(user.ID, edit, "", `{"space": "eng"}`, nil))
	hash := auth.HashToken(testutil.Token(t, billing, user.ID, "", time.Hour))

	info, err := db.IntrospectAccessToken(hash, billing.ID)
	must(err)
	var attrs map[string]map[string]any
	must(json.Unmarshal(info.Attributes, &attrs))
	if len(attrs) != 1 || attrs["invoices.approve"]["limit"] != float64(5000) {
		t.Fatalf("attributes = %s, want only invoices.approve with limit 5000", info.Attributes)
	}

	wikiInfo, err := db.IntrospectAccessToken(hash, wiki.ID)
	must(err)
	if string(wikiInfo.Attributes) == "" || !json.Valid(wikiInfo.Attributes) {
		t.Fatalf("attributes must be valid JSON, got %q", wikiInfo.Attributes)
	}
	attrs = nil
	must(json.Unmarshal(wikiInfo.Attributes, &attrs))
	if _, leaked := attrs["invoices.approve"]; leaked || attrs["pages.edit"]["space"] != "eng" {
		t.Fatalf("wiki attributes = %s", wikiInfo.Attributes)
	}
}

func TestIntrospectionValidityRules(t *testing.T) {
	testutil.Reset(t)
	cases := []struct {
		name   string
		mutate func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string // returns token to introspect
		active bool
	}{
		{"valid", func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string { return token }, true},
		{"unknown token", func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string {
			return "not-a-token"
		}, false},
		{"token without session is valid", func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string {
			return testutil.Token(t, app, acct.ID, "", time.Hour)
		}, true},
		{"expired token", func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string {
			return testutil.Token(t, app, acct.ID, sess.ID, -time.Minute)
		}, false},
		{"revoked token", func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string {
			testutil.Exec(t, `UPDATE access_token SET revoked_at = now() WHERE token_hash = $1`, auth.HashToken(token))
			return token
		}, false},
		{"session revoked (logout)", func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string {
			if _, err := db.RevokeSession(sess.ID); err != nil {
				t.Fatal(err)
			}
			return token
		}, false},
		{"session merely expired still counts (offline access outlives the SSO session)", func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string {
			testutil.Exec(t, `UPDATE session SET expires_at = now() - interval '1 hour' WHERE id = $1`, sess.ID)
			return token
		}, true},
		{"account deleted", func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string {
			if err := db.SoftDeleteAccount(acct.ID); err != nil {
				t.Fatal(err)
			}
			return token
		}, false},
		{"account disabled", func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string {
			testutil.Exec(t, `UPDATE account SET status = 'disabled' WHERE id = $1`, acct.ID)
			return token
		}, false},
		{"app disabled", func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string {
			testutil.Exec(t, `UPDATE app SET enabled = FALSE WHERE id = $1`, app.ID)
			return token
		}, false},
		{"app removed", func(t *testing.T, app db.App, acct db.Account, sess db.Session, token string) string {
			if err := db.RemoveApp(app.ID); err != nil {
				t.Fatal(err)
			}
			return token
		}, false},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app, _ := testutil.CreateApp(t, "app"+string(rune('a'+i)), testutil.AppOptions{})
			acct := testutil.CreateAccount(t, "user"+string(rune('a'+i)))
			sess, _ := testutil.Session(t, acct.ID)
			token := testutil.Token(t, app, acct.ID, sess.ID, time.Hour)
			probe := c.mutate(t, app, acct, sess, token)

			_, err := db.IntrospectAccessToken(auth.HashToken(probe), app.ID)
			switch {
			case c.active && err != nil:
				t.Errorf("token should be active, got %v", err)
			case !c.active && !errors.Is(err, sql.ErrNoRows):
				t.Errorf("token should be inactive (sql.ErrNoRows), got %v", err)
			}
		})
	}
}

func TestIntrospectionReportsTokenMetadata(t *testing.T) {
	testutil.Reset(t)
	app, _ := testutil.CreateApp(t, "billing", testutil.AppOptions{})
	user := testutil.CreateAccount(t, "frank")
	sess, _ := testutil.Session(t, user.ID)
	token := testutil.Token(t, app, user.ID, sess.ID, time.Hour, "openid", "email")

	info, err := db.IntrospectAccessToken(auth.HashToken(token), app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if info.AccountID != user.ID || info.SessionID != sess.ID || info.ClientID != app.ClientID {
		t.Errorf("ids: %+v", info)
	}
	if len(info.Scopes) != 2 || info.Scopes[0] != "openid" || info.Scopes[1] != "email" {
		t.Errorf("scopes = %v", info.Scopes)
	}
	if d := time.Until(info.ExpiresAt); d < 55*time.Minute || d > time.Hour+time.Minute {
		t.Errorf("expires in %v", d)
	}
	if time.Since(info.IssuedAt) > time.Minute {
		t.Errorf("issued %v ago", time.Since(info.IssuedAt))
	}
}
