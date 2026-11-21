package e2e

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"guardian/internal/config"
	"guardian/internal/testutil"
	"guardian/internal/web"
)

// The sign-in pages of 0.1 (docs/PAGES.md S1-S9), driven like a browser without JavaScript.

// Covers: V3
func TestE2ESignUpPageCreatesAnAccountAndSignsItIn(t *testing.T) {
	newTestEnv(t)
	testutil.CreateAccount(t, "taken")
	app, _ := testutil.CreateApp(t, "notes", testutil.AppOptions{FirstParty: true})
	_, challenge := newPKCE(t)
	returnTo := "/authorize?" + authParams{app: app, scope: "openid", state: "s", challenge: challenge}.values().Encode()

	br := newBrowser(t)
	page := readBody(t, br.get("/signup?return_to="+url.QueryEscape(returnTo)))
	for _, want := range []string{"Create an account", "hobby project", `name="password2"`, `name="website"`} {
		if !strings.Contains(page, want) {
			t.Errorf("sign-up page lacks %q", want)
		}
	}
	signup := func(v url.Values) *http.Response {
		v.Set("csrf", br.csrf())
		v.Set("return_to", returnTo)
		return br.postForm("/signup", v)
	}
	form := func(username, password, password2 string) url.Values {
		return url.Values{"username": {username}, "password": {password}, "password2": {password2}}
	}

	// mistakes come back on the form, with what was typed as the username kept
	for _, c := range []struct {
		name   string
		form   url.Values
		status int
		want   string
	}{
		{"bad username", form("a b", "long-enough-pw-1", "long-enough-pw-1"), 400, "Use 3–64 letters"},
		{"short password", form("newbie", "short", "short"), 400, "Use at least 10 characters."},
		{"mismatch", form("newbie", "long-enough-pw-1", "long-enough-pw-2"), 400, "The passwords don&#39;t match."},
		{"taken", form("TAKEN", "long-enough-pw-1", "long-enough-pw-1"), 409, "That username is taken."},
	} {
		resp := signup(c.form)
		wantStatus(t, resp, c.status)
		body := readBody(t, resp)
		if !strings.Contains(body, c.want) {
			t.Errorf("%s: page lacks %q", c.name, c.want)
		}
		if !strings.Contains(body, `value="`+c.form.Get("username")+`"`) && c.name != "bad username" {
			t.Errorf("%s: the username was not kept", c.name)
		}
	}
	if n := testutil.Count(t, `SELECT count(*) FROM account WHERE username = 'newbie'`); n != 0 {
		t.Fatal("an account was created from an invalid form")
	}

	// the honeypot field is filled in only by bots
	bot := form("botty", "long-enough-pw-1", "long-enough-pw-1")
	bot.Set("website", "https://spam.example")
	resp := signup(bot)
	wantStatus(t, resp, 400)
	drain(resp)
	if n := testutil.Count(t, `SELECT count(*) FROM account WHERE username = 'botty'`); n != 0 {
		t.Error("the honeypot did not stop the sign-up")
	}

	// an expired form keeps the username and asks for the passwords again
	resp = br.postForm("/signup", url.Values{"csrf": {strings.Repeat("x", 43)}, "username": {"newbie"}})
	wantStatus(t, resp, http.StatusForbidden)
	if body := readBody(t, resp); !strings.Contains(body, "The form had expired") || !strings.Contains(body, `value="newbie"`) {
		t.Error("an expired sign-up form must be shown again with the username")
	}

	// success: signed in and straight back into the app's sign-in
	resp = signup(form("newbie", "long-enough-pw-1", "long-enough-pw-1"))
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != returnTo {
		t.Fatalf("after sign-up: location %q, want the app's sign-in", loc)
	}
	resp = br.get(returnTo)
	wantStatus(t, resp, http.StatusFound)
	drain(resp)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, app.RedirectURIs[0]+"?code=") {
		t.Errorf("the new account was not signed in to the app: %q", loc)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'account.signed_up'`); n != 1 {
		t.Errorf("%d sign-ups audited, want 1", n)
	}
}

// Covers: U3, A6
func TestE2ETemporaryPasswordMustBeReplacedBeforeSignIn(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "root")
	user := testutil.CreateAccount(t, "hana")
	app, _ := testutil.CreateApp(t, "wiki", testutil.AppOptions{FirstParty: true})
	admin := newBrowser(t)
	admin.mustLogin("root")
	admin.call("PUT", "/api/v1/accounts/"+user.ID+"/password", map[string]any{"new_password": "temporary-password-1"}, 204)

	_, challenge := newPKCE(t)
	authorizeURL := "/authorize?" + authParams{app: app, scope: "openid", state: "s", challenge: challenge}.values().Encode()
	br := newBrowser(t)
	resp := br.login("hana", "temporary-password-1", authorizeURL)
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	passwordURL := resp.Header.Get("Location")
	if passwordURL != "/password?return_to="+url.QueryEscape(authorizeURL) {
		t.Fatalf("after signing in with a temporary password: location %q", passwordURL)
	}

	// the app's sign-in cannot be reached around the page, and prompt=none gets an error instead
	resp = br.get(authorizeURL)
	wantStatus(t, resp, http.StatusFound)
	drain(resp)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/password?") {
		t.Errorf("/authorize with a temporary password: location %q", loc)
	}
	resp = br.get(authorizeURL + "&prompt=none")
	drain(resp)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=interaction_required") {
		t.Errorf("prompt=none with a temporary password: location %q", loc)
	}
	resp = br.get("/login")
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/password" {
		t.Errorf("/login with a temporary password: location %q", loc)
	}

	page := readBody(t, br.get(passwordURL))
	if !strings.Contains(page, "Choose a new password") || !strings.Contains(page, "temporary password") {
		t.Fatalf("the password page is missing: %.300s", page)
	}
	csrf := csrfRe.FindStringSubmatch(page)[1]
	change := func(p1, p2 string) *http.Response {
		return br.postForm("/password", url.Values{"csrf": {csrf}, "return_to": {authorizeURL}, "password": {p1}, "password2": {p2}})
	}
	for _, c := range []struct{ p1, p2, want string }{
		{"temporary-password-1", "temporary-password-1", "That&#39;s the temporary password."},
		{"my-own-password-1", "my-own-password-2", "The passwords don&#39;t match."},
		{"short", "short", "Use at least 10 characters."},
	} {
		resp := change(c.p1, c.p2)
		wantStatus(t, resp, http.StatusBadRequest)
		if body := readBody(t, resp); !strings.Contains(body, c.want) {
			t.Errorf("%s/%s: page lacks %q", c.p1, c.p2, c.want)
		}
	}

	resp = change("my-own-password-1", "my-own-password-1")
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != authorizeURL {
		t.Fatalf("after choosing a password: location %q, want the app's sign-in", loc)
	}
	resp = br.get(authorizeURL)
	drain(resp)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, app.RedirectURIs[0]+"?code=") {
		t.Errorf("sign-in did not continue: %q", loc)
	}
	if got := br.call("GET", "/api/v1/me", nil, 200); got["must_change_password"] != false {
		t.Error("must_change_password is still set")
	}
	// the page is gone once the password is chosen, and the new password works
	resp = br.get("/password")
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("/password without a temporary password: location %q", loc)
	}
	newBrowser(t).mustLoginWith("hana", "my-own-password-1")
}

// Covers: V1
func TestE2ESignInWithEmailAddress(t *testing.T) {
	newTestEnv(t)
	testutil.AdminAccount(t, "root")
	user := testutil.CreateAccount(t, "ivy")
	admin := newBrowser(t)
	admin.mustLogin("root")
	admin.call("PATCH", "/api/v1/accounts/"+user.ID, map[string]any{"email": "Ivy@Example.test"}, 200)

	br := newBrowser(t)
	resp := br.login("ivy@example.test", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if got := br.call("GET", "/api/v1/me", nil, 200); got["username"] != "ivy" {
		t.Errorf("signed in as %v", got["username"])
	}
	resp = newBrowser(t).login("nobody@example.test", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusUnauthorized)
	if body := readBody(t, resp); !strings.Contains(body, "Wrong username or password.") || !strings.Contains(body, `value="nobody@example.test"`) {
		t.Error("a failed sign-in must keep what was typed and say the same as for usernames")
	}
}

// Covers: U6
func TestE2ESignOutToSwitchAccountContinuesTheSignIn(t *testing.T) {
	newTestEnv(t)
	testutil.CreateAccount(t, "jo")
	outsider := testutil.CreateAccount(t, "kim")
	member := testutil.CreateAccount(t, "lee")
	group := testutil.Group(t, "readers", "")
	testutil.AddMember(t, group, member.ID)
	app, _ := testutil.CreateApp(t, "library", testutil.AppOptions{AccessRule: "groups", GroupIDs: []string{group}, FirstParty: true})
	_, challenge := newPKCE(t)
	authorizeURL := "/authorize?" + authParams{app: app, scope: "openid", state: "s", challenge: challenge}.values().Encode()

	br := newBrowser(t)
	br.mustLogin(outsider.Username)
	resp := br.get(authorizeURL)
	wantStatus(t, resp, http.StatusForbidden)
	page := readBody(t, resp)
	for _, want := range []string{"have access to App library", "Signed in as", "kim", "Sign out to switch account"} {
		if !strings.Contains(page, want) {
			t.Errorf("no-access page lacks %q", want)
		}
	}
	m := regexpReturnTo.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the no-access page has no return_to")
	}
	resp = br.postForm("/logout", url.Values{"csrf": {br.csrf()}, "return_to": {htmlUnescape(m[1])}})
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	loc := resp.Header.Get("Location")
	if loc != "/login?return_to="+url.QueryEscape(authorizeURL) {
		t.Fatalf("after signing out to switch: location %q", loc)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM session WHERE account_id = $1 AND revoked_at IS NULL`, outsider.ID); n != 0 {
		t.Error("the old session is still live")
	}
	cb := br.authorizeCallback(mustQuery(t, authorizeURL), member.Username)
	if cb.Query().Get("code") == "" {
		t.Errorf("the other account did not get through: %v", cb)
	}

	// a return_to that is not Guardian's own sign-in is ignored
	br.mustLogin("jo")
	resp = br.postForm("/logout", url.Values{"csrf": {br.csrf()}, "return_to": {"https://evil.example/"}})
	wantStatus(t, resp, http.StatusOK)
	if body := readBody(t, resp); !strings.Contains(body, "You're signed out") {
		t.Errorf("signed-out page missing: %.300s", body)
	}
}

// Covers: V4
func TestE2EPagesRoutingAndStaticFiles(t *testing.T) {
	newTestEnv(t)
	br := newBrowser(t)

	resp := br.get("/")
	wantStatus(t, resp, http.StatusFound)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("/ redirects to %q", loc)
	}

	resp = br.get("/no-such-page")
	wantStatus(t, resp, http.StatusNotFound)
	if body := readBody(t, resp); !strings.Contains(body, "Page not found") || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("unknown page: %.200s", body)
	}
	resp = br.get("/api/v1/no-such-route")
	wantStatus(t, resp, http.StatusNotFound)
	if body := readBody(t, resp); !strings.Contains(body, `"error"`) {
		t.Errorf("/api/v1 must keep its JSON 404: %.200s", body)
	}

	page := readBody(t, br.get("/login"))
	css := regexpCSS.FindStringSubmatch(page)
	if css == nil {
		t.Fatalf("no stylesheet on /login")
	}
	resp = br.get(htmlUnescape(css[1]))
	wantStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/css") || !strings.Contains(body, "mask-composite") {
		t.Errorf("stylesheet: %s, %.100s", resp.Header.Get("Content-Type"), body)
	}
	for _, p := range []string{"/static/background.jpg", "/static/logo-mask.svg", "/static/favicon.svg", "/static/guardian.js"} {
		resp := br.get(p)
		wantStatus(t, resp, http.StatusOK)
		drain(resp)
	}

	// an expired consent or logout form is the "form expired" page
	resp = br.postForm("/logout", url.Values{"csrf": {"nope"}})
	wantStatus(t, resp, http.StatusForbidden)
	if body := readBody(t, resp); !strings.Contains(body, "This form has expired") {
		t.Errorf("expired logout form: %.200s", body)
	}
	// a broken link from an app never shows technical details
	resp = br.get("/authorize?client_id=nope&redirect_uri=https://x.test/cb&response_type=code&scope=openid")
	wantStatus(t, resp, http.StatusBadRequest)
	if body := readBody(t, resp); !strings.Contains(body, "The sign-in link is broken") || strings.Contains(body, "Unknown application") {
		t.Errorf("broken link page: %.300s", body)
	}
}

var (
	regexpReturnTo = regexp.MustCompile(`name="return_to" value="([^"]+)"`)
	regexpCSS      = regexp.MustCompile(`href="(/static/guardian\.css\?v=[^"]+)"`)
)

func htmlUnescape(s string) string { return html.UnescapeString(s) }

// mustQuery returns the query of a relative URL such as /authorize?a=1.
func mustQuery(t *testing.T, rel string) url.Values {
	t.Helper()
	u, err := url.Parse(rel)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// Covers: U19, U20
func TestE2EHomeListsTheAppsTheAccountMayUse(t *testing.T) {
	newTestEnv(t)
	user := testutil.CreateAccount(t, "mo")
	group := testutil.Group(t, "crew", "")
	testutil.AddMember(t, group, user.ID)
	other := testutil.Group(t, "others", "")
	used, usedSecret := testutil.CreateApp(t, "used", testutil.AppOptions{FirstParty: true})
	linked, _ := testutil.CreateApp(t, "linked", testutil.AppOptions{AccessRule: "groups", GroupIDs: []string{group}})
	notLinked, _ := testutil.CreateApp(t, "closed", testutil.AppOptions{AccessRule: "groups", GroupIDs: []string{other}})
	noHome, _ := testutil.CreateApp(t, "nohome", testutil.AppOptions{})
	disabled, _ := testutil.CreateApp(t, "off", testutil.AppOptions{})
	for _, a := range []string{used.ID, linked.ID, notLinked.ID, disabled.ID} {
		testutil.Exec(t, `UPDATE app SET homepage_url = 'https://' || name || '.test/' WHERE id = $1`, a)
	}
	testutil.Exec(t, `UPDATE app SET enabled = FALSE WHERE id = $1`, disabled.ID)
	_ = noHome

	// signing up without an app to return to lands on Home
	br := newBrowser(t)
	resp := br.postForm("/signup", url.Values{"csrf": {br.csrf()}, "username": {"newcomer"},
		"password": {"long-enough-pw-1"}, "password2": {"long-enough-pw-1"}})
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("after sign-up without return_to: location %q, want Home", loc)
	}
	page := readBody(t, br.get("/"))
	for _, want := range []string{"Welcome to Guardian", "newcomer", "App used"} {
		if !strings.Contains(page, want) {
			t.Errorf("Home of a new account lacks %q", want)
		}
	}
	if strings.Contains(page, "Your connected apps") {
		t.Error("a new account has no connected apps")
	}

	// mo has used one app and may use another; the rest stay out
	mb := newBrowser(t)
	mb.signIn(used, usedSecret, "mo", "openid")
	page = readBody(t, mb.get("/"))
	connected, available, ok := strings.Cut(page, "Available apps")
	if !ok || !strings.Contains(connected, "Your connected apps") || !strings.Contains(connected, `href="https://used.test/"`) {
		t.Errorf("the used app is not under connected apps")
	}
	if !strings.Contains(available, `href="https://linked.test/"`) {
		t.Errorf("the app linked to mo's group is not available")
	}
	for _, hidden := range []string{"App closed", "App nohome", "App off"} {
		if strings.Contains(page, hidden) {
			t.Errorf("Home shows %q", hidden)
		}
	}

	// without apps, Home says so; without a session, it is the sign-in page
	testutil.Exec(t, `UPDATE app SET enabled = FALSE`)
	if page := readBody(t, mb.get("/")); !strings.Contains(page, "No apps yet") {
		t.Error("Home without apps lacks its empty state")
	}
	resp = newBrowser(t).get("/")
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("Home without a session: location %q", loc)
	}
}

// The per-address limit counts failures across accounts; the honeypot catches form-filling bots.
//
// Covers: V2, V3
func TestE2EAbuseProtection(t *testing.T) {
	newTestEnv(t)
	// A lower per-address limit than the default 50: every failure costs a full password check, which the
	// race detector makes slow, and the rule is the same at any number.
	limited := testConfig
	limited.LoginLimits = config.LoginLimits{Window: 15 * time.Minute, PerAccountAndIP: 5, PerIP: 8}
	web.Configure(limited)
	t.Cleanup(func() { web.Configure(testConfig) })
	testutil.CreateAccount(t, "kass")
	bot := newBrowser(t)
	bot.ip = "198.51.100.7"
	for i := 0; i < limited.LoginLimits.PerIP; i++ {
		resp := bot.login(fmt.Sprintf("guess%d", i), "wrong-password-1", "")
		drain(resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, resp.StatusCode)
		}
	}
	resp := bot.login("kass", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusTooManyRequests)
	drain(resp)
	// A neighbour behind another address is not affected.
	other := newBrowser(t)
	other.ip = "198.51.100.8"
	other.mustLogin("kass")

	// Honeypots: the forms answer as usual, nothing happens, and it is counted.
	trap := newBrowser(t)
	resp = trap.postForm("/signup", url.Values{"csrf": {trap.csrf()}, "username": {"botty"}, "password": {"long-enough-pw-1"},
		"password2": {"long-enough-pw-1"}, "website": {"http://spam.example"}})
	wantStatus(t, resp, http.StatusBadRequest)
	drain(resp)
	testutil.CreateAccount(t, "urbosa")
	setEmail(t, "urbosa", "urbosa@gerudo.example")
	resp = trap.postForm("/forgot", url.Values{"csrf": {trap.csrf()}, "username": {"urbosa"}, "website": {"x"}})
	wantStatus(t, resp, http.StatusOK)
	if body := readBody(t, resp); !strings.Contains(body, "we have sent a link") {
		t.Error("the trapped reset form must answer as usual")
	}
	time.Sleep(100 * time.Millisecond)
	if len(mailbox.Messages()) != 0 || testutil.Count(t, `SELECT count(*) FROM account WHERE username = 'botty'`) != 0 {
		t.Error("a trapped form did something")
	}
	if testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'honeypot'`) != 2 {
		t.Error("honeypot hits are not audited")
	}
}
