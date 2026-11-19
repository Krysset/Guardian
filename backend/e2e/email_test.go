package e2e

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"guardian/internal/mail"
	"guardian/internal/testutil"
	"guardian/internal/web"
)

// The pages behind Guardian's emails (0.3): sign-up with an address (S2, S2b, S12), password reset (S10,
// S11), changing the address, and the security notices.

var linkRe = regexp.MustCompile(`http://guardian\.test(/[a-z]+\?token=[A-Za-z0-9_%-]+)`)

// linkIn returns the path of the newest email to address whose subject contains subject.
func linkIn(t *testing.T, to, subject string) string {
	t.Helper()
	m, ok := mailbox.WaitFor(to, subject)
	if !ok {
		t.Fatalf("no email %q to %s; got %d emails", subject, to, len(mailbox.Messages()))
	}
	match := linkRe.FindStringSubmatch(m.Text)
	if match == nil {
		t.Fatalf("no link in %q: %s", subject, m.Text)
	}
	if !strings.Contains(m.HTML, `href="http://guardian.test`+strings.ReplaceAll(match[1], "&", "&amp;")+`"`) {
		t.Errorf("the HTML part of %q lacks the link", subject)
	}
	return match[1]
}

func setEmail(t *testing.T, username, address string) {
	t.Helper()
	testutil.Exec(t, `UPDATE account SET email = $2, email_verified_at = now() WHERE username = $1`, username, address)
}

func signupForm(br *browser, username, email, returnTo string) *http.Response {
	return br.postForm("/signup", url.Values{"csrf": {br.csrf()}, "username": {username}, "email": {email},
		"password": {"long-enough-pw-1"}, "password2": {"long-enough-pw-1"}, "return_to": {returnTo}})
}

func TestE2ESignUpWithAnEmailWaitsForItsConfirmation(t *testing.T) {
	newTestEnv(t)
	app, _ := testutil.CreateApp(t, "notes", testutil.AppOptions{FirstParty: true})
	_, challenge := newPKCE(t)
	returnTo := "/authorize?" + authParams{app: app, scope: "openid", state: "s", challenge: challenge}.values().Encode()
	testutil.CreateAccount(t, "zelda")
	setEmail(t, "zelda", "zelda@castle.example")

	br := newBrowser(t)
	if page := readBody(t, br.get("/signup")); !strings.Contains(page, `name="email"`) || !strings.Contains(page, "Optional.") {
		t.Fatal("the sign-up page has no optional email field")
	}
	for _, c := range []struct{ email, want string }{
		{"not-an-address", "Enter an email address"},
		{"ZELDA@castle.example", "already in use"},
	} {
		resp := signupForm(br, "link", c.email, returnTo)
		wantStatus(t, resp, http.StatusBadRequest)
		if body := readBody(t, resp); !strings.Contains(body, c.want) || !strings.Contains(body, `value="`+c.email+`"`) {
			t.Errorf("%s: the page lacks %q or the typed address", c.email, c.want)
		}
	}

	resp := signupForm(br, "link", "link@hyrule.example", returnTo)
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/signup/inbox" {
		t.Fatalf("after sign-up with an address: location %q", loc)
	}
	if br.cookie("guardian_session") != "" {
		t.Fatal("the account was signed in before its address was confirmed")
	}
	inbox := readBody(t, br.get("/signup/inbox"))
	if !strings.Contains(inbox, "Check your inbox") || !strings.Contains(inbox, "l•••@hyrule.example") {
		t.Errorf("the check-your-inbox page does not show the masked address: %.400s", inbox)
	}
	if strings.Contains(inbox, "link@hyrule.example") {
		t.Error("the check-your-inbox page shows the whole address")
	}
	first := linkIn(t, "link@hyrule.example", "Confirm your email address")
	if m, _ := mailbox.WaitFor("link@hyrule.example", "Confirm"); !strings.Contains(m.Text, "finish creating the account") {
		t.Error("the sign-up confirmation does not say what it is for")
	}

	// The account cannot sign in yet; the right password says why, a wrong one does not.
	other := newBrowser(t)
	resp = other.login("link", "long-enough-pw-1", "")
	wantStatus(t, resp, http.StatusForbidden)
	if body := readBody(t, resp); !strings.Contains(body, "Confirm your email address first") {
		t.Error("signing in to a waiting account does not ask for the confirmation")
	}
	resp = other.login("link", "wrong-password-123", "")
	wantStatus(t, resp, http.StatusUnauthorized)
	drain(resp)

	// Resend: a new link, and only the newest one works.
	resp = br.postForm("/signup/inbox", url.Values{"csrf": {br.csrf()}, "action": {"resend"}})
	wantStatus(t, resp, http.StatusOK)
	if body := readBody(t, resp); !strings.Contains(body, "We sent a new link") {
		t.Error("resending does not say so")
	}
	second := linkIn(t, "link@hyrule.example", "Confirm your email address")
	if second == first {
		t.Fatal("resending sent the same link")
	}
	if body := readBody(t, other.get(first)); !strings.Contains(body, "This link has expired") {
		t.Errorf("the replaced link still works: %.300s", body)
	}

	// Opened in the browser that signed up, the link signs in and continues to the app.
	resp = br.get(second)
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != returnTo {
		t.Fatalf("after confirming: location %q, want the app's sign-in", loc)
	}
	resp = br.get(returnTo)
	wantStatus(t, resp, http.StatusFound)
	drain(resp)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, app.RedirectURIs[0]+"?code=") {
		t.Errorf("the confirmed account was not signed in to the app: %q", loc)
	}
	if n := testutil.Count(t, `SELECT count(*) FROM account WHERE username = 'link' AND status = 'active'
		AND email = 'link@hyrule.example' AND email_verified_at IS NOT NULL`); n != 1 {
		t.Error("the account is not active with its confirmed address")
	}
	if body := readBody(t, br.get(second)); !strings.Contains(body, "already used") {
		t.Error("a used link must say so")
	}
	if br.cookie("guardian_signup") != "" {
		t.Error("the sign-up cookie outlived the sign-up")
	}
}

func TestE2EAConfirmationLinkOpenedElsewhereDoesNotSignIn(t *testing.T) {
	newTestEnv(t)
	br := newBrowser(t)
	resp := signupForm(br, "malon", "malon@ranch.example", "")
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	link := linkIn(t, "malon@ranch.example", "Confirm")

	// A mail scanner, or another device, opens the link: the address is confirmed, nobody is signed in.
	scanner := newBrowser(t)
	resp = scanner.get(link)
	wantStatus(t, resp, http.StatusOK)
	if body := readBody(t, resp); !strings.Contains(body, "Your account is ready. Sign in to continue.") {
		t.Errorf("confirming elsewhere: %.300s", body)
	}
	if scanner.cookie("guardian_session") != "" {
		t.Fatal("the link signed in a browser that did not sign up")
	}
	br.mustLoginWith("malon", "long-enough-pw-1")
}

func TestE2ETheFirstAccountToConfirmAnAddressGetsIt(t *testing.T) {
	newTestEnv(t)
	a, b := newBrowser(t), newBrowser(t)
	for _, s := range []struct {
		br   *browser
		user string
	}{{a, "saria"}, {b, "fado"}} {
		resp := signupForm(s.br, s.user, "kokiri@forest.example", "")
		wantStatus(t, resp, http.StatusSeeOther)
		drain(resp)
	}
	msgs := mailbox.Messages()
	if len(msgs) != 2 {
		t.Fatalf("%d emails, want 2", len(msgs))
	}
	var links []string
	for _, m := range msgs {
		links = append(links, linkRe.FindStringSubmatch(m.Text)[1])
	}
	// fado (the second sign-up) confirms first and gets the address.
	resp := b.get(links[1])
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	resp = a.get(links[0])
	wantStatus(t, resp, http.StatusOK)
	if body := readBody(t, resp); !strings.Contains(body, "This address can&#39;t be used") {
		t.Errorf("the second confirmation of an address: %.300s", body)
	}

	// The loser chooses another address on the check-your-inbox page.
	resp = a.postForm("/signup/inbox", url.Values{"csrf": {a.csrf()}, "action": {"change"}, "email": {"kokiri@forest.example"}})
	wantStatus(t, resp, http.StatusBadRequest)
	if body := readBody(t, resp); !strings.Contains(body, "already in use") {
		t.Error("changing to a taken address must be refused")
	}
	resp = a.postForm("/signup/inbox", url.Values{"csrf": {a.csrf()}, "action": {"change"}, "email": {"saria@forest.example"}})
	wantStatus(t, resp, http.StatusOK)
	if body := readBody(t, resp); !strings.Contains(body, "s•••@forest.example") {
		t.Error("the page does not show the new address")
	}
	resp = a.get(linkIn(t, "saria@forest.example", "Confirm"))
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if n := testutil.Count(t, `SELECT count(*) FROM account WHERE status = 'active' AND email LIKE '%@forest.example'`); n != 2 {
		t.Errorf("%d active accounts with their own address, want 2", n)
	}
}

func TestE2EPasswordResetByEmail(t *testing.T) {
	newTestEnv(t)
	acct := testutil.CreateAccount(t, "impa")
	setEmail(t, "impa", "impa@kakariko.example")
	testutil.CreateAccount(t, "noemail")

	// A signed-in session on another device ends with the reset.
	laptop := newBrowser(t)
	laptop.mustLogin("impa")

	br := newBrowser(t)
	if body := readBody(t, br.get("/login")); !strings.Contains(body, `href="/forgot"`) {
		t.Error("the sign-in page has no link to reset a password")
	}
	forgot := func(login string) string {
		resp := br.postForm("/forgot", url.Values{"csrf": {br.csrf()}, "username": {login}})
		wantStatus(t, resp, http.StatusOK)
		return readBody(t, resp)
	}
	// The answer is the same whether or not the account exists or has an address.
	answers := map[string]string{}
	for _, login := range []string{"nobody", "noemail", "IMPA@kakariko.example"} {
		answers[login] = forgot(login)
	}
	if answers["nobody"] != answers["noemail"] || answers["nobody"] != answers["IMPA@kakariko.example"] {
		t.Error("the forgot-password answer differs between accounts")
	}
	if !strings.Contains(answers["nobody"], "If the account has a confirmed email address, we have sent a link") {
		t.Errorf("forgot-password answer: %.300s", answers["nobody"])
	}
	link := linkIn(t, "impa@kakariko.example", "Reset your password")
	if n := len(mailbox.Messages()); n != 1 {
		t.Errorf("%d emails sent, want only the one to the account with an address", n)
	}

	page := readBody(t, br.get(link))
	if !strings.Contains(page, "Choose a new password") || !strings.Contains(page, "Two-factor still applies") {
		t.Fatalf("the reset page: %.300s", page)
	}
	token, _ := url.QueryUnescape(strings.TrimPrefix(link, "/reset?token="))
	post := func(p1, p2 string) *http.Response {
		return br.postForm("/reset", url.Values{"csrf": {br.csrf()}, "token": {token}, "password": {p1}, "password2": {p2}})
	}
	resp := post("new-password-123", "new-password-124")
	wantStatus(t, resp, http.StatusBadRequest)
	if body := readBody(t, resp); !strings.Contains(body, "match") {
		t.Error("mismatched passwords must be refused")
	}
	resp = post("new-password-123", "new-password-123")
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	if loc := resp.Header.Get("Location"); loc != "/login?reset=done" {
		t.Fatalf("after the reset: location %q", loc)
	}
	if body := readBody(t, br.get("/login?reset=done")); !strings.Contains(body, "Your password was changed") {
		t.Error("the sign-in page does not confirm the reset")
	}

	// The old password and the other sessions are gone; the notice went out.
	resp = br.login("impa", testutil.DefaultPassword, "")
	wantStatus(t, resp, http.StatusUnauthorized)
	drain(resp)
	resp = laptop.sendJSON("GET", "/api/v1/me", nil)
	wantStatus(t, resp, http.StatusUnauthorized)
	drain(resp)
	br.mustLoginWith("impa", "new-password-123")
	if _, ok := mailbox.WaitFor("impa@kakariko.example", "Your password was changed"); !ok {
		t.Error("no password-changed notice")
	}
	if n := testutil.Count(t, `SELECT count(*) FROM audit_log WHERE event_type = 'password.reset' AND actor_account_id = $1`, acct.ID); n != 1 {
		t.Error("the reset is not audited")
	}

	// The link works once.
	if body := readBody(t, br.get(link)); !strings.Contains(body, "This link has expired") {
		t.Error("a used reset link still shows the form")
	}
	resp = post("another-password-1", "another-password-1")
	wantStatus(t, resp, http.StatusOK)
	if body := readBody(t, resp); !strings.Contains(body, "This link has expired") {
		t.Error("a used reset link still changes the password")
	}
}

func TestE2EChangingTheEmailAddress(t *testing.T) {
	newTestEnv(t)
	testutil.CreateAccount(t, "rauru")
	setEmail(t, "rauru", "rauru@sky.example")
	testutil.CreateAccount(t, "sonia")
	setEmail(t, "sonia", "sonia@sky.example")
	br := newBrowser(t)
	br.mustLogin("rauru")

	br.call("PUT", "/api/v1/me/email", map[string]any{"email": "nope"}, 400)
	m := br.call("PUT", "/api/v1/me/email", map[string]any{"email": "Sonia@sky.example"}, 409)
	if m["error"] != "email_in_use" {
		t.Errorf("taken address: %v", m)
	}
	br.call("PUT", "/api/v1/me/email", map[string]any{"email": "rauru@temple.example"}, 202)
	notice, ok := mailbox.WaitFor("rauru@sky.example", "Your email address is being changed")
	if !ok || !strings.Contains(notice.Text, "r•••@temple.example") || strings.Contains(notice.Text, "rauru@temple.example") {
		t.Errorf("the old address got no (masked) notice: %q", notice.Text)
	}
	link := linkIn(t, "rauru@temple.example", "Confirm your email address")

	// Until the link is opened, the account keeps its address.
	if me := br.call("GET", "/api/v1/me", nil, 200); me["email"] != "rauru@sky.example" {
		t.Errorf("the address changed before confirmation: %v", me["email"])
	}
	resp := newBrowser(t).get(link)
	wantStatus(t, resp, http.StatusOK)
	if body := readBody(t, resp); !strings.Contains(body, "Email address confirmed") {
		t.Errorf("confirming a change: %.300s", body)
	}
	if me := br.call("GET", "/api/v1/me", nil, 200); me["email"] != "rauru@temple.example" || me["email_verified"] != true {
		t.Errorf("after confirming: %v %v", me["email"], me["email_verified"])
	}
}

func TestE2EEmailOffAndEmailRequired(t *testing.T) {
	newTestEnv(t)
	br := newBrowser(t)

	mail.Configure(nil, mail.Site{})
	t.Cleanup(func() { mail.Configure(mailbox, mail.Site{Name: "Test Guardian", Host: "guardian.test"}) })
	if page := readBody(t, br.get("/signup")); strings.Contains(page, `name="email"`) {
		t.Error("the sign-up page asks for an address although Guardian sends no email")
	}
	if page := readBody(t, br.get("/login")); strings.Contains(page, "Forgot password") {
		t.Error("the sign-in page offers a reset although Guardian sends no email")
	}
	resp := br.get("/forgot")
	wantStatus(t, resp, http.StatusNotFound)
	drain(resp)

	mail.Configure(mailbox, mail.Site{Name: "Test Guardian", Host: "guardian.test"})
	required := testConfig
	required.Mail.RequireEmail = true
	web.Configure(required)
	t.Cleanup(func() { web.Configure(testConfig) })
	resp = signupForm(br, "kass", "", "")
	wantStatus(t, resp, http.StatusBadRequest)
	if body := readBody(t, resp); !strings.Contains(body, "Enter your email address.") {
		t.Error("REQUIRE_EMAIL did not require an address")
	}
	resp = br.postJSON("/api/v1/signup", map[string]any{"username": "kass", "password": "long-enough-pw-1"})
	wantStatus(t, resp, http.StatusBadRequest)
	if m := decodeMap(t, resp); m["error"] != "email_required" {
		t.Errorf("API sign-up with REQUIRE_EMAIL: %v", m)
	}
}
