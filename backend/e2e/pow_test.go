package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"guardian/internal/testutil"
)

// The forms bots like ask the browser to solve a puzzle: sign-up and forgot-password always, sign-in once
// an address has failed a few times. Without an answer (no JavaScript), the page says why; a wrong or
// reused answer is refused; the API's sign-up takes a puzzle of its own.
//
// Covers: V9
func TestE2EProofOfWorkOnTheFormsBotsLike(t *testing.T) {
	newTestEnv(t)
	testutil.CreateAccount(t, "riju")
	br := newBrowser(t)
	before := scrape(t)

	// Sign-up: no answer, a wrong one, a good one, and the good one again.
	form := func(username string) url.Values {
		return url.Values{"csrf": {br.csrf()}, "username": {username}, "password": {"long-enough-pw-1"}, "password2": {"long-enough-pw-1"}}
	}
	page := readBody(t, br.get("/signup"))
	if !strings.Contains(page, `name="pow"`) || !strings.Contains(page, "<noscript>") {
		t.Fatal("the sign-up page carries no puzzle")
	}
	v := form("nojs")
	v.Set("pow", "-")
	resp := br.postForm("/signup", v)
	if body := readBody(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "needs JavaScript") {
		t.Errorf("sign-up without an answer: %d", resp.StatusCode)
	}
	token, number, _ := br.solvePage("/signup")
	v = form("wrong")
	v.Set("pow", token)
	v.Set("pow_number", number+"1")
	resp = br.postForm("/signup", v)
	if body := readBody(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "failed or took too long") {
		t.Errorf("sign-up with a wrong answer: %d", resp.StatusCode)
	}
	v = form("tulin")
	v.Set("pow", token)
	v.Set("pow_number", number)
	resp = br.postForm("/signup", v)
	wantStatus(t, resp, http.StatusSeeOther)
	drain(resp)
	again := newBrowser(t)
	v = url.Values{"csrf": {again.csrf()}, "username": {"tulin2"}, "password": {"long-enough-pw-1"}, "password2": {"long-enough-pw-1"},
		"pow": {token}, "pow_number": {number}}
	resp = again.postForm("/signup", v)
	wantStatus(t, resp, http.StatusBadRequest) // each answer counts once
	drain(resp)
	if n := testutil.Count(t, `SELECT count(*) FROM account WHERE username IN ('nojs', 'wrong', 'tulin2')`); n != 0 {
		t.Errorf("%d accounts were made without a good answer", n)
	}

	// Forgot-password needs one too.
	resp = br.postForm("/forgot", url.Values{"csrf": {br.csrf()}, "username": {"riju"}, "pow": {"-"}})
	wantStatus(t, resp, http.StatusBadRequest)
	drain(resp)

	// Sign-in: no puzzle until the address has failed three times.
	signer := newBrowser(t)
	if strings.Contains(readBody(t, signer.get("/login")), `name="pow"`) {
		t.Error("a first sign-in carries a puzzle")
	}
	for i := 0; i < 3; i++ {
		drain(signer.postForm("/login", url.Values{"csrf": {signer.csrf()}, "username": {"riju"}, "password": {"wrong-password-1"}}))
	}
	if !strings.Contains(readBody(t, signer.get("/login")), `name="pow"`) {
		t.Fatal("no puzzle after three failures")
	}
	resp = signer.postForm("/login", url.Values{"csrf": {signer.csrf()}, "username": {"riju"}, "password": {testutil.DefaultPassword}, "pow": {"-"}})
	if body := readBody(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "quick check") {
		t.Errorf("sign-in without an answer after failures: %d", resp.StatusCode)
	}
	resp = signer.postForm("/login", url.Values{"csrf": {signer.csrf()}, "username": {"riju"}, "password": {testutil.DefaultPassword}})
	wantStatus(t, resp, http.StatusSeeOther) // with the answer, the right password signs in
	drain(resp)

	// The API's sign-up.
	raw := newBrowser(t)
	resp = raw.sendJSON("POST", "/api/v1/signup", map[string]any{"username": "bot", "password": "long-enough-pw-1", "pow_token": "x", "pow_number": "1"})
	wantStatus(t, resp, http.StatusBadRequest)
	if body := decodeMap(t, resp); body["error"] != "pow_failed" {
		t.Errorf("API sign-up without a puzzle: %v", body)
	}
	raw.call("POST", "/api/v1/signup", map[string]any{"username": "kotts", "password": "long-enough-pw-1"}, http.StatusCreated) // solved by the helper

	after := scrape(t)
	for series, want := range map[string]float64{
		`guardian_pow_checks_total{form="signup",result="missing"}`:    1,
		`guardian_pow_checks_total{form="signup",result="invalid"}`:    2,
		`guardian_pow_checks_total{form="signup",result="passed"}`:     1,
		`guardian_pow_checks_total{form="forgot",result="missing"}`:    1,
		`guardian_pow_checks_total{form="login",result="missing"}`:     1,
		`guardian_pow_checks_total{form="login",result="passed"}`:      1,
		`guardian_pow_checks_total{form="api_signup",result="passed"}`: 1,
	} {
		if got := after[series] - before[series]; got != want {
			t.Errorf("%s went up by %v, want %v", series, got, want)
		}
	}
}
