package e2e

import (
	"bufio"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"guardian/internal/testutil"
)

// scrape reads /metrics into a map from series ("name{label="value",...}", labels in Prometheus' order) to
// value.
func scrape(t *testing.T) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	sc := bufio.NewScanner(strings.NewReader(readBody(t, mustGet(t, intSrv.URL+"/metrics"))))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			t.Fatalf("bad metrics line %q", line)
		}
		out[line[:i]] = v
	}
	return out
}

// Covers: P6
func TestE2EMetricsCountHowNotWho(t *testing.T) {
	testutil.Reset(t)
	alice := testutil.CreateAccount(t, "alice")
	bob := testutil.CreateAccount(t, "bob")
	testutil.EnableTOTP(t, bob.ID)
	billing, secret := testutil.CreateApp(t, "billing", testutil.AppOptions{FirstParty: true})
	closed, _ := testutil.CreateApp(t, "closed", testutil.AppOptions{FirstParty: true, AccessRule: "groups"})
	before := scrape(t)

	// Sign-ins by method, and into the app.
	tok := newBrowser(t).signIn(billing, secret, "alice", "openid")
	refreshed(t, billing, secret, tok.Refresh)
	refreshRefused(t, billing, secret, "not-a-token")
	if status, _ := refreshRequest(t, billing, "wrong-secret", tok.Refresh); status != http.StatusUnauthorized {
		t.Errorf("a wrong secret got %d", status)
	}
	if status, _ := refreshRequest(t, billing, "", tok.Refresh); status != http.StatusUnauthorized {
		t.Errorf("a missing secret got %d", status)
	}
	newBrowser(t).mustLogin("bob")

	// Failures: why, never who.
	br := newBrowser(t)
	drain(br.login("alice", "wrong-password-1", ""))
	drain(br.login("nobody-here", "wrong-password-1", ""))
	drain(br.postForm("/login", url.Values{"username": {"alice"}, "password": {"x"}})) // no form token
	r := br.sendJSON("PATCH", "/api/v1/me", map[string]any{}, "Origin", "https://evil.test")
	wantStatus(t, r, http.StatusForbidden)
	drain(r)

	// Not in any of the app's groups.
	br.mustLogin("alice")
	_, challenge := newPKCE(t)
	r = br.get("/authorize?" + authParams{app: closed, state: "s", challenge: challenge}.values().Encode())
	wantStatus(t, r, http.StatusForbidden)
	drain(r)

	after := scrape(t)
	for series, want := range map[string]float64{
		`guardian_logins_total{method="password"}`:                                                          2,
		`guardian_logins_total{method="password_and_code"}`:                                                 1,
		`guardian_login_failures_total{factor="password",reason="wrong_password"}`:                          1,
		`guardian_login_failures_total{factor="password",reason="unknown_account"}`:                         1,
		`guardian_csrf_refusals_total{check="form"}`:                                                        1,
		`guardian_csrf_refusals_total{check="origin"}`:                                                      1,
		`guardian_app_signins_total{app="billing"}`:                                                         1,
		`guardian_app_access_denied_total{app="closed"}`:                                                    1,
		`guardian_tokens_issued_total{app="billing",grant="authorization_code"}`:                            1,
		`guardian_tokens_issued_total{app="billing",grant="refresh_token"}`:                                 1,
		`guardian_token_refusals_total{app="billing",grant="refresh_token",reason="unknown_refresh_token"}`: 1,
		`guardian_token_refusals_total{app="billing",grant="refresh_token",reason="wrong_secret"}`:          2,
	} {
		if got := after[series] - before[series]; got != want {
			t.Errorf("%s went up by %v, want %v", series, got, want)
		}
	}

	// The state of the installation, from the database.
	for _, series := range []string{
		`guardian_state_metrics_up`, `guardian_sessions`, `guardian_app_sessions{app="billing"}`,
		`guardian_accounts{status="active"}`, `guardian_accounts_second_factor{factor="none"}`,
		`guardian_admins_without_second_factor`, `guardian_apps{state="enabled"}`, `guardian_groups{kind="shared"}`,
		`guardian_signing_key_activated_timestamp_seconds`, `guardian_signing_key_rotation_due_timestamp_seconds`,
		`guardian_mail_queue_depth`, `guardian_signups_total{result="confirmed"}`,
		`guardian_passkey_clone_warnings_total`,
	} {
		if _, ok := after[series]; !ok {
			t.Errorf("/metrics lacks %s", series)
		}
	}
	if after[`guardian_state_metrics_up`] != 1 {
		t.Error("the database counts could not be read")
	}

	// Nothing that points to a person or to a raw request value ever becomes part of a series.
	for series := range after {
		for _, leak := range []string{"alice", "bob", "nobody-here", alice.ID, bob.ID, billing.ClientID, "evil.test", "not-a-token"} {
			if strings.Contains(series, leak) {
				t.Errorf("%q leaked into %s", leak, series)
			}
		}
	}
}
