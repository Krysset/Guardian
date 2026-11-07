package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	db "guardian/database"
)

const evil = `<script>alert(1)</script>"'>`

func TestTemplatesEscapeUntrustedData(t *testing.T) {
	pages := []struct {
		name string
		data page
	}{
		{"login", page{Title: evil, Error: evil, CSRF: "tok", ReturnTo: evil}},
		{"consent", page{Title: evil, CSRF: "tok", Username: evil, Req: evil,
			App: db.App{PrettyName: evil, LogoURL: "https://x.test/l.png"}, Scopes: []db.Scope{{Name: "a", Description: evil}}}},
		{"logout", page{Title: evil, Message: evil, CSRF: "tok", IDTokenHint: evil, ClientID: evil, PostLogoutRedirectURI: evil, State: evil}},
		{"message", page{Title: evil, Message: evil}},
	}
	for _, p := range pages {
		rec := httptest.NewRecorder()
		renderPage(rec, 200, p.name, p.data)
		body := rec.Body.String()
		if strings.Contains(body, "<script") {
			t.Errorf("%s: unescaped <script> in output", p.name)
		}
		if !strings.Contains(body, "&lt;script&gt;") {
			t.Errorf("%s: untrusted text was not rendered (escaped)", p.name)
		}
	}
}

func TestPagesSendSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	renderMessage(rec, 418, "Title", "Message")
	if rec.Code != 418 {
		t.Errorf("status = %d", rec.Code)
	}
	h := rec.Header()
	want := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}
	for k, v := range want {
		if h.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, h.Get(k), v)
		}
	}
	csp := h.Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP %q lacks %q", csp, directive)
		}
	}
	if strings.Contains(csp, "form-action") {
		t.Error("form-action must not be set: it would block the redirect back to client apps after POST")
	}
	if !strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type = %q", h.Get("Content-Type"))
	}
}

func TestLoginPageStructure(t *testing.T) {
	rec := httptest.NewRecorder()
	renderPage(rec, 200, "login", page{Title: "Sign in", CSRF: "csrf-token-value", ReturnTo: "/authorize?x=1"})
	body := rec.Body.String()
	for _, want := range []string{
		`action="/login"`, `method="post"`, `name="csrf" value="csrf-token-value"`, `name="return_to" value="/authorize?x=1"`,
		`type="password"`, `autocomplete="current-password"`, `autocomplete="username"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("login page lacks %s", want)
		}
	}
}

func TestConsentPageListsScopesAndEscapesHiddenRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	renderPage(rec, 200, "consent", page{
		Title: "Authorize", CSRF: "tok", Username: "alice", Req: `a=1&b="2"`,
		App:    db.App{PrettyName: "Billing"},
		Scopes: []db.Scope{{Name: "email", Description: "Your email address"}, {Name: "openid", Description: "Verify your identity"}},
	})
	body := rec.Body.String()
	for _, want := range []string{"Billing wants access", "Your email address", "Verify your identity", "alice",
		`action="/consent"`, `value="allow"`, `value="deny"`, `&amp;`, `&#34;`} {
		if !strings.Contains(body, want) {
			t.Errorf("consent page lacks %q", want)
		}
	}
	if strings.Contains(body, `value="a=1&b="`) {
		t.Error("hidden request field is not attribute-escaped")
	}
}

func TestSignedInPageOffersLogoutForm(t *testing.T) {
	rec := httptest.NewRecorder()
	renderPage(rec, 200, "logout", page{Title: "Signed in", Message: "You are signed in as alice.", CSRF: "tok"})
	body := rec.Body.String()
	for _, want := range []string{`action="/logout"`, `name="csrf" value="tok"`, "You are signed in as alice."} {
		if !strings.Contains(body, want) {
			t.Errorf("logout page lacks %q", want)
		}
	}
}
