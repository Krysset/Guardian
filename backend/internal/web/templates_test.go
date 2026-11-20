package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	db "guardian/internal/store"
)

const evil = `<script>alert(1)</script>"'>`

func render(t *testing.T, name string, data Page) string {
	t.Helper()
	rec := httptest.NewRecorder()
	Render(rec, 200, name, data)
	if rec.Code != 200 {
		t.Fatalf("%s: status %d: %s", name, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestEveryPageRendersAndEscapesUntrustedData(t *testing.T) {
	data := Page{
		Title: evil, Heading: evil, Message: evil, Error: evil, CSRF: "tok", ReturnTo: evil, Login: evil,
		FieldErrors: map[string]string{"username": evil, "password": evil, "password2": evil},
		Username:    evil, App: db.App{PrettyName: evil}, Scopes: []string{evil}, Req: evil,
		IDTokenHint: evil, ClientID: evil, PostLogoutRedirectURI: evil, State: evil,
		Notice: evil, Email: evil, Token: evil,
	}
	for name := range pages {
		body := render(t, name, data)
		if strings.Contains(body, "<script>alert") {
			t.Errorf("%s: unescaped <script> in output", name)
		}
		if !strings.Contains(body, "&lt;script&gt;") {
			t.Errorf("%s: untrusted text was not rendered (escaped)", name)
		}
	}
	for _, want := range []string{"login", "signup", "password", "consent", "noaccess", "signout", "signedout", "signedin", "error",
		"inbox", "result", "forgot", "reset"} {
		if pages[want] == nil {
			t.Errorf("page %q is missing", want)
		}
	}
}

func TestPagesHaveNoInlineStylesOrScripts(t *testing.T) {
	data := Page{CSRF: "tok", Heading: "h", Message: "m", Link: &Link{"Go", "/login"}, Error: "e", Username: "alice",
		App: db.App{PrettyName: "Billing", LogoURL: "https://x.test/l.png"}, Scopes: []string{"a"},
		FieldErrors: map[string]string{"username": "u", "password": "p", "password2": "p2"}}
	for name := range pages {
		body := render(t, name, data)
		for _, bad := range []string{"style=", "<style", "onclick", "javascript:"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q, which the Content-Security-Policy blocks", name, bad)
			}
		}
		if strings.Count(body, "<script") != 1 || !strings.Contains(body, `<script src="/static/guardian.js?v=`) {
			t.Errorf("%s: the only script must be /static/guardian.js", name)
		}
		if !strings.Contains(body, `href="/static/guardian.css?v=`) {
			t.Errorf("%s does not load the stylesheet", name)
		}
	}
}

func TestPagesSendSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	Error(rec, NotFound)
	if rec.Code != http.StatusNotFound {
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
	for _, directive := range []string{"default-src 'none'", "style-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP %q lacks %q", csp, directive)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Error("the CSP must not allow inline styles or scripts")
	}
	if strings.Contains(csp, "form-action") {
		t.Error("form-action must not be set: it would block the redirect back to client apps after POST")
	}
	if !strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type = %q", h.Get("Content-Type"))
	}
}

func TestErrorPagesNeverShowDetails(t *testing.T) {
	for kind, e := range errorPages {
		rec := httptest.NewRecorder()
		Error(rec, kind)
		if rec.Code != e.status {
			t.Errorf("%s: status %d, want %d", e.heading, rec.Code, e.status)
		}
		if !strings.Contains(rec.Body.String(), e.heading) {
			t.Errorf("%d: the page lacks its heading", kind)
		}
	}
}

func TestLoginPageStructure(t *testing.T) {
	body := render(t, "login", Page{Title: "Sign in", CSRF: "csrf-token-value", ReturnTo: "/authorize?x=1", Login: "alice"})
	for _, want := range []string{
		`action="/login"`, `method="post"`, `name="csrf" value="csrf-token-value"`, `name="return_to" value="/authorize?x=1"`,
		`type="password"`, `autocomplete="current-password"`, `autocomplete="username"`, `value="alice"`,
		`href="/signup?return_to=%2fauthorize%3fx%3d1"`, "Username or email",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("login page lacks %s", want)
		}
	}
	// Parts of later releases stay out until they work.
	for _, later := range []string{"Forgot password", "security key"} {
		if strings.Contains(body, later) {
			t.Errorf("login page shows %q, which is not built yet", later)
		}
	}
}

func TestSignupPageStructure(t *testing.T) {
	body := render(t, "signup", Page{CSRF: "tok", FieldErrors: map[string]string{"password2": "The passwords don't match."}})
	for _, want := range []string{`action="/signup"`, `name="username"`, `name="password"`, `name="password2"`,
		`name="website"`, `autocomplete="new-password"`, "The passwords don&#39;t match.", `aria-invalid="true"`,
		"only an administrator can reset", "hobby project", "nowhere else"} {
		if !strings.Contains(body, want) {
			t.Errorf("sign-up page lacks %q", want)
		}
	}
}

func TestConsentPageListsScopesAndEscapesHiddenRequest(t *testing.T) {
	body := render(t, "consent", Page{
		Title: "Allow", CSRF: "tok", Username: "alice", Req: `a=1&b="2"`, ReturnTo: "/authorize?a=1",
		App:    db.App{PrettyName: "Billing"},
		Scopes: ScopeLines("Billing", []db.Scope{{Name: "openid"}, {Name: "groups"}, {Name: "custom", Description: "Your invoices"}}),
	})
	for _, want := range []string{"Billing wants to use your Guardian account", "Who you are: your account id",
		"Your groups that are linked to Billing", "Your invoices", "alice", ">B<",
		`action="/consent"`, `value="allow"`, `value="deny"`, `&amp;`, `&#34;`, "Not you? Sign out"} {
		if !strings.Contains(body, want) {
			t.Errorf("consent page lacks %q", want)
		}
	}
	if strings.Contains(body, `value="a=1&b="`) {
		t.Error("hidden request field is not attribute-escaped")
	}
}

func TestScopeLinesPutTheStandardScopesFirst(t *testing.T) {
	got := ScopeLines("Billing", []db.Scope{{Name: "custom", Description: "Your invoices"}, {Name: "groups"},
		{Name: "email"}, {Name: "openid"}, {Name: "offline_access"}, {Name: "profile"}})
	want := []string{"Who you are: your account id", "Your name, username, picture, language and time zone",
		"Your email address", "Your groups that are linked to Billing", "Stay signed in while your Guardian session lasts",
		"Your invoices"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q", got)
	}
}

func TestSignedInPageOffersLogoutForm(t *testing.T) {
	body := render(t, "signedin", Page{Username: "alice", CSRF: "tok"})
	for _, want := range []string{`action="/logout"`, `name="csrf" value="tok"`, "alice"} {
		if !strings.Contains(body, want) {
			t.Errorf("signed-in page lacks %q", want)
		}
	}
}

func TestFooterLinksAreOptional(t *testing.T) {
	defer func() { footerLinks.HelpURL, footerLinks.PrivacyURL = "", "" }()
	if body := render(t, "signedout", Page{}); strings.Contains(body, ">Help<") || strings.Contains(body, ">Privacy<") {
		t.Error("footer links shown without addresses")
	}
	footerLinks.HelpURL, footerLinks.PrivacyURL = "https://example.com/help", "https://example.com/privacy"
	body := render(t, "signedout", Page{})
	if !strings.Contains(body, `href="https://example.com/help"`) || !strings.Contains(body, `href="https://example.com/privacy"`) {
		t.Error("footer links missing")
	}
}

func TestStaticFiles(t *testing.T) {
	for name, version := range assetVersions {
		rec := httptest.NewRecorder()
		serveStatic(rec, httptest.NewRequest("GET", "/static/"+name+"?v="+version, nil))
		if rec.Code != 200 || rec.Body.Len() == 0 {
			t.Errorf("%s: status %d", name, rec.Code)
		}
		if !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
			t.Errorf("%s: a versioned file must be cached long", name)
		}
		if rec.Header().Get("Content-Type") == "application/octet-stream" {
			t.Errorf("%s: no content type", name)
		}
	}
	rec := httptest.NewRecorder()
	serveStatic(rec, httptest.NewRequest("GET", "/static/guardian.css", nil))
	if strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Error("an unversioned request must not be cached for a year")
	}
	for _, p := range []string{"/static/../templates.go", "/static/nope.css", "/static/"} {
		rec := httptest.NewRecorder()
		serveStatic(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, rec.Code)
		}
	}
	for _, name := range []string{"guardian.css", "guardian.js", "background.jpg", "logo-mask.svg", "favicon.svg",
		"figtree-latin.woff2", "figtree-latin-ext.woff2", "figtree-OFL.txt"} {
		if assetVersions[name] == "" {
			t.Errorf("static file %s is missing", name)
		}
	}
}
