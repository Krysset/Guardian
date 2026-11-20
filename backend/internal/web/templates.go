package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"guardian/internal/config"
	"guardian/internal/mail"
	db "guardian/internal/store"
)

//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static
var staticFiles embed.FS

// Page is the data for the sign-in pages. Every field is escaped by html/template.
type Page struct {
	Title    string // the browser tab: "<Title> · Guardian"
	Heading  string // error pages
	Message  string // error pages
	Link     *Link  // error pages: the one way on, if any
	Error    string // a message above the form
	CSRF     string
	ReturnTo string // where to continue after this page (only ever an /authorize URL, see httpx.SafeReturnTo)

	Login       string            // what was typed as the username, kept after an error
	FieldErrors map[string]string // by input name

	Username string // the signed-in account
	App      db.App
	Scopes   []string // what the app will get, one line per scope
	Req      string   // the authorization request, carried through the consent form

	IDTokenHint, ClientID, PostLogoutRedirectURI, State string // the logout request, carried through its form

	Connected, Available []db.App // Home: the apps the user has signed in to, and the others they may use

	Notice string // a confirmation above the form ("We sent a new link.")
	Email  string // the email address typed at sign-up, or a masked address to show
	Token  string // the one-time link's token, carried through the reset form
	Icon   string // result pages: ok, warn or mail
	Change bool   // the check-inbox page: show the form to change the address
	Sent   bool   // the forgot-password page: the link was (or would have been) sent

	Recovery     bool         // S13: asking for a recovery code instead of an authenticator code
	QRCode       template.URL // S15: the QR code, a data: URI that html/template would otherwise refuse
	SecretGroups string       // S15: the secret in groups of four
	Codes        []string     // S16: the recovery codes, shown once
}

// Link is a button that leads somewhere.
type Link struct{ Label, Href string }

// field is the data of the "password" template.
type field struct{ ID, Autocomplete, Error, Hint string }

// footerLinks are the optional Help and Privacy links in the footer of every page.
var footerLinks struct{ HelpURL, PrivacyURL string }

// requireEmail makes an email address mandatory at sign-up (REQUIRE_EMAIL).
var requireEmail bool

// SendLogoutNotices delivers back-channel logouts. The oidc package sets it (web cannot import oidc).
var SendLogoutNotices = func([]db.LogoutNotice) {}

// Configure must be called once at startup, before serving. The configuration is already validated.
func Configure(cfg config.Config) {
	footerLinks.HelpURL = cfg.HelpURL
	footerLinks.PrivacyURL = cfg.PrivacyURL
	requireEmail = cfg.Mail.RequireEmail
}

// RequireEmail reports whether sign-up needs an email address.
func RequireEmail() bool { return requireEmail && mail.Enabled() }

// assetVersions maps each static file to a hash of its content. Pages link to /static/<name>?v=<hash>,
// so a file can be cached for a year and a new release still loads the new file.
var assetVersions = func() map[string]string {
	versions := map[string]string{}
	err := fs.WalkDir(staticFiles, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := staticFiles.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		versions[path.Base(p)] = hex.EncodeToString(sum[:6])
		return nil
	})
	if err != nil {
		panic(err)
	}
	return versions
}()

var funcs = template.FuncMap{
	"asset": func(name string) string {
		v, ok := assetVersions[name]
		if !ok {
			panic("unknown static file " + name)
		}
		return "/static/" + name + "?v=" + v
	},
	"footer": func() any { return footerLinks },
	// mail reports whether Guardian sends email: the email field, "Forgot password?" and resets need it.
	"mail":         mail.Enabled,
	"requireEmail": RequireEmail,
	"field": func(id, autocomplete, errText, hint string) field {
		return field{ID: id, Autocomplete: autocomplete, Error: errText, Hint: hint}
	},
	// initial is the letter shown in place of an app's logo.
	"initial": func(name string) string {
		r, _ := utf8.DecodeRuneInString(strings.TrimSpace(name))
		if r == utf8.RuneError {
			return "?"
		}
		return string(unicode.ToUpper(r))
	},
}

// pages holds one template set per page: the shared layout plus the page's own "content" (and "bar").
var pages = func() map[string]*template.Template {
	base := template.Must(template.New("").Funcs(funcs).ParseFS(templateFiles, "templates/layout.html"))
	files, err := fs.Glob(templateFiles, "templates/*.html")
	if err != nil {
		panic(err)
	}
	m := map[string]*template.Template{}
	for _, f := range files {
		name := strings.TrimSuffix(path.Base(f), ".html")
		if name == "layout" {
			continue
		}
		m[name] = template.Must(template.Must(base.Clone()).ParseFS(templateFiles, f))
	}
	return m
}()

// contentSecurityPolicy allows only Guardian's own styles and script. App logos may come from any https
// address. There is no form-action directive on purpose: some browsers apply it to the redirect after a
// POST, which would block the redirect back to the app.
const contentSecurityPolicy = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' https: data:; " +
	"font-src 'self'; frame-ancestors 'none'; base-uri 'none'"

// Render writes the named page with the headers every sign-in page needs.
func Render(w http.ResponseWriter, status int, name string, data Page) {
	t, ok := pages[name]
	var buf bytes.Buffer
	if !ok {
		slog.Error("unknown page template", "page", name)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		slog.Error("failed to render a page", "page", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// ErrorKind is one of the error pages (S9). They never show technical details.
type ErrorKind int

const (
	// BrokenLink: an app sent the browser here with a client or redirect address Guardian doesn't know.
	BrokenLink ErrorKind = iota
	// SessionExpired: the sign-in session ended halfway through a sign-in.
	SessionExpired
	// FormExpired: a form was posted without a valid CSRF token, usually because it was open too long.
	FormExpired
	// NotFound: nothing at this address.
	NotFound
	// ServerError: something failed on Guardian's side.
	ServerError
)

var errorPages = map[ErrorKind]struct {
	status           int
	heading, message string
	link             *Link
}{
	BrokenLink: {http.StatusBadRequest, "The sign-in link is broken",
		"The app sent you here with an address Guardian doesn't know. Tell whoever runs the app.", nil},
	SessionExpired: {http.StatusUnauthorized, "Your sign-in took too long",
		"Start again from the app you were signing in to.", nil},
	FormExpired: {http.StatusForbidden, "This form has expired",
		"Go back, reload the page and try again.", nil},
	NotFound: {http.StatusNotFound, "Page not found",
		"There's nothing at this address.", &Link{"Go to sign in", "/login"}},
	ServerError: {http.StatusInternalServerError, "Something went wrong",
		"It's not you, it's Guardian. Try again in a few minutes.", nil},
}

// Error renders one of the error pages with its status code.
func Error(w http.ResponseWriter, kind ErrorKind) {
	e := errorPages[kind]
	Render(w, e.status, "error", Page{Title: e.heading, Heading: e.heading, Message: e.message, Link: e.link})
}

// NotFoundHandler answers unknown addresses with the "Page not found" page.
func NotFoundHandler(w http.ResponseWriter, r *http.Request) { Error(w, NotFound) }

// ScopeLines describes what an app will get for each scope, one line each, in the words of the consent page.
// The standard scopes come first, in a fixed order; others follow in the order given.
func ScopeLines(appName string, scopes []db.Scope) []string {
	order := map[string]int{"openid": 1, "profile": 2, "email": 3, "groups": 4, "offline_access": 5}
	scopes = slices.Clone(scopes)
	slices.SortStableFunc(scopes, func(a, b db.Scope) int {
		ra, rb := order[a.Name], order[b.Name]
		if ra == 0 {
			ra = 99
		}
		if rb == 0 {
			rb = 99
		}
		return ra - rb
	})
	lines := make([]string, 0, len(scopes))
	for _, s := range scopes {
		switch s.Name {
		case "openid":
			lines = append(lines, "Who you are: your account id")
		case "profile":
			lines = append(lines, "Your name, username, picture, language and time zone")
		case "email":
			lines = append(lines, "Your email address")
		case "groups":
			lines = append(lines, "Your groups that are linked to "+appName)
		case "offline_access":
			lines = append(lines, "Stay signed in while your Guardian session lasts")
		default:
			lines = append(lines, s.Description)
		}
	}
	return lines
}

// serveStatic serves the files under static/. Requests with the current ?v= are cached for a year.
func serveStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	version, ok := assetVersions[name]
	if !ok {
		Error(w, NotFound)
		return
	}
	b, err := staticFiles.ReadFile("static/" + name)
	if err != nil {
		Error(w, NotFound)
		return
	}
	h := w.Header()
	ctype := mime.TypeByExtension(path.Ext(name))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	h.Set("Content-Type", ctype)
	h.Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Get("v") == version {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "public, max-age=3600")
	}
	if r.Method == http.MethodHead {
		return
	}
	w.Write(b)
}
