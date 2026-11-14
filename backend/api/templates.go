package api

import (
	"bytes"
	"html/template"
	"net/http"

	db "guardian/database"
)

type page struct {
	Title, Message, Error, CSRF, ReturnTo, Username, Req string
	App                                                  db.App
	Scopes                                               []db.Scope
	IDTokenHint, ClientID, PostLogoutRedirectURI, State  string
}

const pageTemplates = `
{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title>
<style>
body{font-family:system-ui,sans-serif;background:#f4f5f7;margin:0;display:grid;place-items:center;min-height:100vh;color:#1a1a1a}
main{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:min(24rem,92vw)}
h1{font-size:1.3rem;margin:0 0 1rem}label{display:block;margin:.8rem 0;font-size:.9rem}
input:not([type=hidden]){display:block;width:100%;box-sizing:border-box;padding:.55rem;margin-top:.25rem;border:1px solid #bbb;border-radius:6px;font-size:1rem}
button{padding:.6rem 1.1rem;border:0;border-radius:6px;background:#2455d8;color:#fff;font-size:1rem;cursor:pointer;margin-top:.5rem;margin-right:.4rem}
button.secondary{background:#e3e5e8;color:#1a1a1a}.error{color:#b00020}.app{display:flex;align-items:center;gap:.7rem;margin-bottom:1rem}
.app img{width:40px;height:40px;border-radius:8px}li{margin:.4rem 0}@media (prefers-color-scheme:dark){body{background:#16181c;color:#eee}main{background:#20242a}input:not([type=hidden]){background:#16181c;color:#eee;border-color:#555}button.secondary{background:#3a3f47;color:#eee}}
</style></head><body><main>{{end}}
{{define "foot"}}</main></body></html>{{end}}

{{define "login"}}{{template "head" .}}<h1>Sign in</h1>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/login">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="return_to" value="{{.ReturnTo}}">
<label>Username<input name="username" autocomplete="username" required autofocus></label>
<label>Password<input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button></form>{{template "foot"}}{{end}}

{{define "consent"}}{{template "head" .}}
<div class="app">{{if .App.LogoURL}}<img src="{{.App.LogoURL}}" alt="">{{end}}<h1>{{.App.PrettyName}} wants access</h1></div>
<p>Signed in as <strong>{{.Username}}</strong>. This will allow {{.App.PrettyName}} to:</p>
<ul>{{range .Scopes}}<li>{{.Description}}</li>{{end}}</ul>
<form method="post" action="/consent">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="req" value="{{.Req}}">
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny" class="secondary">Deny</button></form>{{template "foot"}}{{end}}

{{define "logout"}}{{template "head" .}}<h1>{{.Title}}</h1><p>{{.Message}}</p>
<form method="post" action="/logout">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="id_token_hint" value="{{.IDTokenHint}}">
<input type="hidden" name="client_id" value="{{.ClientID}}"><input type="hidden" name="post_logout_redirect_uri" value="{{.PostLogoutRedirectURI}}">
<input type="hidden" name="state" value="{{.State}}"><button type="submit">Sign out</button></form>{{template "foot"}}{{end}}

{{define "message"}}{{template "head" .}}<h1>{{.Title}}</h1><p>{{.Message}}</p>{{template "foot"}}{{end}}
`

var tmpl = template.Must(template.New("").Parse(pageTemplates))

func renderPage(w http.ResponseWriter, status int, name string, data page) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	// No form-action directive on purpose: some browsers apply it to the redirect after a POST,
	// which would block the redirect back to the client app.
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func renderMessage(w http.ResponseWriter, status int, title, message string) {
	renderPage(w, status, "message", page{Title: title, Message: message})
}
