package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"guardian/internal/httpx"
	"guardian/internal/mail"
	"guardian/internal/oidc"
	db "guardian/internal/store"
	"guardian/internal/web"
)

// The routes behind Home and the account area (0.4): the user's sessions, connected apps, groups and email
// address. Sessions and connected apps are protected changes (httpx.RequireReauth).

// cancelPendingEmail voids the links for a new address; the account keeps its current one.
func cancelPendingEmail(w http.ResponseWriter, r *http.Request) {
	id := httpx.AccountID(r)
	found, err := db.CancelPendingEmail(id)
	if err != nil {
		accountFail(w, err)
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "No address is waiting for confirmation")
		return
	}
	db.Audit("email.change_cancelled", id, "", httpx.ClientIP(r), nil)
	httpx.NoContent(w)
}

// removeMyEmail removes the account's address. A protected change; refused when sign-up requires an
// address (REQUIRE_EMAIL), since the account would then be one that could not be created.
func removeMyEmail(w http.ResponseWriter, r *http.Request) {
	if web.RequireEmail() {
		httpx.ErrorCode(w, http.StatusConflict, "email_required", "This Guardian requires an email address on every account")
		return
	}
	if !httpx.RequireReauth(w, r) {
		return
	}
	id := httpx.AccountID(r)
	if _, err := db.RemoveEmail(id); err != nil {
		accountFail(w, err)
		return
	}
	db.Audit("email.removed", id, "", httpx.ClientIP(r), nil)
	httpx.NoContent(w)
}

// mySession is a session as its owner sees it: the browser and system read from the user agent, and
// whether it is the session making this request.
type mySession struct {
	db.SessionInfo
	Browser string `json:"browser"`
	Current bool   `json:"current"`
}

func listMySessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := db.ListLiveSessions(httpx.AccountID(r), httpx.SessionIdleTimeout)
	if err != nil {
		accountFail(w, err)
		return
	}
	out := make([]mySession, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, mySession{SessionInfo: s, Browser: describeUserAgent(s.UserAgent), Current: s.ID == httpx.SessionID(r)})
	}
	httpx.JSON(w, http.StatusOK, list(out))
}

// endMySession signs one of the user's sessions out. Ending the current one is signing out.
func endMySession(w http.ResponseWriter, r *http.Request) {
	if !httpx.RequireReauth(w, r) {
		return
	}
	id := httpx.AccountID(r)
	sessionID := chi.URLParam(r, "session")
	notices, err := db.RevokeOwnSession(id, sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.Error(w, http.StatusNotFound, "Session not found")
		return
	}
	if err != nil {
		accountFail(w, err)
		return
	}
	oidc.SendLogoutNotices(notices)
	db.Audit("session.revoked", id, "", httpx.ClientIP(r), map[string]any{"session": sessionID, "apps_notified": len(notices)})
	if sessionID == httpx.SessionID(r) {
		httpx.ClearSessionCookie(w)
	}
	httpx.NoContent(w)
}

// endMyOtherSessions is "Sign out everywhere else": every session but this one ends.
func endMyOtherSessions(w http.ResponseWriter, r *http.Request) {
	if !httpx.RequireReauth(w, r) {
		return
	}
	id := httpx.AccountID(r)
	notices, err := db.RevokeOtherSessions(id, httpx.SessionID(r))
	if err != nil {
		accountFail(w, err)
		return
	}
	oidc.SendLogoutNotices(notices)
	db.Audit("session.revoked_others", id, "", httpx.ClientIP(r), map[string]any{"apps_notified": len(notices)})
	httpx.NoContent(w)
}

// connectedApp adds what the app can see, in the words of the consent page.
type connectedApp struct {
	db.ConnectedApp
	Sees []string `json:"sees"`
}

func listMyApps(w http.ResponseWriter, r *http.Request) {
	apps, err := db.ConnectedApps(httpx.AccountID(r))
	if err != nil {
		accountFail(w, err)
		return
	}
	out := make([]connectedApp, 0, len(apps))
	for _, a := range apps {
		scopes, err := db.GetScopes(a.Scopes)
		if err != nil {
			accountFail(w, err)
			return
		}
		out = append(out, connectedApp{ConnectedApp: a, Sees: web.ScopeLines(a.DisplayName, scopes)})
	}
	httpx.JSON(w, http.StatusOK, list(out))
}

// removeMyApp is "Remove access": the app loses the consent, its refresh tokens and the right to look the
// user up, and is told with back-channel logout. Signing in to it again asks for consent again.
func removeMyApp(w http.ResponseWriter, r *http.Request) {
	if !httpx.RequireReauth(w, r) {
		return
	}
	id := httpx.AccountID(r)
	appID := chi.URLParam(r, "app")
	notices, err := db.RemoveAppAccess(id, appID)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.Error(w, http.StatusNotFound, "You have not used this app")
		return
	}
	if err != nil {
		accountFail(w, err)
		return
	}
	oidc.SendLogoutNotices(notices)
	db.Audit("app.access_removed", id, appID, httpx.ClientIP(r), map[string]any{"apps_notified": len(notices)})
	httpx.NoContent(w)
}

// homeApp is an app on Home: enough to show it and open it, nothing about its configuration.
type homeApp struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	LogoURL     string `json:"logo_url,omitempty"`
	HomepageURL string `json:"homepage_url"`
}

// getHome returns what Home shows: this Guardian's name, the apps the user has signed in to, and the ones
// they may use but have not yet. Only enabled apps with a homepage are listed.
func getHome(w http.ResponseWriter, r *http.Request) {
	apps, err := db.AppsForHome(httpx.AccountID(r))
	if err != nil {
		slog.Error("failed to list the apps for Home", "error", err)
		httpx.Error(w, http.StatusInternalServerError, "Request failed")
		return
	}
	connected, available := []homeApp{}, []homeApp{}
	for _, a := range apps {
		h := homeApp{ID: a.App.ID, DisplayName: a.App.PrettyName, Description: a.App.Description,
			LogoURL: a.App.LogoURL, HomepageURL: a.App.HomepageURL}
		if a.Connected {
			connected = append(connected, h)
		} else {
			available = append(available, h)
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"site_name": mail.SiteName(), "connected": connected, "available": available})
}

func listMyGroups(w http.ResponseWriter, r *http.Request) {
	id := httpx.AccountID(r)
	member, err := db.MyGroups(id)
	if err != nil {
		accountFail(w, err)
		return
	}
	managed, err := db.ManagedGroups(id)
	if err != nil {
		accountFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"member_of": member, "manages": managed})
}

// addGroupMemberByLogin adds the account with this exact username or email address. Owners use it: they
// never search accounts, so the only answers are "added" and "No user found".
func addGroupMemberByLogin(w http.ResponseWriter, r *http.Request) {
	group, via, ok := groupAccess(w, r)
	if !ok {
		return
	}
	var req struct {
		Login     string     `json:"login"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if req.Login == "" || len(req.Login) > 254 {
		httpx.Error(w, http.StatusBadRequest, "login must be a username or an email address")
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		httpx.Error(w, http.StatusBadRequest, "expires_at must be in the future")
		return
	}
	member, _, err := db.GetAccountForLogin(req.Login)
	if err != nil || member.Status != "active" {
		httpx.Error(w, http.StatusNotFound, "No user found")
		return
	}
	if err := db.AddGroupMember(group.ID, member.ID, httpx.AccountID(r), req.ExpiresAt); err != nil {
		groupFail(w, err)
		return
	}
	db.Audit("group.member_added", httpx.AccountID(r), "", httpx.ClientIP(r),
		map[string]any{"group": group.ID, "key": group.Key, "account": member.ID, "via": via, "expires_at": req.ExpiresAt})
	httpx.JSON(w, http.StatusOK, map[string]string{"account_id": member.ID, "username": member.Username})
}
