package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"guardian/internal/httpx"
	"guardian/internal/oidc"
	db "guardian/internal/store"
)

// getOverview returns the admin area's figures (AD13). None of them identifies a person.
func getOverview(w http.ResponseWriter, r *http.Request) {
	o, err := db.GetOverview()
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Failed to compute the overview")
		return
	}
	httpx.JSON(w, http.StatusOK, o)
}

// endAccountSessions signs an account out everywhere without disabling it: every session and refresh token
// ends, and apps with back-channel logout are told. Administrators never see the sessions themselves.
func endAccountSessions(w http.ResponseWriter, r *http.Request) {
	acct, err := db.GetAccount(chi.URLParam(r, "account"))
	if errors.Is(err, sql.ErrNoRows) {
		httpx.Error(w, http.StatusNotFound, "Account not found")
		return
	}
	if err != nil {
		accountFail(w, err)
		return
	}
	notices, err := db.RevokeOtherSessions(acct.ID, "")
	if err != nil {
		accountFail(w, err)
		return
	}
	oidc.SendLogoutNotices(notices)
	db.Audit("account.signed_out_everywhere", httpx.AccountID(r), "", httpx.ClientIP(r),
		map[string]any{"account": acct.ID, "apps_notified": len(notices)})
	httpx.NoContent(w)
}

// listScopes returns the standard scopes an app may be allowed, with what each releases.
func listScopes(w http.ResponseWriter, r *http.Request) {
	scopes, err := db.ListScopes()
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Failed to list the scopes")
		return
	}
	httpx.JSON(w, http.StatusOK, list(scopes))
}
