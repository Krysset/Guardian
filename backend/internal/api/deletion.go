package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"guardian/internal/httpx"
	"guardian/internal/oidc"
	db "guardian/internal/store"
)

// Deleting accounts (U15, A7, A8) and "download my data" (U14). A deleted account is disabled at once and
// erased after the grace period (DELETION_GRACE_PERIOD); an administrator can restore it until then, or
// erase it at once.

// deleteMe deletes the signed-in user's own account. A protected change, confirmed by typing the username.
func deleteMe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	acct, err := db.GetAccount(httpx.AccountID(r))
	if err != nil {
		accountFail(w, err)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(req.Username), acct.Username) {
		httpx.Error(w, http.StatusBadRequest, "Type your username to confirm")
		return
	}
	if !httpx.RequireReauth(w, r) {
		return
	}
	notices, err := db.SoftDeleteAccount(acct.ID, acct.ID)
	if err != nil {
		accountFail(w, err)
		return
	}
	oidc.SendLogoutNotices(notices)
	httpx.ClearSessionCookie(w)
	d, _ := db.GetDeletedAccount(acct.ID)
	db.Audit("account.deleted", acct.ID, "", httpx.ClientIP(r), map[string]any{"target": acct.ID, "by": "self", "erase_after": d.EraseAfter})
	httpx.JSON(w, http.StatusOK, map[string]any{"erase_after": d.EraseAfter})
}

// exportMe is "download my data": a JSON file with everything Guardian holds about the account.
func exportMe(w http.ResponseWriter, r *http.Request) {
	data, err := db.ExportAccountData(httpx.AccountID(r))
	if err != nil {
		accountFail(w, err)
		return
	}
	db.Audit("account.exported", httpx.AccountID(r), "", httpx.ClientIP(r), nil)
	w.Header().Set("Content-Disposition", `attachment; filename="guardian-data-`+time.Now().UTC().Format("2006-01-02")+`.json"`)
	httpx.JSON(w, http.StatusOK, data)
}

// deleteAccount deletes someone else's account (A7). It waits out the grace period like a self-deletion.
func deleteAccount(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "account")
	if _, err := db.GetAccount(id); err != nil {
		accountFail(w, err)
		return
	}
	notices, err := db.SoftDeleteAccount(id, httpx.AccountID(r))
	if err != nil {
		accountFail(w, err)
		return
	}
	oidc.SendLogoutNotices(notices) // apps that support back-channel logout drop the user at once
	d, _ := db.GetDeletedAccount(id)
	db.Audit("account.deleted", httpx.AccountID(r), "", httpx.ClientIP(r), map[string]any{"target": id, "erase_after": d.EraseAfter})
	httpx.NoContent(w)
}

// listDeletedAccounts is AD12: accounts in their grace period.
func listDeletedAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := db.ListDeletedAccounts()
	if err != nil {
		accountFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, list(accounts))
}

// restoreAccount brings a deleted account back during its grace period (A8).
func restoreAccount(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "account")
	groups, err := db.RestoreAccount(id)
	if err != nil {
		accountFail(w, err)
		return
	}
	db.Audit("account.restored", httpx.AccountID(r), "", httpx.ClientIP(r), map[string]any{"target": id, "groups_restored": groups})
	acct, err := db.GetAccount(id)
	if err != nil {
		accountFail(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, acct)
}

// eraseAccount erases an account at once ("erase now"), confirmed by typing its username. An account that
// is not deleted yet is deleted first, with the same refusal for the last administrator.
func eraseAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	id := chi.URLParam(r, "account")
	username := ""
	if d, err := db.GetDeletedAccount(id); err == nil {
		username = d.Username
	} else if acct, err := db.GetAccount(id); err == nil {
		username = acct.Username
	} else {
		accountFail(w, err)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(req.Username), username) {
		httpx.Error(w, http.StatusBadRequest, "Type the account's username to confirm")
		return
	}
	if _, err := db.GetDeletedAccount(id); err != nil {
		notices, err := db.SoftDeleteAccount(id, httpx.AccountID(r))
		if err != nil {
			accountFail(w, err)
			return
		}
		oidc.SendLogoutNotices(notices)
	}
	if err := db.EraseAccount(id); err != nil {
		accountFail(w, err)
		return
	}
	db.Audit("account.erased", httpx.AccountID(r), "", httpx.ClientIP(r), map[string]any{"target": id, "by": "admin"})
	httpx.NoContent(w)
}
