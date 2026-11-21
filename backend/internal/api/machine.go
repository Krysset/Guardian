package api

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	"guardian/internal/httpx"
	"guardian/internal/oidc"
	db "guardian/internal/store"
)

// The machine API is how an app reads, with its own credentials and no user involved, what it needs to
// know about its users: its linked groups, who is in them, and the accounts it may know about. It is
// read-only; all changes are made in Guardian.
//
// An app gets a token with the client_credentials grant and sends it as a Bearer token. oidc.VerifyClientToken
// checks it; a user's access token is never accepted.

type ctxKey string

const ctxMachineApp ctxKey = "machine-app"

func machineApp(r *http.Request) db.App {
	app, _ := r.Context().Value(ctxMachineApp).(db.App)
	return app
}

// machineRouter serves /api/v1/apps/self.
func machineRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(requireMachineToken)
	r.Get("/", machineSelf)
	r.Get("/groups", machineGroups)
	r.Get("/groups/{key}/members", machineGroupMembers)
	r.Get("/users/{sub}", machineUser)
	return r
}

// requireMachineToken accepts a client_credentials token for an app that is enabled and still has machine
// access. Both are checked on every request, so turning machine access off takes effect at once.
func requireMachineToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		unauthorized := func() {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			httpx.ErrorCode(w, http.StatusUnauthorized, "invalid_token", "The access token is missing, invalid or expired")
		}
		clientID, ok := oidc.VerifyClientToken(r.Header.Get("Authorization"))
		if !ok {
			unauthorized()
			return
		}
		app, err := db.GetAppByClientID(clientID)
		if err != nil || !app.Enabled || !slices.Contains(app.GrantTypes, "client_credentials") {
			unauthorized()
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxMachineApp, app)))
	})
}

// machineUserJSON is how an account is shown to an app: the claims the app's allowed scopes permit, and,
// if the app may use the groups scope, its groups among the app's linked groups.
func machineUserJSON(app db.App, acct db.Account) (map[string]any, error) {
	names, err := db.GetScopeClaims(app.Scopes)
	if err != nil {
		return nil, err
	}
	out := oidc.BuildClaims(acct, names)
	if slices.Contains(app.Scopes, "groups") {
		groups, err := db.AccountAppGroups(acct.ID, app.ID)
		if err != nil {
			return nil, err
		}
		out["groups"] = groups
	}
	return out, nil
}

func machineSelf(w http.ResponseWriter, r *http.Request) {
	app := machineApp(r)
	httpx.JSON(w, http.StatusOK, map[string]any{
		"client_id": app.ClientID, "name": app.Name, "pretty_name": app.PrettyName,
		"access_rule": app.AccessRule, "scopes": app.Scopes,
	})
}

func machineGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := db.ListAppGroups(machineApp(r).ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Failed to list groups")
		return
	}
	httpx.JSON(w, http.StatusOK, list(groups))
}

func machineGroupMembers(w http.ResponseWriter, r *http.Request) {
	app := machineApp(r)
	members, err := db.ListAppGroupMembers(app.ID, chi.URLParam(r, "key"))
	if errors.Is(err, db.ErrGroupNotFound) {
		httpx.Error(w, http.StatusNotFound, "No such group linked to this app")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Failed to list members")
		return
	}
	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		u, err := machineUserJSON(app, m)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "Failed to list members")
			return
		}
		out = append(out, u)
	}
	httpx.JSON(w, http.StatusOK, list(out))
}

// machineUser looks up one account by its sub. Accounts the app may not know about get the same 404 as
// accounts that do not exist, so the endpoint cannot be used to find out who has an account.
func machineUser(w http.ResponseWriter, r *http.Request) {
	app := machineApp(r)
	sub := chi.URLParam(r, "sub")
	notFound := func() { httpx.Error(w, http.StatusNotFound, "User not found") }
	ok, err := db.AppMayKnowAccount(app.ID, sub)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !ok {
		notFound()
		return
	}
	acct, err := db.GetAccount(sub)
	if err != nil || acct.Status != "active" {
		notFound()
		return
	}
	u, err := machineUserJSON(app, acct)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.JSON(w, http.StatusOK, u)
}
