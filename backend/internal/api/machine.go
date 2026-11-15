package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"guardian/internal/auth"
	db "guardian/internal/store"
)

// The machine API is how an app reads, with its own credentials and no user involved, what it needs to
// know about its users: its linked groups, who is in them, and the accounts it may know about. It is
// read-only; all changes are made in Guardian.
//
// An app gets a token with the client_credentials grant and sends it as a Bearer token. The token's
// audience is Guardian itself, so a user's access token (whose audience is the app) is never accepted.

// machineAudience is the audience of client_credentials tokens: they are for Guardian's own API.
func machineAudience() string { return Issuer }

type ctxKey string

const ctxMachineApp ctxKey = "machine-app"

func machineApp(r *http.Request) db.App {
	app, _ := r.Context().Value(ctxMachineApp).(db.App)
	return app
}

// GetMachineSubrouter serves /api/v1/apps/self.
func GetMachineSubrouter() *chi.Mux {
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
			RespondWithError(w, http.StatusUnauthorized, "invalid_token")
		}
		h := r.Header.Get("Authorization")
		if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
			unauthorized()
			return
		}
		claims := jwt.MapClaims{}
		tok, err := jwt.ParseWithClaims(strings.TrimSpace(h[7:]), claims, signingKeys.Keyfunc,
			jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(Issuer), jwt.WithAudience(machineAudience()),
			jwt.WithExpirationRequired())
		if err != nil || !tok.Valid {
			unauthorized()
			return
		}
		if typ, _ := tok.Header["typ"].(string); typ != accessTokenType {
			unauthorized()
			return
		}
		clientID, _ := claims["client_id"].(string)
		if sub, _ := claims["sub"].(string); sub != clientID || claims["sid"] != nil {
			unauthorized() // only tokens an app got for itself, never one issued for a user
			return
		}
		app, err := db.GetAppByClientID(clientID)
		if err != nil || !app.Enabled || !contains(app.GrantTypes, "client_credentials") {
			unauthorized()
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxMachineApp, app)))
	})
}

// issueClientToken answers a client_credentials request: a token for the app itself, for the machine API.
func issueClientToken(w http.ResponseWriter, app db.App) {
	const grant = "client_credentials"
	if app.ClientType != "confidential" {
		refuse(w, grant, http.StatusUnauthorized, "invalid_client", "Only apps with a secret can get tokens of their own")
		return
	}
	jti, err := auth.RandomToken(16)
	if err != nil {
		refuse(w, grant, http.StatusInternalServerError, "server_error", "")
		return
	}
	now := time.Now()
	ttl := time.Duration(app.AccessTokenTTL) * time.Second
	token, err := signingKeys.Sign(jwt.MapClaims{
		"iss": Issuer, "sub": app.ClientID, "aud": machineAudience(), "client_id": app.ClientID,
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": jti,
	}, accessTokenType)
	if err != nil {
		refuse(w, grant, http.StatusInternalServerError, "server_error", "")
		return
	}
	tokenRequests.WithLabelValues(grant, "issued").Inc()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	RespondWithJSON(w, http.StatusOK, map[string]any{
		"access_token": token, "token_type": "Bearer", "expires_in": int(ttl.Seconds()),
	})
}

// machineUserJSON is how an account is shown to an app: the claims the app's allowed scopes permit, and,
// if the app may use the groups scope, its groups among the app's linked groups.
func machineUserJSON(app db.App, acct db.Account) (map[string]any, error) {
	names, err := db.GetScopeClaims(app.Scopes)
	if err != nil {
		return nil, err
	}
	out := buildClaims(acct, names)
	if contains(app.Scopes, "groups") {
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
	RespondWithJSON(w, http.StatusOK, map[string]any{
		"client_id": app.ClientID, "name": app.Name, "pretty_name": app.PrettyName,
		"access_rule": app.AccessRule, "scopes": app.Scopes,
	})
}

func machineGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := db.ListAppGroups(machineApp(r).ID)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Failed to list groups")
		return
	}
	RespondWithJSON(w, http.StatusOK, groups)
}

func machineGroupMembers(w http.ResponseWriter, r *http.Request) {
	app := machineApp(r)
	members, err := db.ListAppGroupMembers(app.ID, chi.URLParam(r, "key"))
	if errors.Is(err, db.ErrGroupNotFound) {
		RespondWithError(w, http.StatusNotFound, "No such group linked to this app")
		return
	}
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Failed to list members")
		return
	}
	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		u, err := machineUserJSON(app, m)
		if err != nil {
			RespondWithError(w, http.StatusInternalServerError, "Failed to list members")
			return
		}
		out = append(out, u)
	}
	RespondWithJSON(w, http.StatusOK, out)
}

// machineUser looks up one account by its sub. Accounts the app may not know about get the same 404 as
// accounts that do not exist, so the endpoint cannot be used to find out who has an account.
func machineUser(w http.ResponseWriter, r *http.Request) {
	app := machineApp(r)
	sub := chi.URLParam(r, "sub")
	notFound := func() { RespondWithError(w, http.StatusNotFound, "User not found") }
	ok, err := db.AppMayKnowAccount(app.ID, sub)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Internal Server Error")
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
		RespondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	RespondWithJSON(w, http.StatusOK, u)
}
