// Package api is Guardian's JSON API, /api/v1. docs/openapi.yaml describes every route, and a test keeps
// the two in step.
//
// Browser routes use the session cookie and are protected against cross-site requests by the Origin
// check. The machine API (/api/v1/apps/self) uses Bearer client tokens instead.
//
// Conventions: snake_case JSON; unknown request fields are refused; lists are {"items": [...]}, with
// "next_cursor" when they are paged; errors are {"error": "<code>", "message": "<text>"}; a successful
// DELETE, or a change with nothing to return, answers 204.
package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"guardian/internal/httpx"
)

// Router serves /api/v1.
func Router() http.Handler {
	r := chi.NewRouter()
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { httpx.Error(w, http.StatusNotFound, "No such route") })
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, http.StatusMethodNotAllowed, "Method not allowed on this route")
	})

	// The machine API authenticates with Bearer tokens, not cookies, so the Origin check does not apply.
	// "self" can therefore never be an app id below.
	r.Mount("/apps/self", machineRouter())

	r.Group(func(r chi.Router) {
		r.Use(httpx.RequireSameOrigin)
		r.Post("/signup", signup) // open, rate limited per IP

		r.Group(func(r chi.Router) {
			r.Use(httpx.Authenticate)
			r.Get("/me", getMe)
			r.Patch("/me", updateMe)
			r.Put("/me/password", changeMyPassword)
			r.Put("/me/email", changeMyEmail)
			r.Post("/me/reauth", reauth)
			r.Delete("/me", deleteMe)
			r.Get("/me/export", exportMe)
			r.Post("/me/mfa/totp", startTOTPSetup)
			r.Post("/me/mfa/totp/confirm", confirmTOTPSetup)
			r.Post("/me/mfa/totp/finish", finishTOTPSetup)
			r.Delete("/me/mfa/totp", removeTOTP)
			r.Post("/me/mfa/recovery-codes", renewRecoveryCodes)
			r.Post("/me/mfa/recovery-codes/finish", finishRecoveryCodes)

			// Groups: administrators may do everything; a group's owners may see it and manage its members.
			r.Get("/groups", listGroups)
			r.Get("/groups/{group}", getGroup)
			r.Get("/groups/{group}/members", listGroupMembers)
			r.Put("/groups/{group}/members/{account}", addGroupMember)
			r.Delete("/groups/{group}/members/{account}", removeGroupMember)

			// Everything else is for members of guardian-admins.
			r.Group(func(r chi.Router) {
				r.Use(httpx.AdminOnly)
				r.Post("/groups", createGroup)
				r.Patch("/groups/{group}", updateGroup)
				r.Delete("/groups/{group}", deleteGroup)
				r.Post("/groups/{group}/bind", bindGroup)

				r.Get("/accounts", listAccounts)
				r.Post("/accounts", createAccount)
				r.Get("/accounts/{account}", getAccount)
				r.Patch("/accounts/{account}", updateAccount)
				r.Delete("/accounts/{account}", deleteAccount)
				r.Put("/accounts/{account}/password", setAccountPassword)
				r.Post("/accounts/{account}/mfa/reset", resetAccountMFA)
				r.Get("/accounts/deleted", listDeletedAccounts)
				r.Post("/accounts/{account}/restore", restoreAccount)
				r.Post("/accounts/{account}/erase", eraseAccount)

				r.Get("/apps", listApps)
				r.Post("/apps", createApp)
				r.Get("/apps/{app}", getApp)
				r.Patch("/apps/{app}", updateApp)
				r.Delete("/apps/{app}", deleteApp)
				r.Put("/apps/{app}/access", setAppAccess)
				r.Post("/apps/{app}/secret", rotateAppSecret)

				r.Get("/audit", listAudit)
			})
		})
	})
	return r
}

// list wraps a collection in the list envelope. A nil slice becomes [].
func list[T any](items []T) map[string]any {
	if items == nil {
		items = []T{}
	}
	return map[string]any{"items": items}
}

// pageLimit reads ?limit= (default 50, at most 200). On a bad value it writes the error and returns false.
func pageLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return 50, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 200 {
		httpx.Error(w, http.StatusBadRequest, "limit must be a whole number from 1 to 200")
		return 0, false
	}
	return n, true
}
