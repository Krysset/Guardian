package api

import (
	"net/http"

	db "guardian/database"

	"github.com/go-chi/chi/v5"
)

func Authenticate(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		username, pass, ok := r.BasicAuth()
		if !ok {
			RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		_, err := db.GetUserFromCredentials(username, pass)
		if err != nil {
			RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func OnlySelf(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		username, pass, ok := r.BasicAuth()
		if !ok {
			RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		u, err := db.GetUserFromCredentials(username, pass)
		if err != nil {
			RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		if u.ID != chi.URLParam(r, "uuid") {
			RespondWithError(w, http.StatusForbidden, "Forbidden")
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func OnlyAdmin(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		username, pass, ok := r.BasicAuth()
		if !ok {
			RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		u, err := db.GetUserFromCredentials(username, pass)
		if err != nil {
			RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		isAdmin, err := db.UserHasAdmin(u.ID)
		if err != nil {
			RespondWithError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if !isAdmin {
			RespondWithError(w, http.StatusForbidden, "Forbidden")
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

// func ValidateService()
// https://go-chi.io/#/pages/middleware?id=jwt-authentication
