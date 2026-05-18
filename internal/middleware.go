package api

import (
	"encoding/json"
	"net/http"
)

func Authenticate(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		var u User
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&u); err != nil {
			RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
			return
		}
		u.UUID = r.Context().Value("uuid").(string)
		if IsAuthenticated(u) {
			next.ServeHTTP(w, r)
		}
	}

	return http.HandlerFunc(fn)
}

func ValidateAdmin(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		var u User
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&u); err != nil {
			RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
			return
		}
		u.UUID = r.Context().Value("uuid").(string)
		if IsAdmin(u) {
			next.ServeHTTP(w, r)
		}
	}
	return http.HandlerFunc(fn)
}

// func ValidateService()
// https://go-chi.io/#/pages/middleware?id=jwt-authentication
