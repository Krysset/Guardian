package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

func Authenticate(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		var u User
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&u); err != nil {
			RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
			return
		}
		vars := mux.Vars(r)
		u.UUID = vars["uuid"]
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
		vars := mux.Vars(r)
		u.UUID = vars["uuid"]
		if IsAdmin(u) {
			next.ServeHTTP(w, r)
		}
	}
	return http.HandlerFunc(fn)
}
