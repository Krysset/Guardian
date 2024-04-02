package main

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func getAccountSubrouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(Authenticate)
	r.Post("/delete", delete)
	r.Post("/update/password", updatePassword)
	r.Post("/update/username", updateUsername)
	return r
}

func delete(w http.ResponseWriter, r *http.Request) {
	var u User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	u.UUID = r.Context().Value("uuid").(string)
	if RemoveUser(u) {
		RespoondWithSuccess(w)
	} else {
		RespondWithError(w, http.StatusBadRequest, "Failed to delete user")
	}
}

func updatePassword(w http.ResponseWriter, r *http.Request) {
	var u User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	u.UUID = r.Context().Value("uuid").(string)
	if UpdatePassword(u) {
		RespoondWithSuccess(w)
	} else {
		RespondWithError(w, http.StatusBadRequest, "Failed to update password")
	}
}

func updateUsername(w http.ResponseWriter, r *http.Request) {
	var u User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	u.UUID = r.Context().Value("uuid").(string)
	if UpdateUsername(u) {
		RespoondWithSuccess(w)
	} else {
		RespondWithError(w, http.StatusBadRequest, "Failed to update username")
	}
}
