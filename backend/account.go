package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

func InitAccountSubrouter(r *mux.Router) {
	subr := r.PathPrefix("/account").Subrouter()
	subr.Use(Authenticate)
	subr.HandleFunc("/delete/{uuid:^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$}", delete).Methods("DELETE")
	subr.HandleFunc("/update/password/{uuid:^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$}", updatePassword).Methods("PUT")
	subr.HandleFunc("/update/username/{uuid:^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$}", updateUsername).Methods("PUT")
}

func delete(w http.ResponseWriter, r *http.Request) {
	var u User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	vars := mux.Vars(r)
	u.UUID = vars["uuid"]
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
	vars := mux.Vars(r)
	u.UUID = vars["uuid"]
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
	vars := mux.Vars(r)
	u.UUID = vars["uuid"]
	if UpdateUsername(u) {
		RespoondWithSuccess(w)
	} else {
		RespondWithError(w, http.StatusBadRequest, "Failed to update username")
	}
}
