package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

func InitServiceSubrouter(r *mux.Router) {
	subr := r.PathPrefix("/service").Subrouter()
	subr.Use(Authenticate)
	subr.Use(ValidateAdmin)
	subr.HandleFunc("/add", addService).Methods("POST")
	subr.HandleFunc("/remove", removeService).Methods("DELETE")
	subr.HandleFunc("/list", listServices).Methods("GET")
	subr.HandleFunc("/{uuid:^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$}", getService).Methods("GET")
}

func addService(w http.ResponseWriter, r *http.Request) {
	var s Service
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if AddService(s) {
		RespondWithJSON(w, http.StatusOK, s)
	} else {
		RespondWithError(w, http.StatusBadRequest, "Failed to add service")
	}
}

func removeService(w http.ResponseWriter, r *http.Request) {
	var s Service
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if RemoveService(s) {
		RespondWithJSON(w, http.StatusOK, s)
	} else {
		RespondWithError(w, http.StatusBadRequest, "Failed to remove service")
	}
}

// TODO: Verify that returned services actually have content and respond with error if they dont't

func listServices(w http.ResponseWriter, r *http.Request) {
	services := GetServices()
	RespondWithJSON(w, http.StatusOK, services)
}

func getService(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	uuid := vars["uuid"]
	s := Service{UUID: uuid}
	service := GetService(s)
	RespondWithJSON(w, http.StatusOK, service)
}
