package main

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func getServiceSubrouter() *chi.Mux {
	r := chi.NewRouter()

	r.Group(func(r chi.Router) {
		r.Get("/list", listServices)
		r.Get("/{uuid:^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$}", getService)
	})

	r.Group(func(r chi.Router) {
		r.Use(Authenticate)
		r.Use(ValidateAdmin)
		r.Post("/add", addService)
		r.Delete("/remove", removeService) // Maybe use POST instead of DELETE
	})

	return r
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
	uuid := r.Context().Value("uuid").(string)
	s := Service{UUID: uuid}
	service := GetService(s)
	RespondWithJSON(w, http.StatusOK, service)
}
