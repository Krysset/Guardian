package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"guardian/database/connection"
	"guardian/database/app"
)

func getAppSubrouter() *chi.Mux {
	r := chi.NewRouter()

	r.Group(func(r chi.Router) {
		r.Get("/list", listApps)
		r.Get("/{uuid:^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$}", getApp)
	})

	r.Group(func(r chi.Router) {
		r.Use(Authenticate)
		r.Use(ValidateAdmin)
		r.Post("/add", addApp)
		r.Delete("/remove", removeApp) 
	})

	return r
}

func addApp(w http.ResponseWriter, r *http.Request) {
	var s App
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if AddApp(s) {
		RespondWithJSON(w, http.StatusOK, s)
	} else {
		RespondWithError(w, http.StatusBadRequest, "Failed to add App")
	}
}

func removeApp(w http.ResponseWriter, r *http.Request) {
	var s App
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if RemoveApp(s) {
		RespondWithJSON(w, http.StatusOK, s)
	} else {
		RespondWithError(w, http.StatusBadRequest, "Failed to remove App")
	}
}

// TODO: Verify that returned Apps actually have content and respond with error if they dont't

func listApps(w http.ResponseWriter, r *http.Request) {
	Apps := GetApps()
	RespondWithJSON(w, http.StatusOK, Apps)
}

func getApp(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("uuid").(string)
	s := App{UUID: uuid}
	App := GetApp(s)
	RespondWithJSON(w, http.StatusOK, App)
}
