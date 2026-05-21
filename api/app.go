package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	db "guardian/database"
)

func GetAppSubrouter() *chi.Mux {
	r := chi.NewRouter()

	r.Group(func(r chi.Router) {
		r.Get("/list", listApps)
		r.Get("/{uuid:^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$}", getApp)
	})

	r.Group(func(r chi.Router) {
		r.Use(OnlyAdmin)
		r.Post("/add", addApp)
		r.Delete("/remove", removeApp)
	})

	return r
}

func addApp(w http.ResponseWriter, r *http.Request) {
	var s db.App
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	app, err := db.AddApp(s)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to add App")
		return
	}
	RespondWithJSON(w, http.StatusOK, app)
}

func removeApp(w http.ResponseWriter, r *http.Request) {
	var s db.App
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	err := db.RemoveApp(s.ID)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to remove App")
		return
	}
	RespondWithJSON(w, http.StatusOK, s)
}

func listApps(w http.ResponseWriter, r *http.Request) {
	Apps, err := db.GetApps()
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to retrieve Apps")
		return
	}
	RespondWithJSON(w, http.StatusOK, Apps)
}

func getApp(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("uuid").(string)
	App, err := db.GetApp(uuid)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to retrieve App")
		return
	}
	RespondWithJSON(w, http.StatusOK, App)
}
