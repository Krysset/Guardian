package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func GetMetricsSubrouter() *chi.Mux {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(OnlyAdmin) // Change to metrics permission later
		r.Post("/", metrics)
		r.Post("/add", register)
	})
	return r
}

func metrics(w http.ResponseWriter, r *http.Request) {

	RespondWithSuccess(w)
}
