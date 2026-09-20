package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func GetAuthSubRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Group(func(r chi.Router) {
		r.Use()
		r.Post("/accesstoken", issueUserAccessToken)

	})

	return r
}

func issueUserAccessToken(w http.ResponseWriter, r *http.Request) {

}

func genAccessToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
