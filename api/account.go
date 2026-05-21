package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	db "guardian/database"
)

func GetAccountSubrouter() *chi.Mux {
	r := chi.NewRouter()
	r.Post("/register", register)
	r.Group(func(r chi.Router) {
		r.Use(OnlyAdmin)
		r.Post("/delete", delete)
		r.Post("/add", register)
	})
	r.Group(func(r chi.Router) {
		r.Use(OnlySelf)
		r.Post("/update/password", updatePassword)
		r.Post("/update/username", updateUsername)
		r.Post("/update", update)
	})
	return r
}

func delete(w http.ResponseWriter, r *http.Request) {
	var u db.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	u.ID = r.Context().Value("uuid").(string)
	err := db.RemoveUser(u.ID)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to delete user")
		return
	}
	RespondWithSuccess(w)
}

func updatePassword(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var newPasswordRequest struct {
		NewPassword string `json:"newPassword"`
	}

	if err := decoder.Decode(&newPasswordRequest); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	userID := r.Context().Value("uuid").(string)
	err := db.UpdatePassword(userID, newPasswordRequest.NewPassword)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to update password")
		return
	}
	RespondWithSuccess(w)
}

func updateUsername(w http.ResponseWriter, r *http.Request) {
	var u db.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	u.ID = r.Context().Value("uuid").(string)
	err := db.UpdateUsername(u.ID, u.Username)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to update username")
		return
	}
	RespondWithSuccess(w)
}

func update(w http.ResponseWriter, r *http.Request) {
	var u db.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	u.ID = r.Context().Value("uuid").(string)
	newUser, err := db.UpdateUser(u)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to update user")
		return
	}
	RespondWithJSON(w, http.StatusOK, newUser)
}

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	_, err := db.AddUser(req.Username, req.Password)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to register user")
		return
	}
	RespondWithSuccess(w)
}
