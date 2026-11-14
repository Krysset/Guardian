package api

import (
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"guardian/auth"
	db "guardian/database"
)

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

func GetAccountSubrouter() *chi.Mux {
	r := chi.NewRouter()
	r.Post("/register", registerPublic) // open sign-up, rate limited per IP
	r.Group(func(r chi.Router) {
		r.Use(OnlyAdmin)
		r.Post("/delete", deleteAccount)
		r.Post("/add", register)
	})
	r.Group(func(r chi.Router) {
		r.Use(Authenticate)
		r.Get("/me", me)
		r.Post("/update/password", updatePassword)
		r.Post("/update/username", updateUsername)
		r.Post("/update", update)
	})
	return r
}

func validPassword(p string) bool {
	// Upper bound protects the hasher from huge inputs.
	return len(p) >= 10 && len(p) <= 1024
}

const (
	registerLimit  = 10 // sign-ups per IP per window
	registerWindow = time.Hour
)

// registerPublic is open to everyone, so it is limited per client IP (counters live in Postgres and are
// shared by all replicas). Admin-created accounts (/add) use register directly and are not limited.
func registerPublic(w http.ResponseWriter, r *http.Request) {
	n, err := db.RateLimitHit("register:ip:"+clientIP(r), registerWindow)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if n > registerLimit {
		rateLimited.WithLabelValues("register").Inc()
		w.Header().Set("Retry-After", strconv.Itoa(int(registerWindow.Seconds())))
		RespondWithError(w, http.StatusTooManyRequests, "Too many sign-ups from this address. Try again later.")
		return
	}
	register(w, r)
}

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !usernameRe.MatchString(req.Username) {
		RespondWithError(w, http.StatusBadRequest, "Username must be 3-64 characters: letters, digits, '.', '_' or '-'")
		return
	}
	if !validPassword(req.Password) {
		RespondWithError(w, http.StatusBadRequest, "Password must be at least 10 characters")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	acct, err := db.CreateAccount(req.Username, hash)
	if db.IsUniqueViolation(err) {
		RespondWithError(w, http.StatusConflict, "Username is already taken")
		return
	}
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to register user")
		return
	}
	RespondWithJSON(w, http.StatusCreated, acct)
}

func me(w http.ResponseWriter, r *http.Request) {
	acct, err := db.GetAccount(accountID(r))
	if err != nil {
		RespondWithError(w, http.StatusNotFound, "Account not found")
		return
	}
	RespondWithJSON(w, http.StatusOK, acct)
}

// deleteAccount (admin) disables an account and ends all of its sessions.
func deleteAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !db.IsUUID(req.ID) {
		RespondWithError(w, http.StatusBadRequest, "Invalid account id")
		return
	}
	if err := db.SoftDeleteAccount(req.ID); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to delete user")
		return
	}
	db.Audit("account.deleted", accountID(r), "", clientIP(r), map[string]any{"target": req.ID})
	RespondWithSuccess(w)
}

func updatePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	id := accountID(r)
	hash, err := db.GetPasswordHash(id)
	if err != nil || hash == "" || !auth.VerifyPassword(req.CurrentPassword, hash) {
		RespondWithError(w, http.StatusForbidden, "Current password is incorrect")
		return
	}
	if !validPassword(req.NewPassword) {
		RespondWithError(w, http.StatusBadRequest, "Password must be at least 10 characters")
		return
	}
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := db.UpdatePasswordHash(id, newHash); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to update password")
		return
	}
	db.Audit("password.changed", id, "", clientIP(r), nil)
	RespondWithSuccess(w)
}

func updateUsername(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !usernameRe.MatchString(req.Username) {
		RespondWithError(w, http.StatusBadRequest, "Invalid username")
		return
	}
	err := db.UpdateUsername(accountID(r), req.Username)
	if db.IsUniqueViolation(err) {
		RespondWithError(w, http.StatusConflict, "Username is already taken")
		return
	}
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to update username")
		return
	}
	RespondWithSuccess(w)
}

// update edits profile fields. Only fields present in the body are changed.
func update(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DisplayName *string `json:"display_name"`
		GivenName   *string `json:"given_name"`
		FamilyName  *string `json:"family_name"`
		PictureURL  *string `json:"picture_url"`
		Locale      *string `json:"locale"`
		Zoneinfo    *string `json:"zoneinfo"`
		Email       *string `json:"email"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	acct, err := db.GetAccount(accountID(r))
	if err != nil {
		RespondWithError(w, http.StatusNotFound, "Account not found")
		return
	}
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&acct.DisplayName, req.DisplayName)
	set(&acct.GivenName, req.GivenName)
	set(&acct.FamilyName, req.FamilyName)
	set(&acct.PictureURL, req.PictureURL)
	set(&acct.Locale, req.Locale)
	set(&acct.Zoneinfo, req.Zoneinfo)
	set(&acct.Email, req.Email)
	if acct.PictureURL != "" && !validRedirectURI(acct.PictureURL) {
		RespondWithError(w, http.StatusBadRequest, "picture_url must be an https URL")
		return
	}
	updated, err := db.UpdateProfile(acct)
	if db.IsUniqueViolation(err) {
		RespondWithError(w, http.StatusConflict, "Email is already in use")
		return
	}
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Failed to update user")
		return
	}
	RespondWithJSON(w, http.StatusOK, updated)
}
