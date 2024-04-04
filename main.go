package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/joho/godotenv"
)

// Example rest api with chi
// https://github.com/go-chi/chi/blob/master/_examples/rest/main.go#L189

func main() {
	loadEnv()
	// Init DB connection
	GetDatabaseConnection()
	// Init router
	r := chi.NewRouter()
	r.Mount("/api", getApiSubrouter())
	fmt.Println("Server started and ready on port 3001")
	http.ListenAndServe(":3001", r)
	// Close DB connection
	GetDatabaseConnection().Close()
}

func getApiSubrouter() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/", hello)
	r.Post("/login", login)
	r.Post("/register", register)
	r.Mount("/account", getAccountSubrouter())
	r.Mount("/service", getServiceSubrouter())
	return r
}

func hello(w http.ResponseWriter, r *http.Request) {
	RespondWithJSON(w, http.StatusOK, map[string]string{"message": "Hello, World!"})
}

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	var u User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	u.UUID = r.Context().Value("uuid").(string)
	if IsAuthenticated(u) {
		RespondWithError(w, http.StatusBadRequest, "Failed to login")
		return
	}
	sessionId := CreateSession(u)
	if sessionId == "" {
		RespondWithError(w, http.StatusFailedDependency, "Failed to create session")
	}
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
	AddUser(req.Username, req.Password)
	RespoondWithSuccess(w)
}
