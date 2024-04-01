package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/joho/godotenv"
)

func hello(w http.ResponseWriter, r *http.Request) {
	RespondWithJSON(w, http.StatusOK, map[string]string{"message": "Hello, World!"})
}

func main() {
	loadEnv()
	// create the router
	// Test()
	router := mux.NewRouter()
	router.HandleFunc("/", hello).Methods("GET")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/register", register).Methods("POST")
	InitAccountSubrouter(router)
	InitServiceSubrouter(router)
	http.ListenAndServe(":8010", router)
	// Close DB connection
	GetDatabaseConnection().Close()
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
	vars := mux.Vars(r)
	u.UUID = vars["uuid"]
	if IsAuthenticated(u) {
		RespondWithError(w, http.StatusBadRequest, "Failed to login")
		return
	}
	sessionId := CreateSession(u)
	if sessionId == "" {
		RespondWithError(w, http.StatusFailedDependency, "Failed to create session")
	}
}

func register(w http.ResponseWriter, r *http.Request) {
	var u User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	AddUser(u)
}
