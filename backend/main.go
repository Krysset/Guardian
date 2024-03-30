package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/joho/godotenv"
)

func main() {
	loadEnv()
	// create the router
	// Test()
	router := mux.NewRouter()
	router.HandleFunc("/login/{uuid:^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$}", login).Methods("POST")
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
