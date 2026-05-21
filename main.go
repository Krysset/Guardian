package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"

	api "guardian/api"
	db "guardian/database"
)

// Example rest api with chi
// https://github.com/go-chi/chi/blob/master/_examples/rest/main.go#L189

func main() {
	loadEnv()
	// Preemptively initialize DB connection
	db.GetDatabaseConnection()
	// Init router
	r := chi.NewRouter()
	r.Mount("/api", getApiSubrouter())
	fmt.Println("Server started and ready on port 3001")
	http.ListenAndServe(":3001", r)
	// Close DB connection
	db.GetDatabaseConnection().Close()
}

func getApiSubrouter() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/", hello)
	r.Mount("/account", api.GetAccountSubrouter())
	r.Mount("/service", api.GetAppSubrouter())
	return r
}

func hello(w http.ResponseWriter, r *http.Request) {
	api.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "Hello, World!"})
}

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}
