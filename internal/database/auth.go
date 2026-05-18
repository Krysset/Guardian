package database

import (
	"database/sql"
	"log"
	_ "github.com/lib/pq"
	
	"guardian/model"
)

func IsAuthenticated(u User) bool {
	database := GetDatabaseConnection()
	const authenticationQuery = `SELECT * FROM account_credentials WHERE username = $1 AND password = $2`
	var username string
	var password string
	err := database.QueryRow(authenticationQuery, u.Username, u.Password).Scan(&username, &password)
	return err == nil
}

func IsAdmin(u User) bool {
	database = GetDatabaseConnection()
	const adminQuery = `SELECT * FROM account_credentials WHERE id = $1 AND admin = true`
	var id string
	err := database.QueryRow(adminQuery, u.UUID).Scan(&id)
	if err != nil || id != u.UUID {
		return false
	}
	return true
}

func CreateSession(u User) string {
	database = GetDatabaseConnection()
	const sessionQuery = `INSERT INTO account_sessions (accountId) VALUES ($1)`
	var sessionId string
	err := database.QueryRow(sessionQuery, u.UUID).Scan(&sessionId)
	if err != nil {
		log.Println("Failed to create a user session")
		return ""
	}
	return sessionId
}