package database

import (
	"database/sql"
	"log"
	_ "github.com/lib/pq"

	"guardian/model"
)

func GetUser(id string) User {
	database := GetDatabaseConnection()
	const userQuery = `SELECT id, username, email, display_name, created_at FROM account_credentials WHERE id = $1`
	var user User
	err := database.QueryRow(userQuery, id).Scan(&user.UUID, &user.Username, &user.Email, &user.DisplayName, &user.CreatedAt)
	if err != nil {
		log.Println("Failed to retrieve user with id: " + id)
		return User{}
	}
	return user
}

func AddUser(username string, password string) bool {
	database := GetDatabaseConnection()
	const userCreationQuery = `INSERT INTO account_credentials (username, password) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	_, err := database.Exec(userCreationQuery, username, password)
	if err != nil {
		log.Println("Failed to create user with username: " + username)
		return false
	}
	return true
}

func UpdateUser(u User) User {
	database := GetDatabaseConnection()
	const userUpdateQuery = `UPDATE account_credentials SET username = $2, email = $3, display_name = $4 WHERE id = $1`
	_, err := database.Exec(userUpdateQuery, u.UUID, u.Username, u.Email, u.DisplayName)
	if err != nil {
		log.Println("Failed to update user with id: " + u.UUID)
		return User{}
	}
	return GetUser(u.UUID)
}

func RemoveUser(id string) bool {
	database := GetDatabaseConnection()
	const userRemovalQuery = `DELETE FROM account_credentials WHERE id = $1`
	_, err := database.Exec(userRemovalQuery, id)
	if err != nil {
		log.Println("Failed to remove user with id: " + id)
		return false
	}
	return true
}

func UpdatePassword(id string, newPassword string) bool {
	database := GetDatabaseConnection()
	const passwordUpdateQuery = `UPDATE account_credentials SET password = $2 WHERE id = $1`
	_, err := database.Exec(passwordUpdateQuery, id, newPassword)
	if err != nil {
		log.Println("Failed to update password for user with id: " + id)
		return false
	}
	return true
}

func UpdateUsername(id string, newUsername string) bool {
	database := GetDatabaseConnection()
	const usernameUpdateQuery = `UPDATE account_credentials SET username = $2 WHERE id = $1`
	_, err := database.Exec(usernameUpdateQuery, id, newUsername)
	if err != nil {
		log.Println("Failed to update username for user with id: " + id)
		return false
	}
	return true
}