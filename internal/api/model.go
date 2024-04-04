package api

import (
	"log"
)

type User struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserData struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
}

// Account Management

func GetUser(u User) UserData {
	database := GetDatabaseConnection()
	const userQuery = `SELECT id, username FROM account_credentials WHERE id = $1`
	var user UserData
	err := database.QueryRow(userQuery, u.UUID).Scan(&user.UUID, &user.Username)
	if err != nil {
		log.Println("Failed to retrieve user")
		return UserData{}
	}
	return user
}

func AddUser(username string, password string) bool {
	database := GetDatabaseConnection()
	const userCreationQuery = `INSERT INTO account_credentials (username, password) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	_, err := database.Exec(userCreationQuery, username, password)
	if err != nil {
		log.Println("Failed to create user")
		return false
	}
	return true
}

func RemoveUser(u User) bool {
	database := GetDatabaseConnection()
	const userRemovalQuery = `DELETE FROM account_credentials WHERE id = $1`
	_, err := database.Exec(userRemovalQuery, u.UUID)
	if err != nil {
		log.Println("Failed to remove user")
		return false
	}
	return true
}

func UpdatePassword(u User) bool {
	database := GetDatabaseConnection()
	const passwordUpdateQuery = `UPDATE account_credentials SET password = $2 WHERE id = $1`
	_, err := database.Exec(passwordUpdateQuery, u.UUID, u.Password)
	if err != nil {
		log.Println("Failed to update password")
		return false
	}
	return true
}

func UpdateUsername(u User) bool {
	database := GetDatabaseConnection()
	const usernameUpdateQuery = `UPDATE account_credentials SET username = $2 WHERE uuid = $1`
	_, err := database.Exec(usernameUpdateQuery, u.UUID, u.Username)
	if err != nil {
		log.Println("Failed to update username")
		return false
	}
	return true
}

// Service management

type Service struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func AddService(s Service) bool {
	database := GetDatabaseConnection()
	const serviceCreationQuery = `INSERT INTO services (name, description) VALUES ($1, $2)`
	_, err := database.Exec(serviceCreationQuery, s.Name, s.Description)
	if err != nil {
		log.Println("Failed to create service")
		return false
	}
	return true
}

func RemoveService(s Service) bool {
	database := GetDatabaseConnection()
	const serviceRemovalQuery = `DELETE FROM services WHERE id = $1`
	_, err := database.Exec(serviceRemovalQuery, s.UUID)
	if err != nil {
		log.Println("Failed to remove service")
		return false
	}
	return true
}

func GetService(s Service) Service {
	database := GetDatabaseConnection()
	const serviceQuery = `SELECT * FROM services WHERE id = $1`
	var service Service
	err := database.QueryRow(serviceQuery, s.UUID).Scan(&service.UUID, &service.Name, &service.Description)
	if err != nil {
		log.Println("Failed to retrieve service")
		return Service{}
	}
	return service
}

func GetServices() []Service {
	database := GetDatabaseConnection()
	const serviceQuery = `SELECT * FROM services`
	rows, err := database.Query(serviceQuery)
	if err != nil {
		log.Println("Failed to retrieve services")
		return nil
	}
	defer rows.Close()
	var services []Service
	for rows.Next() {
		var s Service
		err := rows.Scan(&s.UUID, &s.Name, &s.Description)
		if err != nil {
			log.Println("Failed to scan service")
			return nil
		}
		services = append(services, s)
	}
	return services
}

// Authentication and Authorization

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
