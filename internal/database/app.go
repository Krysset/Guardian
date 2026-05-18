package database

import (
	"database/sql"
	"log"
	_ "github.com/lib/pq"

	"guardian/model"
)

func AddApp(name string, prettyName string, description string) App {
	database := GetDatabaseConnection()
	const appCreationQuery = `INSERT INTO app (name, pretty_name, description) VALUES ($1, $2, $3)`
	row := database.QueryRow(appCreationQuery, name, prettyName, description)
	var app App
	err := row.Scan(&app.UUID, &app.Name, &app.PrettyName, &app.Description)
	if err != nil {
		log.Println("Failed to create app with name: " + name)
		return App{}
	}
	return app
}

func RemoveApp(id string) bool {
	database := GetDatabaseConnection()
	const appRemovalQuery = `DELETE FROM app WHERE id = $1`
	_, err := database.Exec(appRemovalQuery, id)
	if err != nil {
		log.Println("Failed to remove app with id: " + id)
		return false
	}
	return true
}

func GetApp(id string) App {
	database := GetDatabaseConnection()
	const appQuery = `SELECT * FROM app WHERE id = $1`
	var app App
	err := database.QueryRow(appQuery, id).Scan(&app.UUID, &app.Name, &app.PrettyName, &app.Description)
	if err != nil {
		log.Println("Failed to retrieve app with id: " + id)
		return App{}
	}
	return app
}

func GetApps() []App {
	database := GetDatabaseConnection()
	const appQuery = `SELECT * FROM app`
	rows, err := database.Query(appQuery)
	if err != nil {
		log.Println("Failed to retrieve apps")
		return nil
	}
	defer rows.Close()
	var apps []App
	for rows.Next() {
		var a App
		err := rows.Scan(&a.UUID, &a.Name, &a.PrettyName, &a.Description)
		if err != nil {
			log.Println("Failed to scan app")
			return nil
		}
		apps = append(apps, a)
	}
	return apps
}