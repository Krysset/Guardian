package database

import (
	"log"

	_ "github.com/lib/pq"
)

func AddApp(app App) (App, error) {
	database := GetDatabaseConnection()
	const appCreationQuery = `INSERT INTO app (name, pretty_name, description) VALUES ($1, $2, $3)`
	row := database.QueryRow(appCreationQuery, app.Name, app.PrettyName, app.Description)
	var a App
	err := row.Scan(&a.ID, &a.Name, &a.PrettyName, &a.Description)
	if err != nil {
		log.Println("Failed to create app with name: " + app.Name)
		return App{}, err
	}
	return app, nil
}

func RemoveApp(id string) error {
	database := GetDatabaseConnection()
	const appRemovalQuery = `DELETE FROM app WHERE id = $1`
	_, err := database.Exec(appRemovalQuery, id)
	if err != nil {
		log.Println("Failed to remove app with id: " + id)
		return err
	}
	return nil
}

func GetApp(id string) (App, error) {
	database := GetDatabaseConnection()
	const appQuery = `SELECT * FROM app WHERE id = $1`
	var app App
	err := database.QueryRow(appQuery, id).Scan(&app.ID, &app.Name, &app.PrettyName, &app.Description)
	if err != nil {
		log.Println("Failed to retrieve app with id: " + id)
		return App{}, err
	}
	return app, nil
}

func GetApps() ([]App, error) {
	database := GetDatabaseConnection()
	const appQuery = `SELECT * FROM app`
	rows, err := database.Query(appQuery)
	if err != nil {
		log.Println("Failed to retrieve apps")
		return nil, err
	}
	defer rows.Close()
	var apps []App
	for rows.Next() {
		var a App
		err := rows.Scan(&a.ID, &a.Name, &a.PrettyName, &a.Description)
		if err != nil {
			log.Println("Failed to scan app")
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, nil
}
