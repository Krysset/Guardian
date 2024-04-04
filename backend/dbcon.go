package main

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq"
)

var database *sql.DB

func connect() *sql.DB {
	// Load credentials
	host := os.Getenv("DB_HOST")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	port, err := strconv.Atoi(os.Getenv("DB_PORT"))
	if err != nil {
		fmt.Println("Failed to convert DB_PORT to int. Make sure it is set in .env file. The dev port is now temporarily set")
		port = 5432
	}

	// Connect to DB
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	db, err := sql.Open("postgres", psqlInfo)
	// Check connection
	if err != nil {
		fmt.Println("Something went wrong when connecting to DB. Retrying in 3 seconds..")
		time.Sleep(3 * time.Second)
		db = connect()
	}
	// Test connection
	fmt.Println("Connection to DB established. Testing connection...")
	err = db.Ping()
	if err != nil {
		fmt.Println("Failed to get response from DB. Retrying...")
	}
	fmt.Println("Successfully connected to DB!")

	return db
}

func initialize_db(db *sql.DB) {
	// Init tables
	sql, ioErr := os.ReadFile("schema.sql")
	tableCreationQuery := string(sql)
	if ioErr != nil {
		panic("Failed to read table creation query")
	}
	_, err := db.Exec(tableCreationQuery)

	if err != nil {
		fmt.Println("Something went wrong when creating tables. Retrying 3 seconds...")
		time.Sleep(3 * time.Second)
		initialize_db(db)
	}
}

func GetDatabaseConnection() *sql.DB {
	if database == nil {
		database = connect()
		initialize_db(database)
	}
	return database
}
