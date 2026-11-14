// Package migrations holds the database schema. It is embedded into the binary, so a deployment needs no
// SQL files next to it.
package migrations

import _ "embed"

// InitSQL creates the schema and the seed data. The script is idempotent and takes its own advisory lock,
// so every replica can run it at startup.
//
//go:embed 00001_init.sql
var InitSQL string
