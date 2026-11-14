// Package migrations holds the database migrations. They are embedded into the binary, so a deployment
// needs no SQL files next to it. goose applies them in order at startup (see internal/store).
package migrations

import "embed"

// FS contains every migration file, named <version>_<name>.sql.
//
//go:embed *.sql
var FS embed.FS

// InitSQL is the text of migration 1, which creates the schema and the seed data. It is idempotent,
// so tests run it directly to re-seed an emptied database.
//
//go:embed 00001_init.sql
var InitSQL string
