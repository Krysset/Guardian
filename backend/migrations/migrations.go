// Package migrations holds the database migrations. They are embedded into the binary, so a deployment
// needs no SQL files next to it. goose applies them in order at startup (see internal/store).
package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"strings"
	"testing/fstest"
)

//go:embed *.sql
var files embed.FS

const (
	initFile               = "00001_init.sql"
	fingerprintPlaceholder = "@@INIT_FINGERPRINT@@"
)

var (
	// InitFingerprint identifies the content of migration 1. Until Guardian 1.0 that file is edited in
	// place, and a database created by another revision of it cannot be used; the fingerprint is how
	// Guardian tells. Comments and blank lines do not count.
	InitFingerprint string

	// InitSQL is migration 1 with its fingerprint filled in. It creates the schema and the seed data.
	// It is idempotent, so tests run it directly to re-seed an emptied database.
	InitSQL string

	// FS contains every migration file, named <version>_<name>.sql, ready for goose.
	FS fs.FS
)

func init() {
	out := fstest.MapFS{}
	entries, err := files.ReadDir(".")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		data, err := files.ReadFile(e.Name())
		if err != nil {
			panic(err)
		}
		if e.Name() == initFile {
			InitFingerprint = fingerprint(string(data))
			InitSQL = strings.ReplaceAll(string(data), fingerprintPlaceholder, InitFingerprint)
			data = []byte(InitSQL)
		}
		out[e.Name()] = &fstest.MapFile{Data: data}
	}
	if InitSQL == "" {
		panic("migrations: " + initFile + " is missing")
	}
	FS = out
}

// fingerprint hashes the statements of a SQL script, ignoring comment lines, blank lines and trailing
// spaces, so that rewording a comment does not make existing databases unusable.
func fingerprint(sql string) string {
	h := sha256.New()
	for _, line := range strings.Split(sql, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		h.Write([]byte(line))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
