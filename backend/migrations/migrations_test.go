package migrations

import (
	"io/fs"
	"strings"
	"testing"
)

func TestFingerprintIgnoresCommentsAndBlankLines(t *testing.T) {
	base := "CREATE TABLE a (id INT);\nINSERT INTO a VALUES (1);\n"
	same := "-- a comment\n\nCREATE TABLE a (id INT);   \n   -- indented comment\nINSERT INTO a VALUES (1);\r\n"
	if fingerprint(base) != fingerprint(same) {
		t.Error("comments, blank lines and trailing spaces must not change the fingerprint")
	}
	for name, changed := range map[string]string{
		"a changed statement": "CREATE TABLE a (id BIGINT);\nINSERT INTO a VALUES (1);\n",
		"an added statement":  base + "CREATE INDEX i ON a (id);\n",
		"a removed statement": "CREATE TABLE a (id INT);\n",
		"changed indentation": "  CREATE TABLE a (id INT);\nINSERT INTO a VALUES (1);\n",
	} {
		if fingerprint(changed) == fingerprint(base) {
			t.Errorf("%s must change the fingerprint", name)
		}
	}
}

func TestInitMigrationCarriesItsFingerprint(t *testing.T) {
	if len(InitFingerprint) != 16 {
		t.Fatalf("fingerprint = %q", InitFingerprint)
	}
	if strings.Contains(InitSQL, fingerprintPlaceholder) || !strings.Contains(InitSQL, "'"+InitFingerprint+"'") {
		t.Error("InitSQL must have the placeholder replaced by the fingerprint")
	}
	served, err := fs.ReadFile(FS, initFile)
	if err != nil || string(served) != InitSQL {
		t.Errorf("goose must be given the filled-in script (err %v)", err)
	}
	if !strings.Contains(InitSQL, "-- +goose Up") || strings.Contains(InitSQL, "\nBEGIN;") || strings.Contains(InitSQL, "\nCOMMIT;") {
		t.Error("migration 1 must be a goose migration without its own BEGIN/COMMIT")
	}
}
