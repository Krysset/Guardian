package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"guardian/internal/backup"
	"guardian/internal/config"
)

func run(t *testing.T, stdin []byte, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	noConfig := func() (config.Config, error) { return config.Config{}, errors.New("ISSUER_URL is required") }
	code = runBackupCommand(args, bytes.NewReader(stdin), &out, &errOut, noConfig)
	return code, out.String(), errOut.String()
}

// plainBackup is a decrypted backup with no rows, which verify accepts without a key or a database.
func plainBackup(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := backup.NewWriter(&buf, backup.Manifest{Encryption: backup.EncryptionNone, Issuer: "https://auth.test"})
	if err != nil {
		t.Fatal(err)
	}
	// An empty gzip stream: the payload of a backup with no rows.
	w.Write([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	w.Close()
	return buf.Bytes()
}

// Covers: P2
func TestBackupCommandLine(t *testing.T) {
	file := filepath.Join(t.TempDir(), "b.gbk")
	if err := os.WriteFile(file, plainBackup(t), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		stdin  []byte
		args   []string
		code   int
		stderr string
	}{
		{"verify a file", nil, []string{"backup", "verify", file}, 0, "The backup is complete"},
		{"verify stdin", plainBackup(t), []string{"backup", "verify", "-"}, 0, "every row count matches"},
		{"verify a damaged file", plainBackup(t)[:60], []string{"backup", "verify"}, 1, "damaged"},
		{"verify a missing file", nil, []string{"backup", "verify", file + ".nope"}, 1, "no such file"},
		{"decrypt needs a key", nil, []string{"backup", "decrypt", file}, 2, "--identity-file"},
		{"unknown flag", nil, []string{"backup", "--force"}, 2, "usage:"},
		{"backup takes no file", nil, []string{"backup", "--execute", "x.gbk"}, 2, "unexpected arguments"},
		{"two files", nil, []string{"restore", "a", "b"}, 2, "unexpected arguments"},
		{"out-dir needs execute", nil, []string{"backup", "--out-dir", "/backups", "--recipient", "age1x"}, 2, "--out-dir needs --execute"},
		{"out and out-dir", nil, []string{"backup", "--execute", "--out", "a", "--out-dir", "/b"}, 2, "--out-dir needs --execute"},
		{"keep needs out-dir", nil, []string{"backup", "--execute", "--keep", "3"}, 2, "--keep needs --out-dir"},
		// backup and restore need the configuration (database, issuer, key); verify and decrypt do not.
		{"backup without configuration", nil, []string{"backup", "--recipient", "age1x"}, 1, "ISSUER_URL"},
		{"restore without configuration", nil, []string{"restore", file}, 1, "ISSUER_URL"},
		{"deletions needs export", nil, []string{"deletions"}, 2, "usage:"},
		{"deletions export without configuration", nil, []string{"deletions", "export"}, 1, "ISSUER_URL"},
		{"a missing deletion log", nil, []string{"restore", "--apply-deletions", file + ".nope", file}, 1, "ISSUER_URL"},
	}
	for _, c := range cases {
		code, stdout, stderr := run(t, c.stdin, c.args...)
		if code != c.code || !strings.Contains(stderr, c.stderr) {
			t.Errorf("%s: exit %d, stderr %q; want exit %d and %q", c.name, code, stderr, c.code, c.stderr)
		}
		if stdout != "" {
			t.Errorf("%s: wrote %q to stdout, which only ever carries backup data", c.name, stdout)
		}
	}
}

func TestOutputFileIsRemovedWhenTheCommandFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.gbk")
	w, finish, err := output(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("half a backup"))
	if err := finish(errors.New("failed")); err == nil {
		t.Fatal("the error was lost")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a half-written backup was left behind")
	}
	os.WriteFile(path, []byte("old"), 0o600)
	if _, _, err := output(path, nil); err == nil {
		t.Error("an existing file was overwritten")
	}
}

// Covers: P3, P4
func TestKeysCommandLine(t *testing.T) {
	noConfig := func() (config.Config, error) { return config.Config{}, errors.New("ISSUER_URL is required") }
	for _, c := range []struct {
		args   []string
		code   int
		stderr string
	}{
		{[]string{"keys"}, 2, "usage:"},
		{[]string{"keys", "burn"}, 2, "unknown command"},
		{[]string{"keys", "rotate", "--now"}, 2, "both --now and --revoke-current"},
		{[]string{"keys", "rotate", "--execute"}, 2, "--reason is required"},
		{[]string{"mfa", "reset-totp"}, 2, "--all"},
		{[]string{"keys", "list", "extra"}, 2, "unexpected arguments"},
		{[]string{"keys", "list"}, 1, "ISSUER_URL"},
	} {
		var out, errOut bytes.Buffer
		code := runKeysCommand(c.args, &out, &errOut, noConfig)
		if code != c.code || !strings.Contains(errOut.String(), c.stderr) {
			t.Errorf("%v: exit %d, stderr %q; want %d and %q", c.args, code, errOut.String(), c.code, c.stderr)
		}
	}
}

// Covers: P2
func TestPruneBackupsKeepsTheNewestWithTheirDeletionLogs(t *testing.T) {
	dir := t.TempDir()
	stamps := []string{"20261101T020000Z", "20261102T020000Z", "20261103T020000Z", "20261104T020000Z"}
	for _, s := range stamps {
		os.WriteFile(filepath.Join(dir, "guardian-"+s+".gbk"), nil, 0o600)
		os.WriteFile(filepath.Join(dir, "deletions-"+s+".log"), nil, 0o600)
	}
	os.WriteFile(filepath.Join(dir, "notes.txt"), nil, 0o600)
	removed, err := pruneBackups(dir, 2)
	if err != nil || strings.Join(removed, ",") != "guardian-20261101T020000Z.gbk,guardian-20261102T020000Z.gbk" {
		t.Fatalf("removed %v (%v)", removed, err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*"))
	var names []string
	for _, l := range left {
		names = append(names, filepath.Base(l))
	}
	if strings.Join(names, ",") != "deletions-20261103T020000Z.log,deletions-20261104T020000Z.log,guardian-20261103T020000Z.gbk,guardian-20261104T020000Z.gbk,notes.txt" {
		t.Errorf("left: %v", names)
	}
	if removed, _ := pruneBackups(dir, 0); removed != nil {
		t.Error("keep 0 must keep everything")
	}
}
