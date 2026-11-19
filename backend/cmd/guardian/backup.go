package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"guardian/internal/backup"
	"guardian/internal/config"
	db "guardian/internal/store"
)

// The backup commands write data to stdout and everything meant for people to stderr, so that
// `kubectl exec ... -- guardian backup ... > file` captures only the backup.

const backupUsage = `usage:
  guardian backup [--execute --reason TEXT] (--recipient KEY ... | --recipients-file FILE) [--without-audit] [--out FILE]
  guardian backup verify [--identity-file FILE] [FILE|-]
  guardian backup decrypt --identity-file FILE [--out FILE] [FILE|-]
  guardian restore [--execute --reason TEXT --confirm HOST] [--identity-file FILE] [--allow-other-issuer] [FILE|-]

Without --execute, backup and restore only show what they would do. See docs/INSTALL.md, "Backup and restore".`

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// runBackupCommand runs `guardian backup ...` or `guardian restore ...` and returns the exit code.
func runBackupCommand(args []string, stdin io.Reader, stdout, stderr io.Writer, loadConfig func() (config.Config, error)) int {
	fail := func(err error) int {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	usage := func(msg string) int {
		if msg != "" {
			fmt.Fprintln(stderr, msg)
		}
		fmt.Fprintln(stderr, backupUsage)
		return 2
	}

	command, args := args[0], args[1:]
	if command == "backup" && len(args) > 0 && (args[0] == "verify" || args[0] == "decrypt") {
		command, args = "backup "+args[0], args[1:]
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		execute, withoutAudit, otherIssuer bool
		reason, recipientsFile, out        string
		identityFile, confirm              string
		recipients                         listFlag
	)
	switch command {
	case "backup":
		fs.BoolVar(&execute, "execute", false, "")
		fs.StringVar(&reason, "reason", "", "")
		fs.Var(&recipients, "recipient", "")
		fs.StringVar(&recipientsFile, "recipients-file", "", "")
		fs.BoolVar(&withoutAudit, "without-audit", false, "")
		fs.StringVar(&out, "out", "", "")
	case "backup verify":
		fs.StringVar(&identityFile, "identity-file", "", "")
	case "backup decrypt":
		fs.StringVar(&identityFile, "identity-file", "", "")
		fs.StringVar(&out, "out", "", "")
	case "restore":
		fs.BoolVar(&execute, "execute", false, "")
		fs.StringVar(&reason, "reason", "", "")
		fs.StringVar(&confirm, "confirm", "", "")
		fs.StringVar(&identityFile, "identity-file", "", "")
		fs.BoolVar(&otherIssuer, "allow-other-issuer", false, "")
	}
	if err := fs.Parse(args); err != nil {
		return usage(err.Error())
	}
	rest := fs.Args()
	wantsFile := command != "backup"
	if (!wantsFile && len(rest) > 0) || len(rest) > 1 {
		return usage("unexpected arguments: " + strings.Join(rest, " "))
	}

	var identities io.Reader
	if identityFile != "" {
		b, err := os.ReadFile(identityFile)
		if err != nil {
			return fail(err)
		}
		identities = strings.NewReader(string(b))
	}
	in := stdin
	if wantsFile && len(rest) == 1 && rest[0] != "-" {
		f, err := os.Open(rest[0])
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		in = f
	}

	// verify and decrypt run on the operator's machine: no configuration, no database.
	switch command {
	case "backup verify":
		if _, err := backup.Verify(in, identities, stderr); err != nil {
			return fail(err)
		}
		return 0
	case "backup decrypt":
		if identities == nil {
			return usage("decrypt needs --identity-file")
		}
		w, finish, err := output(out, stdout)
		if err != nil {
			return fail(err)
		}
		if err := finish(backup.DecryptFile(in, identities, w)); err != nil {
			return fail(err)
		}
		return 0
	}

	cfg, err := loadConfig()
	if err != nil {
		return fail(fmt.Errorf("invalid configuration: %w", err))
	}
	connectCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := db.Open(connectCtx, cfg.DB)
	if err != nil {
		return fail(err)
	}
	ctx := context.Background()
	opt := backup.Options{Issuer: cfg.IssuerURL, KeyEncryptionKey: cfg.KeyEncryptionKey, Execute: execute, Reason: reason}

	if command == "restore" {
		err := backup.Restore(ctx, conn, backup.RestoreOptions{
			Options: opt, Confirm: confirm, Identities: identities, AllowOtherIssuer: otherIssuer,
		}, in, stderr)
		if err != nil {
			return fail(err)
		}
		return 0
	}

	list := strings.Join(recipients, "\n")
	if recipientsFile != "" {
		b, err := os.ReadFile(recipientsFile)
		if err != nil {
			return fail(err)
		}
		list += "\n" + string(b)
	}
	w, finish := io.Writer(io.Discard), func(err error) error { return err }
	if execute {
		if w, finish, err = output(out, stdout); err != nil {
			return fail(err)
		}
	}
	if err := finish(backup.Backup(ctx, conn, backup.BackupOptions{Options: opt, Recipients: list, WithAudit: !withoutAudit}, w, stderr)); err != nil {
		return fail(err)
	}
	return 0
}

// output opens the file to write to, or stdout. finish closes the file, and removes it when the command
// failed, so a half-written backup never looks like a finished one.
func output(path string, stdout io.Writer) (io.Writer, func(error) error, error) {
	if path == "" || path == "-" {
		return stdout, func(err error) error { return err }, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, func(err error) error {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(path)
		}
		return err
	}, nil
}
