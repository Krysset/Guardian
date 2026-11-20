package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"guardian/internal/auth"
	"guardian/internal/backup"
	"guardian/internal/config"
	db "guardian/internal/store"
)

// The backup commands write data to stdout and everything meant for people to stderr, so that
// `kubectl exec ... -- guardian backup ... > file` captures only the backup.

const backupUsage = `usage:
  guardian backup [--execute --reason TEXT] (--recipient KEY ... | --recipients-file FILE) [--without-audit]
                  [--out FILE | --out-dir DIR [--keep N]]
  guardian backup verify [--identity-file FILE] [FILE|-]
  guardian backup decrypt --identity-file FILE [--out FILE] [FILE|-]
  guardian restore [--execute --reason TEXT --confirm HOST] [--identity-file FILE] [--allow-other-issuer]
                   [--apply-deletions FILE] [FILE|-]
  guardian deletions export [--out FILE]

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
	if command == "deletions" {
		if len(args) == 0 || args[0] != "export" {
			return usage("")
		}
		command, args = "deletions export", args[1:]
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		execute, withoutAudit, otherIssuer   bool
		reason, recipientsFile, out, outDir  string
		identityFile, confirm, deletionsFile string
		recipients                           listFlag
		keep                                 int
	)
	switch command {
	case "backup":
		fs.BoolVar(&execute, "execute", false, "")
		fs.StringVar(&reason, "reason", "", "")
		fs.Var(&recipients, "recipient", "")
		fs.StringVar(&recipientsFile, "recipients-file", "", "")
		fs.BoolVar(&withoutAudit, "without-audit", false, "")
		fs.StringVar(&out, "out", "", "")
		fs.StringVar(&outDir, "out-dir", "", "")
		fs.IntVar(&keep, "keep", 0, "")
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
		fs.StringVar(&deletionsFile, "apply-deletions", "", "")
	case "deletions export":
		fs.StringVar(&out, "out", "", "")
	}
	if err := fs.Parse(args); err != nil {
		return usage(err.Error())
	}
	rest := fs.Args()
	if outDir != "" && (out != "" || !execute) {
		return usage("--out-dir needs --execute, and not --out")
	}
	if keep < 0 || (keep > 0 && outDir == "") {
		return usage("--keep needs --out-dir and a number of backups to keep")
	}
	wantsFile := command != "backup" && command != "deletions export"
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
	ring, err := auth.ParseKeyring(cfg.Keyring)
	if err != nil {
		return fail(fmt.Errorf("the encryption keyring: %w", err))
	}
	auth.SetKeyring(ring)
	opt := backup.Options{Issuer: cfg.IssuerURL, Keyring: ring, Execute: execute, Reason: reason}

	if command == "deletions export" {
		w, finish, err := output(out, stdout)
		if err != nil {
			return fail(err)
		}
		n, err := backup.ExportDeletions(ctx, conn, w)
		if err := finish(err); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stderr, "Wrote %d deletion log entries.\n", n)
		return 0
	}

	if command == "restore" {
		var deletions []db.Deletion
		if deletionsFile != "" {
			f, err := os.Open(deletionsFile)
			if err != nil {
				return fail(err)
			}
			deletions, err = backup.ReadDeletions(f)
			f.Close()
			if err != nil {
				return fail(err)
			}
		}
		err := backup.Restore(ctx, conn, backup.RestoreOptions{
			Options: opt, Confirm: confirm, Identities: identities, AllowOtherIssuer: otherIssuer, Deletions: deletions,
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
	stamp := time.Now().UTC().Format("20060102T150405Z")
	if outDir != "" {
		out = filepath.Join(outDir, "guardian-"+stamp+".gbk")
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
	if outDir == "" {
		return 0
	}
	// A scheduled backup (the chart's CronJob): the deletion log goes next to it, and old ones are removed.
	dw, finishDeletions, err := output(filepath.Join(outDir, "deletions-"+stamp+".log"), stdout)
	if err != nil {
		return fail(err)
	}
	n, err := backup.ExportDeletions(ctx, conn, dw)
	if err := finishDeletions(err); err != nil {
		return fail(err)
	}
	fmt.Fprintf(stderr, "Wrote %s and its deletion log (%d entries).\n", out, n)
	removed, err := pruneBackups(outDir, keep)
	for _, name := range removed {
		fmt.Fprintf(stderr, "Removed the old backup %s.\n", name)
	}
	if err != nil {
		return fail(err)
	}
	return 0
}

// pruneBackups keeps the newest keep backups in dir (guardian-<time>.gbk, with their deletions-<time>.log)
// and removes the rest. keep 0 keeps everything. The names sort by time.
func pruneBackups(dir string, keep int) ([]string, error) {
	if keep == 0 {
		return nil, nil
	}
	backups, err := filepath.Glob(filepath.Join(dir, "guardian-*.gbk"))
	if err != nil || len(backups) <= keep {
		return nil, err
	}
	sort.Strings(backups)
	var removed []string
	for _, b := range backups[:len(backups)-keep] {
		stamp := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(b), "guardian-"), ".gbk")
		if err := os.Remove(b); err != nil {
			return removed, err
		}
		if err := os.Remove(filepath.Join(dir, "deletions-"+stamp+".log")); err != nil && !os.IsNotExist(err) {
			return removed, err
		}
		removed = append(removed, filepath.Base(b))
	}
	return removed, nil
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
