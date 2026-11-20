package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"guardian/internal/auth"
	"guardian/internal/backup"
	"guardian/internal/config"
	"guardian/internal/mail"
	db "guardian/internal/store"
)

// The runbook commands for keys (docs/INSTALL.md, "Keys"):
//
//	guardian keys list                        the signing keys and their stages, and the keyring
//	guardian keys rotate                      publish a new signing key now; it signs after an hour
//	guardian keys rotate --now --revoke-current   the emergency path: a new key signs at once, the old one is withdrawn
//	guardian keys reencrypt                   move every encrypted value to the keyring's first key now
//	guardian mfa reset-totp --all             remove every authenticator app (after a keyring key leaked)
//
// Like backup and restore, the changing ones are dry runs without --execute and need --reason; the
// emergency rotation and the reset also need --confirm with the issuer host. Each run is audited.

const keysUsage = `usage:
  guardian keys list
  guardian keys rotate [--execute --reason TEXT]
  guardian keys rotate --now --revoke-current [--execute --reason TEXT --confirm HOST]
  guardian keys reencrypt [--execute --reason TEXT]
  guardian mfa reset-totp --all [--execute --reason TEXT --confirm HOST]

Without --execute, the commands only show what they would do. See docs/INSTALL.md, "Keys".`

func runKeysCommand(args []string, stdout, stderr io.Writer, loadConfig func() (config.Config, error)) int {
	fail := func(err error) int {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	usage := func(msg string) int {
		if msg != "" {
			fmt.Fprintln(stderr, msg)
		}
		fmt.Fprintln(stderr, keysUsage)
		return 2
	}
	if len(args) < 2 {
		return usage("")
	}
	command := args[0] + " " + args[1]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		execute, now, revoke, all bool
		reason, confirm           string
	)
	switch command {
	case "keys list":
	case "keys rotate":
		fs.BoolVar(&now, "now", false, "")
		fs.BoolVar(&revoke, "revoke-current", false, "")
		fallthrough
	case "keys reencrypt":
		fs.BoolVar(&execute, "execute", false, "")
		fs.StringVar(&reason, "reason", "", "")
		fs.StringVar(&confirm, "confirm", "", "")
	case "mfa reset-totp":
		fs.BoolVar(&all, "all", false, "")
		fs.BoolVar(&execute, "execute", false, "")
		fs.StringVar(&reason, "reason", "", "")
		fs.StringVar(&confirm, "confirm", "", "")
	default:
		return usage("unknown command: " + command)
	}
	if err := fs.Parse(args[2:]); err != nil {
		return usage(err.Error())
	}
	if fs.NArg() > 0 {
		return usage("unexpected arguments: " + strings.Join(fs.Args(), " "))
	}
	if now != revoke {
		return usage("the emergency path takes both --now and --revoke-current")
	}
	if command == "mfa reset-totp" && !all {
		return usage("reset-totp only works on every account: add --all (one account is reset in the admin area)")
	}
	destructive := now || command == "mfa reset-totp"
	if execute && strings.TrimSpace(reason) == "" {
		return usage("--reason is required with --execute: it goes into the audit log")
	}

	cfg, err := loadConfig()
	if err != nil {
		return fail(fmt.Errorf("invalid configuration: %w", err))
	}
	if execute && destructive && confirm != backup.IssuerHost(cfg.IssuerURL) {
		return fail(fmt.Errorf("--confirm must be this installation's issuer host, %q", backup.IssuerHost(cfg.IssuerURL)))
	}
	connectCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := db.Open(connectCtx, cfg.DB); err != nil {
		return fail(err)
	}
	ring, err := auth.ParseKeyring(cfg.Keyring)
	if err != nil {
		return fail(fmt.Errorf("the encryption keyring: %w", err))
	}
	auth.SetKeyring(ring)
	audit := func(event string, meta map[string]any) {
		meta["via"], meta["reason"] = "cli", reason
		db.Audit(event, "", "", "", meta)
	}

	switch command {
	case "keys list":
		return listKeys(stdout, ring)

	case "keys reencrypt":
		counts, err := auth.ValuesPerKey()
		if err != nil {
			return fail(err)
		}
		if err := auth.CheckKeyring(ring); err != nil {
			return fail(err)
		}
		left := 0
		for id, n := range counts {
			if id != ring.Primary().ID {
				left += n
			}
		}
		if !execute {
			fmt.Fprintf(stderr, "Dry run: %d values would move to key %s. Guardian also does this by itself every minute.\n", left, ring.Primary().ID)
			return 0
		}
		n, err := auth.Reencrypt()
		if err != nil {
			return fail(err)
		}
		audit("keyring.reencrypted", map[string]any{"values": n, "key_id": ring.Primary().ID})
		fmt.Fprintf(stderr, "Re-encrypted %d values with key %s.\n", n, ring.Primary().ID)
		return 0

	case "keys rotate":
		active, err := db.GetActiveSigningKey()
		if err != nil {
			return fail(err)
		}
		if !execute {
			if now {
				fmt.Fprintf(stderr, "Dry run: a new key would sign at once, and the current key %s would be withdrawn at once.\n"+
					"Tokens it signed stop verifying wherever Guardian's keys are fetched again; apps that cache them keep\n"+
					"accepting such tokens until their cache expires. Restart or refresh the apps afterwards.\n", active.KID)
			} else {
				fmt.Fprintf(stderr, "Dry run: a new key would be published now and sign in about an hour; %s would then retire.\n", active.KID)
			}
			return 0
		}
		k, err := auth.NewSigningKey()
		if err != nil {
			return fail(err)
		}
		if now {
			retired, err := db.EmergencyRotate(k)
			if err != nil {
				return fail(err)
			}
			audit("signing_key.revoked", map[string]any{"kid": k.KID, "retired": retired, "by": "emergency"})
			fmt.Fprintf(stderr, "Key %s signs now; withdrawn: %s. Every replica follows within a minute.\n"+
				"Now restart or refresh the apps, so they drop the withdrawn key from their caches.\n", k.KID, strings.Join(retired, ", "))
			return 0
		}
		if err := db.AddPendingSigningKey(k); errors.Is(err, db.ErrKeyPending) {
			return fail(errors.New("a new key is already pending; it signs within the hour"))
		} else if err != nil {
			return fail(err)
		}
		audit("signing_key.created", map[string]any{"kid": k.KID, "by": "hand"})
		fmt.Fprintf(stderr, "Key %s is published and signs in about an hour; %s then retires.\n", k.KID, active.KID)
		return 0

	case "mfa reset-totp":
		accounts, err := db.TOTPAccounts()
		if err != nil {
			return fail(err)
		}
		if !execute {
			fmt.Fprintf(stderr, "Dry run: %d accounts would lose their authenticator app and recovery codes, and be emailed.\n"+
				"Administrators and group owners set it up again at their next sign-in.\n", len(accounts))
			return 0
		}
		if m := cfg.Mail; m.Enabled() {
			mail.Configure(mail.SMTP{Host: m.Host, Port: m.Port, Username: m.Username, Password: m.Password,
				Security: m.Security, From: *m.From}, mail.Site{Name: m.From.Name, Host: backup.IssuerHost(cfg.IssuerURL)})
		}
		n, err := db.RemoveAllTOTP()
		if err != nil {
			return fail(err)
		}
		audit("mfa.reset_all", map[string]any{"accounts": len(accounts), "rows": n})
		emailed := 0
		for _, a := range accounts {
			if a.Email != "" {
				mail.Enqueue(mail.TwoFactorReset(a.Email, reason, time.Now(), a.Zoneinfo))
				emailed++
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := mail.Wait(ctx); err != nil {
			fmt.Fprintln(stderr, "warning: not every email was sent in time")
		}
		fmt.Fprintf(stderr, "Removed the authenticator apps of %d accounts; %d were emailed.\n", len(accounts), emailed)
		return 0
	}
	return usage("")
}

func listKeys(w io.Writer, ring *auth.Keyring) int {
	keys, err := db.ListSigningKeys()
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		return 1
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SIGNING KEY\tSTAGE\tCREATED\tSIGNS FROM\tUNPUBLISHED FROM")
	day := func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.UTC().Format("2006-01-02 15:04")
	}
	for _, k := range keys {
		until := k.RetireAt
		if k.RetiredAt != nil {
			until = k.RetiredAt
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", k.KID, k.Status, day(&k.CreatedAt), day(k.ActivatedAt), day(until))
	}
	tw.Flush()
	counts, err := auth.ValuesPerKey()
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		return 1
	}
	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KEYRING KEY\tFINGERPRINT\tROLE\tVALUES")
	for i, k := range ring.Keys() {
		role := "decrypts"
		if i == 0 {
			role = "encrypts"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", k.ID, k.Fingerprint(), role, counts[k.ID])
		delete(counts, k.ID)
	}
	for id, n := range counts {
		fmt.Fprintf(tw, "%s\t(missing)\t-\t%d\n", id, n)
	}
	tw.Flush()
	return 0
}
