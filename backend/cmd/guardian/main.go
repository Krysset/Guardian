// Command guardian runs the Guardian server.
//
//	guardian            start the server (the default)
//	guardian serve      the same
//	guardian migrate    apply pending database migrations, then exit
//	guardian backup     write an encrypted backup to stdout (see backup.go)
//	guardian restore    restore a backup into a new installation
//	guardian deletions  export the deletion log (ids of erased accounts), for restores
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	// Time zone data inside the binary: emails show times in each account's zone, and the image has none.
	_ "time/tzdata"

	"github.com/joho/godotenv"

	"guardian/internal/config"
	"guardian/internal/server"
)

func main() {
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	// .env is optional: in containers the variables are injected directly.
	envErr := godotenv.Load()

	if command == "backup" || command == "restore" || command == "deletions" {
		// stdout carries the backup, so log lines go to stderr.
		os.Exit(runBackupCommand(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, func() (config.Config, error) {
			cfg, err := config.Load()
			slog.SetDefault(newLogger(cfg.Log, os.Stderr))
			return cfg, err
		}))
	}
	if len(os.Args) > 2 || (command != "serve" && command != "migrate") {
		fmt.Fprintln(os.Stderr, "usage: guardian [serve|migrate|backup|restore|deletions]")
		os.Exit(2)
	}

	cfg, err := config.Load()
	slog.SetDefault(newLogger(cfg.Log, os.Stdout))
	if envErr != nil {
		slog.Debug("no .env file loaded", "error", envErr)
	}
	if err != nil {
		// Load joins every problem it found; log one line for each.
		for _, p := range flatten([]error{err}) {
			slog.Error("invalid configuration", "problem", p.Error())
		}
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if command == "migrate" {
		err = server.Migrate(ctx, cfg)
	} else {
		err = server.Run(ctx, cfg)
	}
	if errors.Is(err, context.Canceled) {
		// Asked to stop before startup finished, for example while waiting for the database.
		slog.Info("stopped during startup")
		return
	}
	if err != nil {
		slog.Error("Guardian stopped with an error", "command", command, "error", err)
		os.Exit(1)
	}
}

func newLogger(cfg config.Log, w io.Writer) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

// flatten expands joined errors, so nested lists of problems become one flat list.
func flatten(errs []error) []error {
	var out []error
	for _, e := range errs {
		if joined, ok := e.(interface{ Unwrap() []error }); ok {
			out = append(out, flatten(joined.Unwrap())...)
		} else {
			out = append(out, e)
		}
	}
	return out
}
