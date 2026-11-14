// Command guardian runs the Guardian server.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	"guardian/internal/config"
	"guardian/internal/server"
)

func main() {
	// .env is optional: in containers the variables are injected directly.
	envErr := godotenv.Load()

	cfg, err := config.Load()
	slog.SetDefault(newLogger(cfg.Log))
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
	err = server.Run(ctx, cfg)
	if errors.Is(err, context.Canceled) {
		// Asked to stop before startup finished, for example while waiting for the database.
		slog.Info("stopped during startup")
		return
	}
	if err != nil {
		slog.Error("Guardian stopped with an error", "error", err)
		os.Exit(1)
	}
}

func newLogger(cfg config.Log) *slog.Logger {
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
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
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
