package logger

import (
	"log/slog"
	"os"
)

func Setup() {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	// Logger that writes to STDOUT
	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))

	// Set as default logger
	slog.SetDefault(logger)
}
