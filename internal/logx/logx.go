// Package logx provides a thin, dependency-free logging layer built on the
// standard library's log/slog. It centralizes level parsing and handler
// construction so every Rahro binary logs consistently.
package logx

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format selects the on-disk/stdout encoding of log records.
type Format string

const (
	// FormatText is human-friendly key=value output (default for dev).
	FormatText Format = "text"
	// FormatJSON is machine-parseable output (recommended in production).
	FormatJSON Format = "json"
)

// Options configures a logger.
type Options struct {
	// Level is one of: debug, info, warn, error (case-insensitive).
	Level string
	// Format is "text" or "json".
	Format Format
	// Output is where records are written; defaults to os.Stderr when nil.
	Output io.Writer
	// AddSource includes file:line of the log call site.
	AddSource bool
}

// ParseLevel maps a string to an slog.Level. Unknown values fall back to Info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "info", "":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// New builds an *slog.Logger from Options.
func New(opts Options) *slog.Logger {
	out := opts.Output
	if out == nil {
		out = os.Stderr
	}
	handlerOpts := &slog.HandlerOptions{
		Level:     ParseLevel(opts.Level),
		AddSource: opts.AddSource,
	}
	var h slog.Handler
	switch opts.Format {
	case FormatJSON:
		h = slog.NewJSONHandler(out, handlerOpts)
	default:
		h = slog.NewTextHandler(out, handlerOpts)
	}
	return slog.New(h)
}

// NewDefault returns a sensible text logger at the given level, writing to
// stderr. Convenience for binaries that don't need custom output.
func NewDefault(level string) *slog.Logger {
	return New(Options{Level: level, Format: FormatText})
}
