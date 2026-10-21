package logx

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":    slog.LevelDebug,
		"DEBUG":    slog.LevelDebug,
		"info":     slog.LevelInfo,
		"":         slog.LevelInfo,
		"warn":     slog.LevelWarn,
		"warning":  slog.LevelWarn,
		"error":    slog.LevelError,
		"nonsense": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNewWritesAtLevel(t *testing.T) {
	var buf bytes.Buffer
	log := New(Options{Level: "warn", Format: FormatText, Output: &buf})

	log.Debug("debug-should-be-filtered")
	log.Info("info-should-be-filtered")
	log.Warn("warn-should-appear")

	out := buf.String()
	if strings.Contains(out, "should-be-filtered") {
		t.Errorf("records below level leaked through: %q", out)
	}
	if !strings.Contains(out, "warn-should-appear") {
		t.Errorf("warn record missing: %q", out)
	}
}

func TestNewJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	log := New(Options{Level: "info", Format: FormatJSON, Output: &buf})
	log.Info("hello", "k", "v")
	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("expected JSON output, got %q", out)
	}
}
