// Package version exposes build metadata for Rahro binaries.
//
// Values are overridable at build time via -ldflags, e.g.:
//
//	go build -ldflags "-X github.com/awmiresgg/rahro/core/version.Version=1.2.3"
package version

import "runtime/debug"

// These are set via -ldflags at release build time. They keep sensible
// defaults for `go run` / `go build` during development.
var (
	// Version is the semantic version of the build.
	Version = "0.0.0-dev"
	// Commit is the git commit the build was produced from.
	Commit = "unknown"
	// Date is the build timestamp (RFC3339).
	Date = "unknown"
)

// String returns a human-readable one-line version string.
func String() string {
	return "rahro " + Version + " (commit " + commitShort() + ", built " + Date + ")"
}

func commitShort() string {
	if Commit != "unknown" {
		if len(Commit) > 12 {
			return Commit[:12]
		}
		return Commit
	}
	// Fall back to VCS info embedded by the Go toolchain when available.
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				if len(s.Value) > 12 {
					return s.Value[:12]
				}
				return s.Value
			}
		}
	}
	return Commit
}
