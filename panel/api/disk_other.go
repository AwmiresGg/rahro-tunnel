//go:build !linux

package api

// diskUsage is a no-op on non-Linux hosts (the panel still runs; the dashboard
// disk gauge simply reads zero).
func diskUsage(path string) (total, used uint64) { return 0, 0 }
