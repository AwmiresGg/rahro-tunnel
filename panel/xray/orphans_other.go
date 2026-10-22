//go:build !linux

package xray

// killOrphans is a no-op on non-Linux hosts (orphan detection via /proc is
// Linux-specific; the panel still works, it just can't reap a stale Xray).
func (m *Manager) killOrphans() {}
