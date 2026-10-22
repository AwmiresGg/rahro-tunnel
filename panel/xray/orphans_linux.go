//go:build linux

package xray

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// killOrphans kills any process running our Xray binary that this Manager does
// not currently own, so a stale Xray from a previous panel instance can't keep
// the inbound ports with an outdated config.
func (m *Manager) killOrphans() {
	bin := m.binPath()
	abs, err := filepath.Abs(bin)
	if err != nil {
		abs = bin
	}
	canon, err := filepath.EvalSymlinks(abs)
	if err != nil {
		canon = abs
	}
	own := -1
	if m.cmd != nil && m.cmd.Process != nil {
		own = m.cmd.Process.Pid
	}
	self := os.Getpid()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self || pid == own {
			continue
		}
		link, err := os.Readlink("/proc/" + e.Name() + "/exe")
		if err != nil {
			continue
		}
		// A replaced binary (e.g. after an update) shows " (deleted)".
		link = strings.TrimSuffix(link, " (deleted)")
		if link == abs || link == canon {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			m.log.Info("killed orphaned xray", "pid", pid)
		}
	}
}
