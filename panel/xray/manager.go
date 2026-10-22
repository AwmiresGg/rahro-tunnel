package xray

import (
	"archive/zip"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

// releaseURL is the latest Xray-core release asset for the running arch.
func releaseURL() (string, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip", true
	case "arm64":
		return "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip", true
	default:
		return "", false
	}
}

// Manager downloads and supervises the Xray-core binary, feeding it configs
// generated from the panel's inbounds/users.
type Manager struct {
	dir  string // working dir, e.g. /etc/rahro/xray
	log  *slog.Logger
	mu   sync.Mutex
	cmd  *exec.Cmd
	logf *os.File
}

// NewManager creates a manager rooted at dir.
func NewManager(dir string, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Manager{dir: dir, log: log}
}

func (m *Manager) binPath() string  { return filepath.Join(m.dir, "xray") }
func (m *Manager) confPath() string { return filepath.Join(m.dir, "config.json") }

// Installed reports whether the Xray binary is present.
func (m *Manager) Installed() bool {
	st, err := os.Stat(m.binPath())
	return err == nil && !st.IsDir()
}

// EnsureBinary downloads and extracts the Xray binary if it is not present.
func (m *Manager) EnsureBinary() error {
	if m.Installed() {
		return nil
	}
	url, ok := releaseURL()
	if !ok {
		return fmt.Errorf("xray: unsupported arch %s", runtime.GOARCH)
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return err
	}
	m.log.Info("downloading xray-core", "url", url)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("xray download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("xray download: HTTP %d", resp.StatusCode)
	}
	zipPath := filepath.Join(m.dir, "xray.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()
	defer os.Remove(zipPath)

	if err := extractFile(zipPath, "xray", m.binPath()); err != nil {
		return err
	}
	// Also extract geo data if present (best-effort).
	_ = extractFile(zipPath, "geoip.dat", filepath.Join(m.dir, "geoip.dat"))
	_ = extractFile(zipPath, "geosite.dat", filepath.Join(m.dir, "geosite.dat"))
	return os.Chmod(m.binPath(), 0o755)
}

// extractFile pulls a single named entry out of a zip into dst.
func extractFile(zipPath, name, dst string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, zf := range zr.File {
		if zf.Name != name {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, rc)
		return err
	}
	return fmt.Errorf("xray: %q not found in archive", name)
}

// Apply writes the config and (re)starts Xray with it.
func (m *Manager) Apply(cfg map[string]any) error {
	b, err := Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return err
	}
	tmp := m.confPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.confPath()); err != nil {
		return err
	}
	return m.restart()
}

// Start launches Xray with the current config.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startLocked()
}

func (m *Manager) restart() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return m.startLocked()
}

func (m *Manager) startLocked() error {
	if !m.Installed() {
		return fmt.Errorf("xray: binary not installed (call EnsureBinary)")
	}
	lf, err := os.OpenFile(filepath.Join(m.dir, "xray.log"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(m.binPath(), "run", "-c", m.confPath())
	cmd.Dir = m.dir
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		return fmt.Errorf("xray start: %w", err)
	}
	m.cmd = cmd
	m.logf = lf
	go func() { _ = cmd.Wait() }() // reap
	m.log.Info("xray started", "pid", cmd.Process.Pid)
	return nil
}

// Stop terminates the Xray process if running.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return nil
}

func (m *Manager) stopLocked() {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		m.cmd = nil
	}
	if m.logf != nil {
		m.logf.Close()
		m.logf = nil
	}
}

// Running reports whether Xray is currently supervised and alive.
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmd != nil && m.cmd.Process != nil
}

// Version returns the Xray binary's version string.
func (m *Manager) Version() (string, error) {
	if !m.Installed() {
		return "", fmt.Errorf("xray not installed")
	}
	out, err := exec.Command(m.binPath(), "version").Output()
	if err != nil {
		return "", err
	}
	return firstLine(string(out)), nil
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
