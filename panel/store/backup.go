package store

import (
	"fmt"
	"os"
	"path/filepath"
)

// Backup returns a consistent snapshot of the entire database as a single
// SQLite file. It uses `VACUUM INTO`, which is safe to run against a live
// database (unlike copying the file while writers may be active).
func (s *Store) Backup() ([]byte, error) {
	tmp, err := os.MkdirTemp("", "rahro-backup")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	dst := filepath.Join(tmp, "backup.db")
	// VACUUM INTO requires the target not to exist.
	if _, err := s.db.Exec(`VACUUM INTO ?`, dst); err != nil {
		return nil, fmt.Errorf("store: backup: %w", err)
	}
	return os.ReadFile(dst)
}
