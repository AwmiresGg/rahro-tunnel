package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateUser(&User{Username: "u1", UUID: "x", SubToken: "t1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	data, err := st.Backup()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || string(data[:15]) != "SQLite format 3" {
		t.Fatalf("backup is not a SQLite file (len=%d)", len(data))
	}
	// The snapshot must be openable and contain the user.
	bpath := filepath.Join(dir, "restored.db")
	if err := os.WriteFile(bpath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(bpath)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if _, err := st2.GetUserByUsername("u1"); err != nil {
		t.Fatalf("restored db missing user: %v", err)
	}
}
