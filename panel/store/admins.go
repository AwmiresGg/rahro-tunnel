package store

import "database/sql"

// Admin is a panel administrator.
type Admin struct {
	ID           int64
	Username     string
	PasswordHash string
	TOTPSecret   string
	CreatedAt    int64
}

// CreateAdmin inserts a new admin.
func (s *Store) CreateAdmin(username, passwordHash string) (*Admin, error) {
	res, err := s.db.Exec(
		`INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)`,
		username, passwordHash, now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Admin{ID: id, Username: username, PasswordHash: passwordHash, CreatedAt: now()}, nil
}

// GetAdmin looks up an admin by username.
func (s *Store) GetAdmin(username string) (*Admin, error) {
	var a Admin
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, totp_secret, created_at FROM admins WHERE username = ?`,
		username).Scan(&a.ID, &a.Username, &a.PasswordHash, &a.TOTPSecret, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// UpdateAdminPassword sets a new password hash for an admin.
func (s *Store) UpdateAdminPassword(username, passwordHash string) error {
	res, err := s.db.Exec(`UPDATE admins SET password_hash = ? WHERE username = ?`, passwordHash, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateAdminCredentials changes an admin's username and/or password hash by id.
func (s *Store) UpdateAdminCredentials(id int64, username, passwordHash string) error {
	res, err := s.db.Exec(`UPDATE admins SET username = ?, password_hash = ? WHERE id = ?`,
		username, passwordHash, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountAdmins returns the number of admins (used to detect first-run).
func (s *Store) CountAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM admins`).Scan(&n)
	return n, err
}
