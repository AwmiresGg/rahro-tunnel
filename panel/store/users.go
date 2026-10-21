package store

import (
	"database/sql"
	"time"
)

// User is a tunnel user (subscriber).
type User struct {
	ID         int64  `json:"id"`
	Username   string `json:"username"`
	UUID       string `json:"uuid"`
	SubToken   string `json:"sub_token"`
	QuotaBytes int64  `json:"quota_bytes"` // 0 = unlimited
	UsedBytes  int64  `json:"used_bytes"`
	ExpiresAt  int64  `json:"expires_at"` // unix; 0 = never
	Enabled    bool   `json:"enabled"`
	CreatedAt  int64  `json:"created_at"`
}

// Active reports whether the user may currently connect.
func (u *User) Active() bool {
	if !u.Enabled {
		return false
	}
	if u.ExpiresAt > 0 && time.Now().Unix() > u.ExpiresAt {
		return false
	}
	if u.QuotaBytes > 0 && u.UsedBytes >= u.QuotaBytes {
		return false
	}
	return true
}

// CreateUser inserts a new user.
func (s *Store) CreateUser(u *User) (*User, error) {
	u.CreatedAt = now()
	res, err := s.db.Exec(
		`INSERT INTO users (username, uuid, sub_token, quota_bytes, used_bytes, expires_at, enabled, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Username, u.UUID, u.SubToken, u.QuotaBytes, u.UsedBytes, u.ExpiresAt, b2i(u.Enabled), u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.ID, _ = res.LastInsertId()
	return u, nil
}

const userCols = `id, username, uuid, sub_token, quota_bytes, used_bytes, expires_at, enabled, created_at`

func scanUser(sc interface{ Scan(...any) error }) (*User, error) {
	var u User
	var enabled int
	if err := sc.Scan(&u.ID, &u.Username, &u.UUID, &u.SubToken, &u.QuotaBytes, &u.UsedBytes, &u.ExpiresAt, &enabled, &u.CreatedAt); err != nil {
		return nil, err
	}
	u.Enabled = enabled != 0
	return &u, nil
}

// ListUsers returns all users, newest first.
func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) getUserBy(col, val string) (*User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE `+col+` = ?`, val))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

// GetUser looks up a user by id.
func (s *Store) GetUser(id int64) (*User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

// GetUserByUsername looks up a user by username.
func (s *Store) GetUserByUsername(username string) (*User, error) {
	return s.getUserBy("username", username)
}

// GetUserByUUID looks up a user by UUID.
func (s *Store) GetUserByUUID(uuid string) (*User, error) { return s.getUserBy("uuid", uuid) }

// GetUserBySubToken looks up a user by subscription token.
func (s *Store) GetUserBySubToken(tok string) (*User, error) { return s.getUserBy("sub_token", tok) }

// UpdateUser updates mutable fields of a user.
func (s *Store) UpdateUser(u *User) error {
	res, err := s.db.Exec(
		`UPDATE users SET username=?, quota_bytes=?, used_bytes=?, expires_at=?, enabled=? WHERE id=?`,
		u.Username, u.QuotaBytes, u.UsedBytes, u.ExpiresAt, b2i(u.Enabled), u.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AddUsage atomically increments a user's used bytes.
func (s *Store) AddUsage(id, delta int64) error {
	_, err := s.db.Exec(`UPDATE users SET used_bytes = used_bytes + ? WHERE id = ?`, delta, id)
	return err
}

// DeleteUser removes a user.
func (s *Store) DeleteUser(id int64) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
