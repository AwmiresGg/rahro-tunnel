package store

import "database/sql"

// APIToken is a token used by external integrations (e.g. a Telegram sales
// bot). Only the hash is stored; the plaintext is shown once at creation.
type APIToken struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Scopes    string `json:"scopes"`
	CreatedAt int64  `json:"created_at"`
	LastUsed  int64  `json:"last_used"`
}

// CreateAPIToken stores the hash of a token and returns the row.
func (s *Store) CreateAPIToken(name, tokenHash, scopes string) (*APIToken, error) {
	res, err := s.db.Exec(
		`INSERT INTO api_tokens (name, token_hash, scopes, created_at) VALUES (?, ?, ?, ?)`,
		name, tokenHash, scopes, now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &APIToken{ID: id, Name: name, Scopes: scopes, CreatedAt: now()}, nil
}

// ListAPITokens returns token metadata (never the secret).
func (s *Store) ListAPITokens() ([]*APIToken, error) {
	rows, err := s.db.Query(`SELECT id, name, scopes, created_at, last_used FROM api_tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Scopes, &t.CreatedAt, &t.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// AuthenticateAPIToken returns the token row matching a hash and records usage.
func (s *Store) AuthenticateAPIToken(tokenHash string) (*APIToken, error) {
	var t APIToken
	err := s.db.QueryRow(
		`SELECT id, name, scopes, created_at, last_used FROM api_tokens WHERE token_hash = ?`,
		tokenHash).Scan(&t.ID, &t.Name, &t.Scopes, &t.CreatedAt, &t.LastUsed)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.db.Exec(`UPDATE api_tokens SET last_used = ? WHERE id = ?`, now(), t.ID)
	return &t, nil
}

// DeleteAPIToken removes a token by id.
func (s *Store) DeleteAPIToken(id int64) error {
	res, err := s.db.Exec(`DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
