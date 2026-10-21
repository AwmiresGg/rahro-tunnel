package store

import "database/sql"

// Node roles and serving modes.
const (
	RolePanel    = "panel"
	RoleLocation = "location" // foreign egress
	RoleTunnel   = "tunnel"   // Iran relay

	ServingStandard = "standard"
	ServingRahro    = "rahro"
	ServingBoth     = "both"
)

// Node is a panel-managed server (location egress or Iran tunnel relay).
type Node struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Location    string `json:"location"`
	Address     string `json:"address"`
	Upstream    string `json:"upstream"`
	ServingMode string `json:"serving_mode"`
	EnrollToken string `json:"enroll_token,omitempty"`
	Secret      string `json:"-"` // never serialized to clients
	Enabled     bool   `json:"enabled"`
	LastSeen    int64  `json:"last_seen"`
	CreatedAt   int64  `json:"created_at"`
}

const nodeCols = `id, name, role, location, address, upstream, serving_mode, enroll_token, secret, enabled, last_seen, created_at`

func scanNode(sc interface{ Scan(...any) error }) (*Node, error) {
	var n Node
	var enabled int
	if err := sc.Scan(&n.ID, &n.Name, &n.Role, &n.Location, &n.Address, &n.Upstream,
		&n.ServingMode, &n.EnrollToken, &n.Secret, &enabled, &n.LastSeen, &n.CreatedAt); err != nil {
		return nil, err
	}
	n.Enabled = enabled != 0
	return &n, nil
}

// CreateNode inserts a node (typically with an enroll token, no secret yet).
func (s *Store) CreateNode(n *Node) (*Node, error) {
	n.CreatedAt = now()
	if n.ServingMode == "" {
		n.ServingMode = ServingBoth
	}
	res, err := s.db.Exec(
		`INSERT INTO nodes (name, role, location, address, upstream, serving_mode, enroll_token, secret, enabled, last_seen, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		n.Name, n.Role, n.Location, n.Address, n.Upstream, n.ServingMode,
		n.EnrollToken, n.Secret, b2i(n.Enabled), n.LastSeen, n.CreatedAt)
	if err != nil {
		return nil, err
	}
	n.ID, _ = res.LastInsertId()
	return n, nil
}

// ListNodes returns all nodes.
func (s *Store) ListNodes() ([]*Node, error) {
	rows, err := s.db.Query(`SELECT ` + nodeCols + ` FROM nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GetNode looks up a node by id.
func (s *Store) GetNode(id int64) (*Node, error) {
	n, err := scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return n, err
}

// EnrollNode finds a node by its one-time enroll token, stores the shared
// secret, clears the token, and records first contact. Returns the node.
func (s *Store) EnrollNode(enrollToken, secret string) (*Node, error) {
	n, err := scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE enroll_token = ? AND enroll_token != ''`, enrollToken))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(`UPDATE nodes SET secret = ?, enroll_token = '', last_seen = ? WHERE id = ?`,
		secret, now(), n.ID); err != nil {
		return nil, err
	}
	n.Secret = secret
	n.EnrollToken = ""
	n.LastSeen = now()
	return n, nil
}

// AuthenticateNode returns the node matching an id+secret pair, or ErrNotFound.
func (s *Store) AuthenticateNode(id int64, secret string) (*Node, error) {
	n, err := s.GetNode(id)
	if err != nil {
		return nil, err
	}
	if n.Secret == "" || n.Secret != secret {
		return nil, ErrNotFound
	}
	return n, nil
}

// TouchNode updates a node's last-seen timestamp.
func (s *Store) TouchNode(id int64) error {
	_, err := s.db.Exec(`UPDATE nodes SET last_seen = ? WHERE id = ?`, now(), id)
	return err
}

// UpdateNode updates mutable fields.
func (s *Store) UpdateNode(n *Node) error {
	res, err := s.db.Exec(
		`UPDATE nodes SET name=?, role=?, location=?, address=?, upstream=?, serving_mode=?, enabled=? WHERE id=?`,
		n.Name, n.Role, n.Location, n.Address, n.Upstream, n.ServingMode, b2i(n.Enabled), n.ID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteNode removes a node.
func (s *Store) DeleteNode(id int64) error {
	res, err := s.db.Exec(`DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
