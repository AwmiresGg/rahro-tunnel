package store

import "database/sql"

// Inbound protocols and transports the panel understands. These map onto Xray
// inbound config when the Xray core is managed (see the xray package).
const (
	ProtoVLESS       = "vless"
	ProtoVMess       = "vmess"
	ProtoTrojan      = "trojan"
	ProtoShadowsocks = "shadowsocks"
)

// Inbound is a server-side listener definition (protocol + port + transport +
// security). Active users are offered as clients on every enabled inbound.
type Inbound struct {
	ID        int64  `json:"id"`
	Tag       string `json:"tag"`
	Protocol  string `json:"protocol"`
	Listen    string `json:"listen"`
	Port      int    `json:"port"`
	Network   string `json:"network"`  // tcp|ws|grpc|http|quic
	Security  string `json:"security"` // none|tls|reality
	Settings  string `json:"settings"` // JSON blob (stream/flow/sni/dest/…)
	Remark    string `json:"remark"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
}

const inboundCols = `id, tag, protocol, listen, port, network, security, settings, remark, enabled, created_at`

func scanInbound(sc interface{ Scan(...any) error }) (*Inbound, error) {
	var in Inbound
	var enabled int
	if err := sc.Scan(&in.ID, &in.Tag, &in.Protocol, &in.Listen, &in.Port, &in.Network,
		&in.Security, &in.Settings, &in.Remark, &enabled, &in.CreatedAt); err != nil {
		return nil, err
	}
	in.Enabled = enabled != 0
	return &in, nil
}

// CreateInbound inserts a new inbound.
func (s *Store) CreateInbound(in *Inbound) (*Inbound, error) {
	in.CreatedAt = now()
	if in.Network == "" {
		in.Network = "tcp"
	}
	if in.Security == "" {
		in.Security = "tls"
	}
	if in.Settings == "" {
		in.Settings = "{}"
	}
	res, err := s.db.Exec(
		`INSERT INTO inbounds (tag, protocol, listen, port, network, security, settings, remark, enabled, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.Tag, in.Protocol, in.Listen, in.Port, in.Network, in.Security, in.Settings, in.Remark, b2i(in.Enabled), in.CreatedAt)
	if err != nil {
		return nil, err
	}
	in.ID, _ = res.LastInsertId()
	return in, nil
}

// ListInbounds returns all inbounds.
func (s *Store) ListInbounds() ([]*Inbound, error) {
	rows, err := s.db.Query(`SELECT ` + inboundCols + ` FROM inbounds ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Inbound
	for rows.Next() {
		in, err := scanInbound(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// GetInbound looks up an inbound by id.
func (s *Store) GetInbound(id int64) (*Inbound, error) {
	in, err := scanInbound(s.db.QueryRow(`SELECT `+inboundCols+` FROM inbounds WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return in, err
}

// UpdateInbound updates mutable fields of an inbound.
func (s *Store) UpdateInbound(in *Inbound) error {
	res, err := s.db.Exec(
		`UPDATE inbounds SET tag=?, protocol=?, listen=?, port=?, network=?, security=?, settings=?, remark=?, enabled=? WHERE id=?`,
		in.Tag, in.Protocol, in.Listen, in.Port, in.Network, in.Security, in.Settings, in.Remark, b2i(in.Enabled), in.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteInbound removes an inbound.
func (s *Store) DeleteInbound(id int64) error {
	res, err := s.db.Exec(`DELETE FROM inbounds WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
