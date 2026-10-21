// Package config defines Rahro's configuration schema and a dependency-free
// loader (JSON file + environment-variable overrides) with validation.
//
// The schema is intentionally forward-looking: fields for transports, REALITY
// decoy settings, and the web panel exist now so later milestones can fill in
// behavior without reshaping configs users have already written.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config is the top-level Rahro configuration. A single config file can carry
// any subset of Server/Client/Panel; a binary uses the sections it needs.
type Config struct {
	LogLevel  string        `json:"log_level,omitempty"`
	LogFormat string        `json:"log_format,omitempty"`
	Server    *ServerConfig `json:"server,omitempty"`
	Client    *ClientConfig `json:"client,omitempty"`
	Panel     *PanelConfig  `json:"panel,omitempty"`
}

// ServerConfig describes the tunnel server (the VPS side).
type ServerConfig struct {
	// Listen is the address the tunnel accepts connections on, e.g. ":443".
	Listen string `json:"listen"`
	// Transport is the wire transport: tls|ws|grpc|h2|quic. (Only "tls" is
	// implemented before M5; others are accepted but not yet active.)
	Transport string `json:"transport"`
	// Reality holds REALITY-style decoy settings (see M3).
	Reality RealityConfig `json:"reality"`
}

// RealityConfig configures the REALITY-style active-probing defense: the
// server borrows a real decoy site's TLS and transparently proxies
// unauthenticated connections to it.
type RealityConfig struct {
	// Decoy is the real site whose TLS the server mimics / proxies to,
	// e.g. "www.microsoft.com:443".
	Decoy string `json:"decoy"`
	// PrivateKey is the server's long-term X25519 private key (base64). Empty
	// means "generate on first run and persist".
	PrivateKey string `json:"private_key,omitempty"`
	// ShortIDs are optional client-routing identifiers (hex), REALITY-style.
	ShortIDs []string `json:"short_ids,omitempty"`
}

// ClientConfig describes the client (user side) that dials the server.
type ClientConfig struct {
	// Server is the remote tunnel address, e.g. "vps.example.com:443".
	Server string `json:"server"`
	// Transport mirrors ServerConfig.Transport.
	Transport string `json:"transport"`
	// PublicKey is the server's long-term X25519 public key (base64).
	PublicKey string `json:"public_key"`
	// UUID identifies this user to the server (32 hex chars, dashes allowed).
	UUID string `json:"uuid"`
	// SNI is the TLS server name to present (should match the decoy).
	SNI string `json:"sni,omitempty"`
	// SOCKS is the local SOCKS5 inbound address, e.g. "127.0.0.1:1080".
	SOCKS string `json:"socks,omitempty"`
	// HTTP is the local HTTP-proxy inbound address, e.g. "127.0.0.1:1081".
	HTTP string `json:"http,omitempty"`
}

// PanelTLSMode selects how the web panel is exposed in a browser.
type PanelTLSMode string

const (
	// PanelTLSOff serves plain HTTP (e.g. http://<ip>:<port>) — quick setup/LAN.
	PanelTLSOff PanelTLSMode = "off"
	// PanelTLSSelfSigned serves HTTPS with an auto-generated self-signed cert
	// bound to the server IP (browser warning accepted). Works with no domain.
	PanelTLSSelfSigned PanelTLSMode = "self-signed"
	// PanelTLSDomain serves HTTPS with a real cert for a domain (ACME/
	// Let's Encrypt, or a user-supplied cert/key).
	PanelTLSDomain PanelTLSMode = "domain"
)

// PanelConfig configures the web admin panel (3x-ui-style single binary).
type PanelConfig struct {
	// Enabled turns the panel on.
	Enabled bool `json:"enabled"`
	// Listen is the panel bind address, e.g. "0.0.0.0:2053".
	Listen string `json:"listen"`
	// TLSMode is off|self-signed|domain (see PanelTLSMode).
	TLSMode PanelTLSMode `json:"tls_mode"`
	// Domain is required when TLSMode == domain.
	Domain string `json:"domain,omitempty"`
	// CertFile/KeyFile override automatic certs (used by self-signed/domain).
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	// BasePath is an optional secret URL prefix (e.g. "/x7f3a") to reduce
	// drive-by scanning of the panel.
	BasePath string `json:"base_path,omitempty"`
}

// Default returns a baseline config suitable for a fresh server+panel install.
func Default() *Config {
	return &Config{
		LogLevel:  "info",
		LogFormat: "text",
		Server: &ServerConfig{
			Listen:    ":443",
			Transport: "tls",
			Reality: RealityConfig{
				Decoy: "www.microsoft.com:443",
			},
		},
		Panel: &PanelConfig{
			Enabled: true,
			Listen:  "0.0.0.0:2053",
			TLSMode: PanelTLSSelfSigned,
		},
	}
}

// Load reads and validates a JSON config from path, then applies environment
// overrides. Missing optional fields keep their zero values.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	c.applyEnvOverrides()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadOrDefault loads path if it exists; otherwise returns Default(). It still
// applies environment overrides and validates in both cases.
func LoadOrDefault(path string) (*Config, error) {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return Load(path)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat config %q: %w", path, err)
		}
	}
	c := Default()
	c.applyEnvOverrides()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Save writes the config as indented JSON to path.
func (c *Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write config %q: %w", path, err)
	}
	return nil
}

// applyEnvOverrides lets a few key settings be overridden without editing the
// file — handy for containers and the install scripts.
func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("RAHRO_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("RAHRO_LOG_FORMAT"); v != "" {
		c.LogFormat = v
	}
	if v := os.Getenv("RAHRO_PANEL_LISTEN"); v != "" {
		if c.Panel == nil {
			c.Panel = &PanelConfig{Enabled: true}
		}
		c.Panel.Listen = v
	}
	if v := os.Getenv("RAHRO_SERVER_LISTEN"); v != "" {
		if c.Server == nil {
			c.Server = &ServerConfig{Transport: "tls"}
		}
		c.Server.Listen = v
	}
}

// Validate checks internal consistency and fills obvious defaults. It returns
// the first problem found so install scripts can surface a clear message.
func (c *Config) Validate() error {
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.LogFormat == "" {
		c.LogFormat = "text"
	}
	if c.LogFormat != string(logFormatText) && c.LogFormat != string(logFormatJSON) {
		return fmt.Errorf("log_format must be %q or %q, got %q", logFormatText, logFormatJSON, c.LogFormat)
	}

	if c.Server != nil {
		if err := c.Server.validate(); err != nil {
			return err
		}
	}
	if c.Client != nil {
		if err := c.Client.validate(); err != nil {
			return err
		}
	}
	if c.Panel != nil {
		if err := c.Panel.validate(); err != nil {
			return err
		}
	}
	if c.Server == nil && c.Client == nil && c.Panel == nil {
		return fmt.Errorf("config has no server, client, or panel section")
	}
	return nil
}

// mirror logx formats here without importing logx (config must stay low-level).
type logFormat string

const (
	logFormatText logFormat = "text"
	logFormatJSON logFormat = "json"
)

var validTransports = map[string]bool{
	"tls": true, "ws": true, "grpc": true, "h2": true, "quic": true,
}

func (s *ServerConfig) validate() error {
	if s.Listen == "" {
		return fmt.Errorf("server.listen is required")
	}
	if err := validateHostPort(s.Listen, true); err != nil {
		return fmt.Errorf("server.listen: %w", err)
	}
	if s.Transport == "" {
		s.Transport = "tls"
	}
	if !validTransports[s.Transport] {
		return fmt.Errorf("server.transport %q is not one of tls|ws|grpc|h2|quic", s.Transport)
	}
	if s.Reality.Decoy == "" {
		return fmt.Errorf("server.reality.decoy is required (e.g. www.microsoft.com:443)")
	}
	if err := validateHostPort(s.Reality.Decoy, false); err != nil {
		return fmt.Errorf("server.reality.decoy: %w", err)
	}
	return nil
}

func (c *ClientConfig) validate() error {
	if c.Server == "" {
		return fmt.Errorf("client.server is required")
	}
	if err := validateHostPort(c.Server, false); err != nil {
		return fmt.Errorf("client.server: %w", err)
	}
	if c.Transport == "" {
		c.Transport = "tls"
	}
	if !validTransports[c.Transport] {
		return fmt.Errorf("client.transport %q is not one of tls|ws|grpc|h2|quic", c.Transport)
	}
	if c.PublicKey == "" {
		return fmt.Errorf("client.public_key is required")
	}
	if c.UUID == "" {
		return fmt.Errorf("client.uuid is required")
	}
	if _, err := c.UserID(); err != nil {
		return fmt.Errorf("client.uuid: %w", err)
	}
	if c.SOCKS == "" && c.HTTP == "" {
		return fmt.Errorf("client needs at least one inbound (socks or http)")
	}
	return nil
}

// UserID parses the client UUID (32 hex chars, dashes optional) into 16 bytes.
func (c *ClientConfig) UserID() ([16]byte, error) {
	var id [16]byte
	hexStr := strings.ReplaceAll(c.UUID, "-", "")
	if len(hexStr) != 32 {
		return id, fmt.Errorf("must be 32 hex chars (16 bytes), got %d", len(hexStr))
	}
	for i := 0; i < 16; i++ {
		var b int
		if _, err := fmt.Sscanf(hexStr[i*2:i*2+2], "%02x", &b); err != nil {
			return id, fmt.Errorf("invalid hex: %w", err)
		}
		id[i] = byte(b)
	}
	return id, nil
}

func (p *PanelConfig) validate() error {
	if !p.Enabled {
		return nil
	}
	if p.Listen == "" {
		return fmt.Errorf("panel.listen is required when panel is enabled")
	}
	if err := validateHostPort(p.Listen, false); err != nil {
		return fmt.Errorf("panel.listen: %w", err)
	}
	switch p.TLSMode {
	case "":
		p.TLSMode = PanelTLSSelfSigned
	case PanelTLSOff, PanelTLSSelfSigned:
		// ok
	case PanelTLSDomain:
		if p.Domain == "" {
			return fmt.Errorf("panel.domain is required when tls_mode is %q", PanelTLSDomain)
		}
	default:
		return fmt.Errorf("panel.tls_mode %q is not one of off|self-signed|domain", p.TLSMode)
	}
	if p.BasePath != "" && !strings.HasPrefix(p.BasePath, "/") {
		return fmt.Errorf("panel.base_path must start with '/', got %q", p.BasePath)
	}
	return nil
}

// validateHostPort checks "host:port" (or ":port" when allowEmptyHost) and that
// the port is a valid TCP port number.
func validateHostPort(addr string, allowEmptyHost bool) error {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return fmt.Errorf("%q must be host:port", addr)
	}
	host, portStr := addr[:i], addr[i+1:]
	if host == "" && !allowEmptyHost {
		return fmt.Errorf("%q is missing a host", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("%q has a non-numeric port", addr)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range 1-65535", port)
	}
	return nil
}
