package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultIsValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("Default() should validate, got: %v", err)
	}
	if c.Server == nil || c.Panel == nil {
		t.Fatal("Default() should include server and panel sections")
	}
	if c.Server.Transport != "tls" {
		t.Errorf("default transport = %q, want tls", c.Server.Transport)
	}
	if c.Panel.TLSMode != PanelTLSSelfSigned {
		t.Errorf("default panel TLS mode = %q, want self-signed", c.Panel.TLSMode)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rahro.json")

	orig := Default()
	orig.Server.Reality.Decoy = "www.cloudflare.com:443"
	orig.Panel.Listen = "0.0.0.0:9000"
	if err := orig.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Server.Reality.Decoy != "www.cloudflare.com:443" {
		t.Errorf("decoy round-trip = %q", got.Server.Reality.Decoy)
	}
	if got.Panel.Listen != "0.0.0.0:9000" {
		t.Errorf("panel listen round-trip = %q", got.Panel.Listen)
	}
}

func TestLoadOrDefaultMissingFile(t *testing.T) {
	c, err := LoadOrDefault(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("LoadOrDefault on missing file should return default, got: %v", err)
	}
	if c.Server == nil {
		t.Fatal("expected default config with server section")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"server":{"listen":":443","transport":"tls","reality":{"decoy":"x:1"}},"typo_field":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load should reject unknown fields")
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"empty everything", func(c *Config) { c.Server = nil; c.Client = nil; c.Panel = nil }, true},
		{"bad transport", func(c *Config) { c.Server.Transport = "carrier-pigeon" }, true},
		{"missing decoy", func(c *Config) { c.Server.Reality.Decoy = "" }, true},
		{"bad listen port", func(c *Config) { c.Server.Listen = ":70000" }, true},
		{"non-numeric port", func(c *Config) { c.Server.Listen = ":https" }, true},
		{"panel domain mode without domain", func(c *Config) { c.Panel.TLSMode = PanelTLSDomain }, true},
		{"panel base path without slash", func(c *Config) { c.Panel.BasePath = "secret" }, true},
		{"valid default", func(c *Config) {}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Default()
			tt.mutate(c)
			err := c.Validate()
			if tt.wantErr != (err != nil) {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestClientValidation(t *testing.T) {
	c := &Config{Client: &ClientConfig{
		Server:    "vps.example.com:443",
		PublicKey: "AAAA",
		UUID:      "00112233445566778899aabbccddeeff",
		SOCKS:     "127.0.0.1:1080",
	}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid client rejected: %v", err)
	}
	// Missing inbound should fail.
	c.Client.SOCKS = ""
	c.Client.HTTP = ""
	if err := c.Validate(); err == nil {
		t.Fatal("client with no inbound should fail validation")
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("RAHRO_LOG_LEVEL", "debug")
	t.Setenv("RAHRO_PANEL_LISTEN", "1.2.3.4:5555")
	c, err := LoadOrDefault("")
	if err != nil {
		t.Fatalf("LoadOrDefault: %v", err)
	}
	if c.LogLevel != "debug" {
		t.Errorf("env log level override failed: %q", c.LogLevel)
	}
	if c.Panel.Listen != "1.2.3.4:5555" {
		t.Errorf("env panel listen override failed: %q", c.Panel.Listen)
	}
}
