package xray

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/awmiresgg/rahro/panel/store"
)

// TestManagerIntegration downloads the real Xray binary, applies a generated
// config, and checks the process starts and listens. It is skipped unless
// RAHRO_XRAY_IT=1 (it pulls ~tens of MB and runs a process).
func TestManagerIntegration(t *testing.T) {
	if os.Getenv("RAHRO_XRAY_IT") == "" {
		t.Skip("set RAHRO_XRAY_IT=1 to run the Xray download+run integration test")
	}
	dir := t.TempDir()
	m := NewManager(dir, nil)
	if err := m.EnsureBinary(); err != nil {
		t.Fatalf("EnsureBinary: %v", err)
	}
	if !m.Installed() {
		t.Fatal("binary not installed after EnsureBinary")
	}
	v, err := m.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	t.Logf("xray version: %s", v)

	inbounds := []*store.Inbound{{
		Tag: "it", Protocol: store.ProtoVLESS, Port: 10800,
		Network: "tcp", Security: "none", Enabled: true,
	}}
	users := []*store.User{{
		Username: "u", UUID: "11111111-1111-1111-1111-111111111111", Enabled: true,
	}}
	if err := m.Apply(GenerateConfig(inbounds, users)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer m.Stop()

	time.Sleep(1500 * time.Millisecond)
	if !m.Running() {
		b, _ := os.ReadFile(dir + "/xray.log")
		t.Fatalf("xray not running; log:\n%s", b)
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:10800", 2*time.Second)
	if err != nil {
		b, _ := os.ReadFile(dir + "/xray.log")
		t.Fatalf("port 10800 not listening: %v; log:\n%s", err, b)
	}
	conn.Close()

	// The stats API inbound must be reachable and the StatsService must answer.
	// With no traffic yet the result is empty, but a successful call proves the
	// metering path (api inbound + routing + `xray api statsquery`) works.
	if _, err := m.QueryTraffic(false); err != nil {
		b, _ := os.ReadFile(dir + "/xray.log")
		t.Fatalf("QueryTraffic: %v; log:\n%s", err, b)
	}
}
