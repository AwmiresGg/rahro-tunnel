package xray

import (
	"encoding/json"
	"testing"

	"github.com/awmiresgg/rahro/panel/store"
)

func TestGenerateConfigVLESSReality(t *testing.T) {
	inbounds := []*store.Inbound{
		{
			Tag: "vless-reality", Protocol: store.ProtoVLESS, Port: 443,
			Network: "tcp", Security: "reality", Enabled: true,
			Settings: `{"flow":"xtls-rprx-vision","dest":"www.microsoft.com:443","serverNames":["www.microsoft.com"],"privateKey":"PK","shortIds":["ab"]}`,
		},
		{Tag: "disabled", Protocol: store.ProtoVLESS, Port: 8443, Enabled: false},
	}
	users := []*store.User{
		{Username: "a", UUID: "uuid-a", Enabled: true},
		{Username: "b", UUID: "uuid-b", Enabled: true},
		{Username: "expired", UUID: "uuid-c", Enabled: true, ExpiresAt: 1}, // inactive
	}

	cfg := GenerateConfig(inbounds, users)
	b, err := Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Valid JSON round-trips.
	var rt map[string]any
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	ins := cfg["inbounds"].([]map[string]any)
	if len(ins) != 1 {
		t.Fatalf("want 1 enabled inbound, got %d", len(ins))
	}
	ib := ins[0]
	if ib["protocol"] != "vless" {
		t.Fatalf("protocol = %v", ib["protocol"])
	}
	settings := ib["settings"].(map[string]any)
	clients := settings["clients"].([]map[string]any)
	if len(clients) != 2 {
		t.Fatalf("want 2 active clients, got %d", len(clients))
	}
	if clients[0]["id"] != "uuid-a" || clients[0]["flow"] != "xtls-rprx-vision" {
		t.Fatalf("client 0 wrong: %+v", clients[0])
	}
	if settings["decryption"] != "none" {
		t.Fatal("vless decryption should be none")
	}
	stream := ib["streamSettings"].(map[string]any)
	if stream["security"] != "reality" {
		t.Fatal("security should be reality")
	}
	r := stream["realitySettings"].(map[string]any)
	if r["privateKey"] != "PK" {
		t.Fatalf("reality privateKey missing: %+v", r)
	}
}

func TestGenerateConfigTrojanWSTLS(t *testing.T) {
	inbounds := []*store.Inbound{{
		Tag: "trojan-ws", Protocol: store.ProtoTrojan, Port: 2096,
		Network: "ws", Security: "tls", Enabled: true,
		Settings: `{"sni":"example.com","path":"/trojan","host":"example.com"}`,
	}}
	users := []*store.User{{Username: "u", UUID: "pw-uuid", Enabled: true}}

	cfg := GenerateConfig(inbounds, users)
	ib := cfg["inbounds"].([]map[string]any)[0]
	clients := ib["settings"].(map[string]any)["clients"].([]map[string]any)
	if clients[0]["password"] != "pw-uuid" {
		t.Fatalf("trojan client should use password: %+v", clients[0])
	}
	stream := ib["streamSettings"].(map[string]any)
	if stream["tlsSettings"].(map[string]any)["serverName"] != "example.com" {
		t.Fatal("tls serverName missing")
	}
	if stream["wsSettings"].(map[string]any)["path"] != "/trojan" {
		t.Fatal("ws path missing")
	}
}

func TestGenerateConfigShadowsocksDefaults(t *testing.T) {
	inbounds := []*store.Inbound{{Tag: "ss", Protocol: store.ProtoShadowsocks, Port: 8388, Enabled: true}}
	users := []*store.User{{Username: "u", UUID: "pw", Enabled: true}}
	cfg := GenerateConfig(inbounds, users)
	settings := cfg["inbounds"].([]map[string]any)[0]["settings"].(map[string]any)
	c := settings["clients"].([]map[string]any)[0]
	if c["method"] != "chacha20-ietf-poly1305" {
		t.Fatalf("default ss method wrong: %v", c["method"])
	}
	if settings["network"] != "tcp,udp" {
		t.Fatal("ss network should be tcp,udp")
	}
}

func TestGenerateConfigNoUsers(t *testing.T) {
	cfg := GenerateConfig(nil, nil)
	if len(cfg["inbounds"].([]map[string]any)) != 0 {
		t.Fatal("no inbounds expected")
	}
	if _, err := Marshal(cfg); err != nil {
		t.Fatal(err)
	}
}
