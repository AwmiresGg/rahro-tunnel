package xray

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/awmiresgg/rahro/panel/store"
)

func TestShareLinkVLESSReality(t *testing.T) {
	in := &store.Inbound{
		Tag: "reality-443", Protocol: store.ProtoVLESS, Port: 443,
		Network: "tcp", Security: "reality", Enabled: true,
		Settings: `{"publicKey":"PBKX","shortIds":["ab12"],"serverNames":["www.microsoft.com"],"flow":"xtls-rprx-vision"}`,
	}
	u := &store.User{UUID: "uuid-1", Enabled: true}
	link := ShareLink(in, u, "1.2.3.4")
	for _, want := range []string{"vless://uuid-1@1.2.3.4:443?", "security=reality", "pbk=PBKX", "sid=ab12", "sni=www.microsoft.com", "flow=xtls-rprx-vision", "type=tcp", "#reality-443"} {
		if !strings.Contains(link, want) {
			t.Fatalf("vless link missing %q:\n%s", want, link)
		}
	}
}

func TestShareLinkTrojanWSTLS(t *testing.T) {
	in := &store.Inbound{
		Tag: "trojan", Protocol: store.ProtoTrojan, Port: 2096,
		Network: "ws", Security: "tls", Enabled: true,
		Settings: `{"sni":"ex.com","path":"/t","host":"ex.com"}`,
	}
	link := ShareLink(in, &store.User{UUID: "pw1"}, "ex.com")
	for _, want := range []string{"trojan://pw1@ex.com:2096?", "type=ws", "security=tls", "sni=ex.com"} {
		if !strings.Contains(link, want) {
			t.Fatalf("trojan link missing %q:\n%s", want, link)
		}
	}
}

func TestShareLinkShadowsocks(t *testing.T) {
	in := &store.Inbound{Tag: "ss", Protocol: store.ProtoShadowsocks, Port: 8388, Enabled: true}
	link := ShareLink(in, &store.User{UUID: "secretpw"}, "host")
	if !strings.HasPrefix(link, "ss://") || !strings.Contains(link, "@host:8388") {
		t.Fatalf("bad ss link: %s", link)
	}
	raw := strings.TrimPrefix(strings.Split(link, "@")[0], "ss://")
	dec, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || !strings.Contains(string(dec), ":secretpw") {
		t.Fatalf("ss userinfo wrong: %q (%v)", dec, err)
	}
}

func TestShareLinkVMess(t *testing.T) {
	in := &store.Inbound{Tag: "vm", Protocol: store.ProtoVMess, Port: 80, Network: "ws", Security: "none", Enabled: true}
	link := ShareLink(in, &store.User{UUID: "vid"}, "h")
	if !strings.HasPrefix(link, "vmess://") {
		t.Fatalf("bad vmess link: %s", link)
	}
	dec, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	var m map[string]any
	if err := json.Unmarshal(dec, &m); err != nil {
		t.Fatalf("vmess json: %v", err)
	}
	if m["id"] != "vid" || m["add"] != "h" {
		t.Fatalf("vmess fields wrong: %+v", m)
	}
}
