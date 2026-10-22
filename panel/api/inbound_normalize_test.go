package api

import (
	"encoding/json"
	"testing"

	"github.com/awmiresgg/rahro/panel/store"
)

func TestNormalizeRealityFillsEverything(t *testing.T) {
	s := &Server{} // nil Xray -> falls back to the crypto keypair generator
	in := &store.Inbound{Tag: "vr", Protocol: store.ProtoVLESS, Security: "reality"}
	s.normalizeInbound(in)

	var m map[string]any
	if err := json.Unmarshal([]byte(in.Settings), &m); err != nil {
		t.Fatalf("settings not valid JSON: %v", err)
	}
	for _, k := range []string{"privateKey", "publicKey", "serverNames", "dest", "shortIds", "fingerprint", "flow"} {
		if _, ok := m[k]; !ok {
			t.Errorf("reality settings missing %q: %s", k, in.Settings)
		}
	}
	if m["flow"] != "xtls-rprx-vision" {
		t.Errorf("vless reality should default flow to vision, got %v", m["flow"])
	}
	if firstStr(m["serverNames"]) == "" || strOrEmpty(m["dest"]) == "" {
		t.Error("serverNames/dest must be non-empty")
	}
}

func TestNormalizeKeepsProvidedValues(t *testing.T) {
	s := &Server{}
	in := &store.Inbound{Tag: "vr", Protocol: store.ProtoVLESS, Security: "reality",
		Settings: `{"serverNames":["example.org"],"dest":"example.org:443","shortIds":["aa11"]}`}
	s.normalizeInbound(in)
	var m map[string]any
	json.Unmarshal([]byte(in.Settings), &m)
	if firstStr(m["serverNames"]) != "example.org" {
		t.Errorf("should keep provided serverNames, got %v", m["serverNames"])
	}
	if firstStr(m["shortIds"]) != "aa11" {
		t.Errorf("should keep provided shortIds, got %v", m["shortIds"])
	}
	if strOrEmpty(m["privateKey"]) == "" {
		t.Error("should still fill a keypair")
	}
}

func TestNormalizeNoneLeavesSettings(t *testing.T) {
	s := &Server{}
	in := &store.Inbound{Tag: "s", Protocol: store.ProtoShadowsocks, Security: "none"}
	s.normalizeInbound(in)
	// No reality/tls fields injected for a plain inbound.
	if in.Settings != "" && in.Settings != "{}" {
		var m map[string]any
		json.Unmarshal([]byte(in.Settings), &m)
		if _, ok := m["privateKey"]; ok {
			t.Errorf("none-security inbound should not get reality keys: %s", in.Settings)
		}
	}
}
