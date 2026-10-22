// Package xray generates Xray-core configuration from the panel's inbounds and
// users, and manages the Xray process (download, run, reload). The panel owns
// the data model; Xray does the actual protocol work — the same split 3x-ui
// uses. No Xray or 3x-ui source is copied: Xray runs as a managed external
// binary configured via its JSON config.
package xray

import (
	"encoding/json"

	"github.com/awmiresgg/rahro/panel/store"
)

// APIPort is the localhost-only port on which Xray exposes its gRPC stats/API
// service, used by the panel to read per-user traffic counters.
const APIPort = 62789

// GenerateConfig builds an Xray config object from the enabled inbounds and the
// active users (offered as clients on every inbound). The result marshals to a
// valid Xray config.json. It enables per-user traffic statistics so the panel
// can meter usage and enforce quotas.
func GenerateConfig(inbounds []*store.Inbound, users []*store.User) map[string]any {
	var active []*store.User
	for _, u := range users {
		if u.Active() {
			active = append(active, u)
		}
	}

	// A localhost dokodemo-door inbound tagged "api" lets the panel reach the
	// StatsService to read (and reset) per-user traffic counters.
	ins := []map[string]any{{
		"tag":      "api",
		"listen":   "127.0.0.1",
		"port":     APIPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1"},
	}}
	for _, in := range inbounds {
		if !in.Enabled {
			continue
		}
		ins = append(ins, buildInbound(in, active))
	}

	return map[string]any{
		"log":   map[string]any{"loglevel": "warning"},
		"api":   map[string]any{"tag": "api", "services": []string{"StatsService"}},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{
				"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true},
			},
			"system": map[string]any{
				"statsInboundUplink": true, "statsInboundDownlink": true,
			},
		},
		"inbounds": ins,
		"outbounds": []map[string]any{
			{"protocol": "freedom", "tag": "direct"},
			{"protocol": "blackhole", "tag": "blocked"},
		},
		"routing": map[string]any{
			"rules": []map[string]any{
				{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
			},
		},
	}
}

// Marshal renders a config object as pretty JSON.
func Marshal(cfg map[string]any) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}

func buildInbound(in *store.Inbound, users []*store.User) map[string]any {
	extra := map[string]any{}
	if in.Settings != "" {
		_ = json.Unmarshal([]byte(in.Settings), &extra)
	}

	listen := in.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}

	ib := map[string]any{
		"tag":            in.Tag,
		"listen":         listen,
		"port":           in.Port,
		"protocol":       in.Protocol,
		"settings":       buildSettings(in.Protocol, users, extra),
		"streamSettings": buildStream(in.Network, in.Security, extra),
	}
	// Optional sniffing (helps routing/stats); harmless default.
	ib["sniffing"] = map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}}
	return ib
}

func buildSettings(proto string, users []*store.User, extra map[string]any) map[string]any {
	clients := make([]map[string]any, 0, len(users))
	for _, u := range users {
		c := map[string]any{"email": u.Username}
		switch proto {
		case store.ProtoVLESS:
			c["id"] = u.UUID
			if f, ok := extra["flow"].(string); ok && f != "" {
				c["flow"] = f
			}
		case store.ProtoVMess:
			c["id"] = u.UUID
		case store.ProtoTrojan:
			c["password"] = u.UUID
		case store.ProtoShadowsocks:
			c["password"] = u.UUID
			method, _ := extra["method"].(string)
			if method == "" {
				method = "chacha20-ietf-poly1305"
			}
			c["method"] = method
		}
		clients = append(clients, c)
	}

	s := map[string]any{"clients": clients}
	switch proto {
	case store.ProtoVLESS:
		s["decryption"] = "none"
	case store.ProtoShadowsocks:
		s["network"] = "tcp,udp"
	}
	return s
}

func buildStream(network, security string, extra map[string]any) map[string]any {
	if network == "" {
		network = "tcp"
	}
	if security == "" {
		security = "none"
	}
	ss := map[string]any{"network": network, "security": security}

	switch security {
	case "tls":
		tls := map[string]any{}
		if sni, ok := extra["sni"].(string); ok && sni != "" {
			tls["serverName"] = sni
		}
		if certs, ok := extra["certificates"]; ok {
			tls["certificates"] = certs
		}
		if alpn, ok := extra["alpn"]; ok {
			tls["alpn"] = alpn
		}
		ss["tlsSettings"] = tls
	case "reality":
		r := map[string]any{"show": false}
		copyKeys(r, extra, "dest", "serverNames", "privateKey", "shortIds", "xver", "fingerprint", "spiderX")
		ss["realitySettings"] = r
	}

	switch network {
	case "ws":
		ws := map[string]any{"path": strOr(extra["path"], "/")}
		if h, ok := extra["host"].(string); ok && h != "" {
			ws["headers"] = map[string]any{"Host": h}
		}
		ss["wsSettings"] = ws
	case "grpc":
		ss["grpcSettings"] = map[string]any{"serviceName": strOr(extra["serviceName"], "")}
	case "http":
		ss["httpSettings"] = map[string]any{"path": strOr(extra["path"], "/")}
	}
	return ss
}

func copyKeys(dst, src map[string]any, keys ...string) {
	for _, k := range keys {
		if v, ok := src[k]; ok {
			dst[k] = v
		}
	}
}

func strOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}
