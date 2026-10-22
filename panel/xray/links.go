package xray

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/awmiresgg/rahro/panel/store"
)

// ShareLink builds a client share URI (vless://, vmess://, trojan://, ss://)
// for a user on an inbound, reachable at host. Returns "" for unknown
// protocols. Advanced parameters are read from the inbound's settings JSON
// (sni, publicKey, shortIds, path, host, serviceName, flow, alpn, method).
func ShareLink(in *store.Inbound, u *store.User, host string) string {
	extra := map[string]any{}
	if in.Settings != "" {
		_ = json.Unmarshal([]byte(in.Settings), &extra)
	}
	label := in.Tag
	switch in.Protocol {
	case store.ProtoVLESS:
		return "vless://" + u.UUID + "@" + hostPort(host, in.Port) + "?" + streamQuery(in, extra).Encode() + "#" + url.PathEscape(label)
	case store.ProtoTrojan:
		return "trojan://" + u.UUID + "@" + hostPort(host, in.Port) + "?" + streamQuery(in, extra).Encode() + "#" + url.PathEscape(label)
	case store.ProtoVMess:
		return vmessLink(in, u, host, extra, label)
	case store.ProtoShadowsocks:
		method := str(extra["method"], "chacha20-ietf-poly1305")
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + u.UUID))
		return "ss://" + userinfo + "@" + hostPort(host, in.Port) + "#" + url.PathEscape(label)
	}
	return ""
}

func streamQuery(in *store.Inbound, extra map[string]any) url.Values {
	q := url.Values{}
	net := in.Network
	if net == "" {
		net = "tcp"
	}
	sec := in.Security
	if sec == "" {
		sec = "none"
	}
	q.Set("type", net)
	q.Set("security", sec)

	switch sec {
	case "tls":
		if v := str(extra["sni"], ""); v != "" {
			q.Set("sni", v)
		}
		if v := str(extra["fingerprint"], "chrome"); v != "" {
			q.Set("fp", v)
		}
	case "reality":
		if v := str(extra["publicKey"], ""); v != "" {
			q.Set("pbk", v)
		}
		if v := firstString(extra["shortIds"]); v != "" {
			q.Set("sid", v)
		}
		if v := firstString(extra["serverNames"]); v != "" {
			q.Set("sni", v)
		} else if v := str(extra["sni"], ""); v != "" {
			q.Set("sni", v)
		}
		q.Set("fp", str(extra["fingerprint"], "chrome"))
	}
	if f := str(extra["flow"], ""); f != "" {
		q.Set("flow", f)
	}
	switch net {
	case "ws":
		q.Set("path", str(extra["path"], "/"))
		if h := str(extra["host"], ""); h != "" {
			q.Set("host", h)
		}
	case "grpc":
		q.Set("serviceName", str(extra["serviceName"], ""))
	case "http":
		q.Set("path", str(extra["path"], "/"))
	}
	return q
}

func vmessLink(in *store.Inbound, u *store.User, host string, extra map[string]any, label string) string {
	m := map[string]any{
		"v": "2", "ps": label, "add": host, "port": strconv.Itoa(in.Port),
		"id": u.UUID, "aid": "0", "scy": "auto",
		"net": orStr(in.Network, "tcp"), "type": "none",
		"host": str(extra["host"], ""), "path": str(extra["path"], ""),
		"tls": tlsField(in.Security), "sni": str(extra["sni"], ""),
	}
	b, _ := json.Marshal(m)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func tlsField(sec string) string {
	if sec == "tls" || sec == "reality" {
		return "tls"
	}
	return ""
}

func hostPort(host string, port int) string { return host + ":" + strconv.Itoa(port) }

func str(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func orStr(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

func firstString(v any) string {
	if arr, ok := v.([]any); ok && len(arr) > 0 {
		if s, ok := arr[0].(string); ok {
			return s
		}
	}
	return ""
}
