package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/awmiresgg/rahro/core/crypto"
	"github.com/awmiresgg/rahro/panel/store"
	"github.com/awmiresgg/rahro/panel/xray"
)

// realityKeypair returns an X25519 keypair in Xray's base64 format, preferring
// `xray x25519` (guaranteed compatible with the core) and falling back to our
// own generator when the binary is not yet installed.
func (s *Server) realityKeypair() (priv, pub string, err error) {
	if s.Xray != nil {
		if p, q, e := s.Xray.GenerateRealityKeypair(); e == nil {
			return p, q, nil
		}
	}
	kp, e := crypto.GenerateKeyPair()
	if e != nil {
		return "", "", e
	}
	return base64.RawURLEncoding.EncodeToString(kp.PrivateBytes()),
		base64.RawURLEncoding.EncodeToString(kp.PublicBytes()), nil
}

// normalizeInbound fills in every field the inbound's security mode needs so it
// is always a valid Xray config and always yields working client links — no
// matter how little the admin typed. It mutates in.Settings. This is what makes
// "add a REALITY inbound" work with one click instead of hand-written JSON.
func (s *Server) normalizeInbound(in *store.Inbound) {
	extra := map[string]any{}
	if in.Settings != "" {
		_ = json.Unmarshal([]byte(in.Settings), &extra)
	}
	switch in.Security {
	case "reality":
		if strOrEmpty(extra["privateKey"]) == "" {
			if p, q, err := s.realityKeypair(); err == nil {
				extra["privateKey"], extra["publicKey"] = p, q
			}
		}
		// Always keep publicKey derived from privateKey, so a stored/pasted
		// publicKey can never disagree with the server's key (the cause of
		// "REALITY: received real certificate" auth failures).
		if pk := xray.RealityPublicKey(strOrEmpty(extra["privateKey"])); pk != "" {
			extra["publicKey"] = pk
		}
		if firstStr(extra["serverNames"]) == "" {
			sni := strOrEmpty(extra["sni"])
			if sni == "" {
				sni = "www.microsoft.com"
			}
			extra["serverNames"] = []any{sni}
		}
		if strOrEmpty(extra["dest"]) == "" {
			extra["dest"] = firstStr(extra["serverNames"]) + ":443"
		}
		if firstStr(extra["shortIds"]) == "" {
			extra["shortIds"] = []any{randHex(8)}
		}
		if strOrEmpty(extra["fingerprint"]) == "" {
			extra["fingerprint"] = "chrome"
		}
		if in.Protocol == store.ProtoVLESS && strOrEmpty(extra["flow"]) == "" {
			extra["flow"] = "xtls-rprx-vision"
		}
	case "tls":
		if strOrEmpty(extra["fingerprint"]) == "" {
			extra["fingerprint"] = "chrome"
		}
	}
	b, _ := json.Marshal(extra)
	in.Settings = string(b)
}

func strOrEmpty(v any) string { s, _ := v.(string); return s }

// firstStr returns the first element of a string-or-any slice as a string.
func firstStr(v any) string {
	switch a := v.(type) {
	case []any:
		if len(a) > 0 {
			s, _ := a[0].(string)
			return s
		}
	case []string:
		if len(a) > 0 {
			return a[0]
		}
	}
	return ""
}

func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
