package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/awmiresgg/rahro/panel/store"
	"github.com/awmiresgg/rahro/panel/xray"
)

// subLink returns the user's subscription URL.
func (s *Server) subLink(u *store.User) string {
	return strings.TrimRight(s.PublicBase, "/") + "/sub/" + u.SubToken
}

// publicHost extracts the panel's hostname/IP from PublicBase.
func (s *Server) publicHost() string {
	if u, err := url.Parse(s.PublicBase); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return hostOnly(s.PublicBase)
}

// usableHost reports whether a host is a real reachable address (not a
// placeholder, loopback, or wildcard we must not put in a client link).
func usableHost(h string) bool {
	switch strings.ToLower(h) {
	case "", "your_server_ip", "127.0.0.1", "localhost", "0.0.0.0", "::1":
		return false
	}
	return true
}

// hostForRequest returns the best host to embed in client links: the configured
// public host when it is real, otherwise the host the admin actually reached
// the panel on (from the request). This makes links work even when public_url
// was never set correctly (e.g. IP auto-detection failed at install time).
func (s *Server) hostForRequest(r *http.Request) string {
	if h := s.publicHost(); usableHost(h) {
		return h
	}
	h := r.Host
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	h = strings.Trim(h, "[]")
	if usableHost(h) {
		return h
	}
	return s.publicHost() // nothing better; return whatever we have
}

// inboundLinks builds client share links for this user across the enabled,
// Xray-served inbounds on the given host.
func (s *Server) inboundLinks(u *store.User, host string) []string {
	inbounds, _ := s.Store.ListInbounds()
	var links []string
	for _, in := range inbounds {
		if !in.Enabled || !u.ServesInbound(in.Tag) {
			continue
		}
		if l := xray.ShareLink(in, u, host); l != "" {
			links = append(links, l)
		}
	}
	return links
}

// buildConfigs produces one share link per enabled, user-serving node, so a
// single subscription lists every location (Marzban-style). Standard-mode and
// tunnel nodes emit a VLESS link; Rahro-native nodes emit a rahro:// link.
func buildConfigs(u *store.User, nodes []*store.Node) []string {
	var links []string
	for _, n := range nodes {
		if !n.Enabled || n.Address == "" || n.Role == store.RolePanel {
			// Panel-only nodes aren't necessarily user ingress; skip unless they
			// carry a user-facing address.
			if n.Address == "" {
				continue
			}
		}
		label := n.Location
		if label == "" {
			label = n.Name
		}
		frag := url.PathEscape(fmt.Sprintf("Rahro-%s", label))
		switch n.ServingMode {
		case store.ServingRahro:
			links = append(links, fmt.Sprintf("rahro://%s@%s?security=reality#%s", u.UUID, n.Address, frag))
		default: // standard or both -> a widely-supported VLESS link
			links = append(links, fmt.Sprintf(
				"vless://%s@%s?encryption=none&security=tls&type=tcp&sni=%s#%s",
				u.UUID, n.Address, hostOnly(n.Address), frag))
		}
	}
	return links
}

func hostOnly(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

func (s *Server) handleSubscription(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	u, err := s.Store.GetUserBySubToken(tok)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	nodes, _ := s.Store.ListNodes()
	// Real, Xray-served inbound links first, then multi-location node links.
	links := append(s.inboundLinks(u, s.hostForRequest(r)), buildConfigs(u, nodes)...)
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))

	// Standard subscription-userinfo header so clients can show quota/expiry.
	total := u.QuotaBytes
	w.Header().Set("Subscription-Userinfo",
		fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d", u.UsedBytes, total, u.ExpiresAt))
	w.Header().Set("Profile-Update-Interval", "12")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !u.Active() {
		// Still return 200 with the (possibly empty) body so clients don't error,
		// but an inactive user gets no usable configs.
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(""))))
		return
	}
	w.Write([]byte(body))
}
