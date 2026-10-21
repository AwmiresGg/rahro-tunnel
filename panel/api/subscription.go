package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/awmiresgg/rahro/panel/store"
)

// subLink returns the user's subscription URL.
func (s *Server) subLink(u *store.User) string {
	return strings.TrimRight(s.PublicBase, "/") + "/sub/" + u.SubToken
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
	links := buildConfigs(u, nodes)
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
