package api

import (
	"net/http"

	"rsc.io/qr"

	"github.com/awmiresgg/rahro/panel/xray"
)

// handleUserLinks returns the individual client share links for a user, one per
// enabled inbound the user is assigned to, plus the subscription URL. The panel
// UI shows each with a copy button and a QR code.
func (s *Server) handleUserLinks(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad id")
		return
	}
	u, err := s.Store.GetUser(id)
	if err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	host := s.hostForRequest(r)
	inbounds, _ := s.Store.ListInbounds()
	links := []map[string]string{}
	for _, in := range inbounds {
		if !in.Enabled || !u.ServesInbound(in.Tag) {
			continue
		}
		if l := xray.ShareLink(in, u, host); l != "" {
			links = append(links, map[string]string{
				"tag": in.Tag, "protocol": in.Protocol, "link": l,
			})
		}
	}
	// Build the subscription URL from the address the admin actually used, so it
	// is reachable even if public_url was never set correctly.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	sub := scheme + "://" + r.Host + "/sub/" + u.SubToken
	if !usableHost(s.hostForRequest(r)) { // nothing better available
		sub = s.subLink(u)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":   sub,
		"links": links,
	})
}

// handleQR renders the ?text= parameter as a PNG QR code. Generated locally
// (no external service), so it works fully offline.
func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("text")
	if text == "" {
		httpError(w, http.StatusBadRequest, "text required")
		return
	}
	if len(text) > 2048 {
		httpError(w, http.StatusBadRequest, "text too long")
		return
	}
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "qr encode failed")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(code.PNG())
}
