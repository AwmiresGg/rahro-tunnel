package api

import (
	"net/http"

	"github.com/awmiresgg/rahro/panel/xray"
)

// ApplyXray regenerates the Xray config from the current inbounds+users and
// (re)starts the core. It is a no-op when Xray is not configured. Errors are
// logged, not returned, so user/inbound edits never fail because of Xray.
func (s *Server) ApplyXray() {
	if s.Xray == nil {
		return
	}
	inbounds, _ := s.Store.ListInbounds()
	users, _ := s.Store.ListUsers()

	enabled := false
	for _, in := range inbounds {
		if in.Enabled {
			enabled = true
			break
		}
	}
	if !enabled {
		_ = s.Xray.Stop()
		return
	}
	if !s.Xray.Installed() {
		s.Log.Warn("xray binary not installed yet; skipping apply")
		return
	}
	if err := s.Xray.Apply(xray.GenerateConfig(inbounds, users)); err != nil {
		s.Log.Error("xray apply failed", "err", err)
	}
}

func (s *Server) handleXrayStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"enabled": s.Xray != nil}
	if s.Xray != nil {
		resp["installed"] = s.Xray.Installed()
		resp["running"] = s.Xray.Running()
		if v, err := s.Xray.Version(); err == nil {
			resp["version"] = v
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleXrayApply(w http.ResponseWriter, r *http.Request) {
	if s.Xray == nil {
		httpError(w, http.StatusServiceUnavailable, "xray is not enabled on this panel")
		return
	}
	s.ApplyXray()
	resp := map[string]any{
		"installed": s.Xray.Installed(),
		"running":   s.Xray.Running(),
	}
	writeJSON(w, http.StatusOK, resp)
}
