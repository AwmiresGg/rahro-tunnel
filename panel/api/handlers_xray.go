package api

import (
	"net/http"

	"github.com/awmiresgg/rahro/panel/xray"
)

// handleRealityKeys generates an X25519 keypair in Xray's base64-rawURL format.
// The private key goes in the inbound's reality settings; the public key goes
// into client share links (pbk=).
func (s *Server) handleRealityKeys(w http.ResponseWriter, r *http.Request) {
	priv, pub, err := s.realityKeypair()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"privateKey": priv,
		"publicKey":  pub,
	})
}

// ApplyXray regenerates and applies the Xray config, logging any error. Most
// callers use this fire-and-forget form.
func (s *Server) ApplyXray() {
	if err := s.ApplyXrayErr(); err != nil {
		s.Log.Error("xray apply failed", "err", err)
	}
}

// ApplyXrayErr regenerates the Xray config from the current inbounds+users and
// (re)starts the core, returning any error (e.g. Xray rejected the config). It
// is a no-op when Xray is not configured or installed.
func (s *Server) ApplyXrayErr() error {
	if s.Xray == nil {
		return nil
	}
	inbounds, _ := s.Store.ListInbounds()
	users, _ := s.Store.ListUsers()

	// Record which users are in the config we're about to apply, so the traffic
	// loop can tell when membership changes (a quota/expiry transition) and
	// needs to reapply to drop a now-inactive user.
	s.setLastActive(activeSet(users))

	enabled := false
	for _, in := range inbounds {
		if in.Enabled {
			enabled = true
			break
		}
	}
	if !enabled {
		return s.Xray.Stop()
	}
	if !s.Xray.Installed() {
		s.Log.Warn("xray binary not installed yet; skipping apply")
		return nil
	}
	return s.Xray.Apply(xray.GenerateConfig(inbounds, users))
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
	err := s.ApplyXrayErr()
	resp := map[string]any{
		"installed": s.Xray.Installed(),
		"running":   s.Xray.Running(),
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}
