package api

import (
	"net/http"
	"strings"

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
	cfg := xray.GenerateConfig(inbounds, users)
	// Optional debug logging: when enabled, Xray logs every incoming connection
	// (even failed/probe), which tells us whether a client's packets reach the
	// server at all vs. being blocked upstream.
	if lvl, ok, _ := s.Store.GetSetting("xray_loglevel"); ok && lvl != "" {
		if lg, ok := cfg["log"].(map[string]any); ok {
			lg["loglevel"] = lvl
		}
	}
	return s.Xray.Apply(cfg)
}

// handleXrayLog returns the tail of Xray's runtime log (or access log with
// ?access=1), so the admin can see exactly what happens when a client connects
// — e.g. "REALITY: processed invalid connection" (key mismatch) vs an
// "accepted ... email:" line (connected) vs nothing (never reached the server).
func (s *Server) handleXrayLog(w http.ResponseWriter, r *http.Request) {
	if s.Xray == nil {
		httpError(w, http.StatusServiceUnavailable, "xray is not enabled")
		return
	}
	access := r.URL.Query().Get("access") == "1"
	out := s.Xray.TailLog(access, 200)
	if access {
		// Drop the internal stats-API polls so only real client connections show.
		var kept []string
		for _, ln := range strings.Split(out, "\n") {
			if strings.Contains(ln, "[api ") || strings.Contains(ln, ">>> api") ||
				strings.Contains(ln, ":62789") || strings.Contains(ln, "inbound>>>api") {
				continue
			}
			kept = append(kept, ln)
		}
		out = strings.TrimSpace(strings.Join(kept, "\n"))
		if out == "" {
			out = "(no real client connections yet — only internal stats polls, which are hidden)"
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"log": out})
}

// handleXrayDebug toggles verbose Xray logging (loglevel debug) and reapplies,
// so the admin can see whether a client's connection reaches the server.
func (s *Server) handleXrayDebug(w http.ResponseWriter, r *http.Request) {
	cur, _, _ := s.Store.GetSetting("xray_loglevel")
	next := "debug"
	if cur == "debug" {
		next = "warning"
	}
	if err := s.Store.SetSetting("xray_loglevel", next); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.ApplyXray()
	writeJSON(w, http.StatusOK, map[string]string{"loglevel": next})
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
