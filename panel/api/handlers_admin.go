package api

import (
	"net/http"
	"time"

	"github.com/awmiresgg/rahro/panel/auth"
	"github.com/awmiresgg/rahro/panel/store"
)

const gib = int64(1) << 30

// --- users ---

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.ListUsers()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if users == nil {
		users = []*store.User{}
	}
	writeJSON(w, http.StatusOK, users)
}

type createUserReq struct {
	Username  string `json:"username"`
	QuotaGB   int64  `json:"quota_gb"`   // 0 = unlimited
	Days      int64  `json:"days"`       // 0 = never expires
	IPLimit   int    `json:"ip_limit"`   // 0 = unlimited
	ResetDays int    `json:"reset_days"` // 0 = no auto reset
	Enabled   *bool  `json:"enabled"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := readJSON(r, &req); err != nil || req.Username == "" {
		httpError(w, http.StatusBadRequest, "username required")
		return
	}
	u := &store.User{
		Username:   req.Username,
		UUID:       auth.NewUUIDHex(),
		SubToken:   auth.NewToken(18),
		QuotaBytes: req.QuotaGB * gib,
		IPLimit:    req.IPLimit,
		ResetDays:  req.ResetDays,
		Enabled:    true,
	}
	if req.Enabled != nil {
		u.Enabled = *req.Enabled
	}
	if req.Days > 0 {
		u.ExpiresAt = time.Now().Add(time.Duration(req.Days) * 24 * time.Hour).Unix()
	}
	created, err := s.Store.CreateUser(u)
	if err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	s.ApplyXray()
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, u)
}

type updateUserReq struct {
	Username   *string `json:"username"`
	QuotaBytes *int64  `json:"quota_bytes"`
	UsedBytes  *int64  `json:"used_bytes"`
	ExpiresAt  *int64  `json:"expires_at"`
	Enabled    *bool   `json:"enabled"`
	IPLimit    *int    `json:"ip_limit"`
	ResetDays  *int    `json:"reset_days"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
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
	var req updateUserReq
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Username != nil {
		u.Username = *req.Username
	}
	if req.QuotaBytes != nil {
		u.QuotaBytes = *req.QuotaBytes
	}
	if req.UsedBytes != nil {
		u.UsedBytes = *req.UsedBytes
	}
	if req.ExpiresAt != nil {
		u.ExpiresAt = *req.ExpiresAt
	}
	if req.Enabled != nil {
		u.Enabled = *req.Enabled
	}
	if req.IPLimit != nil {
		u.IPLimit = *req.IPLimit
	}
	if req.ResetDays != nil {
		u.ResetDays = *req.ResetDays
	}
	if err := s.Store.UpdateUser(u); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.ApplyXray()
	writeJSON(w, http.StatusOK, u)
}

// handleResetUser zeroes a user's used traffic (manual reset).
func (s *Server) handleResetUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.Store.ResetUsage(id); err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	// A reset may re-activate a user that was over quota, so reapply.
	s.ApplyXray()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.Store.DeleteUser(id); err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	s.ApplyXray()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- nodes ---

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.Store.ListNodes()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if nodes == nil {
		nodes = []*store.Node{}
	}
	writeJSON(w, http.StatusOK, nodes)
}

type createNodeReq struct {
	Name        string `json:"name"`
	Role        string `json:"role"`
	Location    string `json:"location"`
	Address     string `json:"address"`
	Upstream    string `json:"upstream"`
	ServingMode string `json:"serving_mode"`
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var req createNodeReq
	if err := readJSON(r, &req); err != nil || req.Name == "" {
		httpError(w, http.StatusBadRequest, "name required")
		return
	}
	switch req.Role {
	case store.RolePanel, store.RoleLocation, store.RoleTunnel:
	default:
		httpError(w, http.StatusBadRequest, "role must be panel|location|tunnel")
		return
	}
	n := &store.Node{
		Name:        req.Name,
		Role:        req.Role,
		Location:    req.Location,
		Address:     req.Address,
		Upstream:    req.Upstream,
		ServingMode: req.ServingMode,
		EnrollToken: auth.NewToken(18),
		Enabled:     true,
	}
	created, err := s.Store.CreateNode(n)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Include a ready-to-run enrollment command for convenience.
	resp := map[string]any{
		"node":            created,
		"connection_code": created.EnrollToken,
		"enroll_command":  "bash <(curl -sL https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/scripts/install.sh) node " + created.EnrollToken,
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.Store.DeleteNode(id); err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- api tokens ---

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := s.Store.ListAPITokens()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if toks == nil {
		toks = []*store.APIToken{}
	}
	writeJSON(w, http.StatusOK, toks)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Scopes string `json:"scopes"`
	}
	if err := readJSON(r, &req); err != nil || req.Name == "" {
		httpError(w, http.StatusBadRequest, "name required")
		return
	}
	if req.Scopes == "" {
		req.Scopes = "users:write"
	}
	plain := auth.NewAPIToken()
	tok, err := s.Store.CreateAPIToken(req.Name, auth.HashToken(plain), req.Scopes)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The plaintext token is returned exactly once.
	writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "secret": plain})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.Store.DeleteAPIToken(id); err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
