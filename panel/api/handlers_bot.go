package api

import (
	"net/http"
	"time"

	"github.com/awmiresgg/rahro/panel/auth"
	"github.com/awmiresgg/rahro/panel/store"
)

// userResponse is the bot-facing representation of a user (adds the sub link).
func (s *Server) userResponse(u *store.User) map[string]any {
	return map[string]any{
		"username":    u.Username,
		"uuid":        u.UUID,
		"sub_link":    s.subLink(u),
		"quota_bytes": u.QuotaBytes,
		"used_bytes":  u.UsedBytes,
		"expires_at":  u.ExpiresAt,
		"enabled":     u.Enabled,
		"active":      u.Active(),
	}
}

// POST /botapi/users  — create a user for a sale.
func (s *Server) handleBotCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Username == "" {
		req.Username = "tg-" + auth.NewToken(6)
	}
	u := &store.User{
		Username:   req.Username,
		UUID:       auth.NewUUIDHex(),
		SubToken:   auth.NewToken(18),
		QuotaBytes: req.QuotaGB * gib,
		Enabled:    true,
	}
	if req.Days > 0 {
		u.ExpiresAt = time.Now().Add(time.Duration(req.Days) * 24 * time.Hour).Unix()
	}
	created, err := s.Store.CreateUser(u)
	if err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, s.userResponse(created))
}

// GET /botapi/users/{uuid}
func (s *Server) handleBotGetUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.GetUserByUUID(r.PathValue("uuid"))
	if err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, s.userResponse(u))
}

// POST /botapi/users/{uuid}/renew  {add_days, add_gb}  — extend a subscription.
func (s *Server) handleBotRenewUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.GetUserByUUID(r.PathValue("uuid"))
	if err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	var req struct {
		AddDays int64 `json:"add_days"`
		AddGB   int64 `json:"add_gb"`
		Reset   bool  `json:"reset_usage"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	base := time.Now()
	if u.ExpiresAt > base.Unix() {
		base = time.Unix(u.ExpiresAt, 0)
	}
	if req.AddDays > 0 {
		u.ExpiresAt = base.Add(time.Duration(req.AddDays) * 24 * time.Hour).Unix()
	}
	if req.AddGB > 0 {
		u.QuotaBytes += req.AddGB * gib
	}
	if req.Reset {
		u.UsedBytes = 0
	}
	u.Enabled = true
	if err := s.Store.UpdateUser(u); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.userResponse(u))
}

// GET /botapi/nodes  — enabled locations the sale covers.
func (s *Server) handleBotNodes(w http.ResponseWriter, r *http.Request) {
	nodes, _ := s.Store.ListNodes()
	out := []map[string]string{}
	for _, n := range nodes {
		if !n.Enabled {
			continue
		}
		out = append(out, map[string]string{"name": n.Name, "location": n.Location, "role": n.Role})
	}
	writeJSON(w, http.StatusOK, out)
}
