// Package api implements the Rahro panel's HTTP API: a cookie-authenticated
// admin API, a public subscription endpoint, and a token-authenticated bot API
// for external integrations such as a Telegram sales bot.
package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/awmiresgg/rahro/panel/auth"
	"github.com/awmiresgg/rahro/panel/store"
)

// Server holds the API dependencies.
type Server struct {
	Store *store.Store
	Log   *slog.Logger
	// PublicBase is the externally-reachable panel base URL (used to build
	// subscription links), e.g. "https://panel.example.com:2053".
	PublicBase string

	mu       sync.Mutex
	sessions map[string]session // cookie token -> session
}

type session struct {
	admin   string
	expires time.Time
}

const sessionCookie = "rahro_session"
const sessionTTL = 24 * time.Hour

// New creates an API server.
func New(st *store.Store, log *slog.Logger, publicBase string) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{Store: st, Log: log, PublicBase: publicBase, sessions: map[string]session{}}
}

// Routes registers all API routes on a new mux and returns it.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()

	// Admin auth.
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.admin(s.handleMe))
	mux.HandleFunc("POST /api/account", s.admin(s.handleChangeAccount))
	mux.HandleFunc("GET /api/stats", s.admin(s.handleStats))

	// Users.
	mux.HandleFunc("GET /api/users", s.admin(s.handleListUsers))
	mux.HandleFunc("POST /api/users", s.admin(s.handleCreateUser))
	mux.HandleFunc("GET /api/users/{id}", s.admin(s.handleGetUser))
	mux.HandleFunc("PATCH /api/users/{id}", s.admin(s.handleUpdateUser))
	mux.HandleFunc("DELETE /api/users/{id}", s.admin(s.handleDeleteUser))

	// Inbounds.
	mux.HandleFunc("GET /api/inbounds", s.admin(s.handleListInbounds))
	mux.HandleFunc("POST /api/inbounds", s.admin(s.handleCreateInbound))
	mux.HandleFunc("GET /api/inbounds/{id}", s.admin(s.handleGetInbound))
	mux.HandleFunc("PATCH /api/inbounds/{id}", s.admin(s.handleUpdateInbound))
	mux.HandleFunc("DELETE /api/inbounds/{id}", s.admin(s.handleDeleteInbound))

	// Nodes.
	mux.HandleFunc("GET /api/nodes", s.admin(s.handleListNodes))
	mux.HandleFunc("POST /api/nodes", s.admin(s.handleCreateNode))
	mux.HandleFunc("DELETE /api/nodes/{id}", s.admin(s.handleDeleteNode))

	// API tokens (for the Telegram sales bot etc.).
	mux.HandleFunc("GET /api/tokens", s.admin(s.handleListTokens))
	mux.HandleFunc("POST /api/tokens", s.admin(s.handleCreateToken))
	mux.HandleFunc("DELETE /api/tokens/{id}", s.admin(s.handleDeleteToken))

	// Node control plane (node-secret authenticated in-handler).
	mux.HandleFunc("POST /nodeapi/enroll", s.handleNodeEnroll)
	mux.HandleFunc("POST /nodeapi/config", s.handleNodeConfig)

	// Public subscription.
	mux.HandleFunc("GET /sub/{token}", s.handleSubscription)

	// Bot API (Bearer token).
	mux.HandleFunc("POST /botapi/users", s.botToken(s.handleBotCreateUser))
	mux.HandleFunc("GET /botapi/users/{uuid}", s.botToken(s.handleBotGetUser))
	mux.HandleFunc("POST /botapi/users/{uuid}/renew", s.botToken(s.handleBotRenewUser))
	mux.HandleFunc("GET /botapi/nodes", s.botToken(s.handleBotNodes))

	return mux
}

// --- admin session middleware ---

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			httpError(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		s.mu.Lock()
		sess, ok := s.sessions[c.Value]
		if ok && time.Now().After(sess.expires) {
			delete(s.sessions, c.Value)
			ok = false
		}
		s.mu.Unlock()
		if !ok {
			httpError(w, http.StatusUnauthorized, "session expired")
			return
		}
		next(w, r)
	}
}

func (s *Server) newSession(admin string) string {
	tok := auth.NewToken(24)
	s.mu.Lock()
	s.sessions[tok] = session{admin: admin, expires: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	return tok
}

// --- bot token middleware ---

func (s *Server) botToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			httpError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		if _, err := s.Store.AuthenticateAPIToken(auth.HashToken(tok)); err != nil {
			httpError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next(w, r)
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return ""
}

// --- handlers: auth ---

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	a, err := s.Store.GetAdmin(req.Username)
	if err != nil || !auth.VerifyPassword(req.Password, a.PasswordHash) {
		httpError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	tok := s.newSession(a.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(sessionTTL),
	})
	writeJSON(w, http.StatusOK, map[string]string{"username": a.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(sessionCookie)
	s.mu.Lock()
	sess := s.sessions[c.Value]
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"username": sess.admin})
}

// handleChangeAccount changes the logged-in admin's username and/or password.
// The current password is always required.
func (s *Server) handleChangeAccount(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(sessionCookie)
	s.mu.Lock()
	sess := s.sessions[c.Value]
	s.mu.Unlock()

	admin, err := s.Store.GetAdmin(sess.admin)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "account not found")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewUsername     string `json:"new_username"`
		NewPassword     string `json:"new_password"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	if !auth.VerifyPassword(req.CurrentPassword, admin.PasswordHash) {
		httpError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	newUser := admin.Username
	if req.NewUsername != "" {
		newUser = req.NewUsername
	}
	newHash := admin.PasswordHash
	if req.NewPassword != "" {
		if len(req.NewPassword) < 6 {
			httpError(w, http.StatusBadRequest, "new password must be at least 6 characters")
			return
		}
		h, err := auth.HashPassword(req.NewPassword)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		newHash = h
	}
	if err := s.Store.UpdateAdminCredentials(admin.ID, newUser, newHash); err != nil {
		httpError(w, http.StatusConflict, "could not update (is the username already taken?)")
		return
	}
	s.mu.Lock()
	if sv, ok := s.sessions[c.Value]; ok {
		sv.admin = newUser
		s.sessions[c.Value] = sv
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"username": newUser})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	users, _ := s.Store.ListUsers()
	nodes, _ := s.Store.ListNodes()
	active := 0
	for _, u := range users {
		if u.Active() {
			active++
		}
	}
	online := 0
	for _, n := range nodes {
		if n.Enabled {
			online++
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{
		"users": len(users), "active_users": active,
		"nodes": len(nodes), "nodes_enabled": online,
	})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	return dec.Decode(v)
}

func pathID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}
