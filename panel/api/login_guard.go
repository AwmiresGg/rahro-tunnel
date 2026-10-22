package api

import (
	"net"
	"net/http"
	"time"
)

// Brute-force protection: after maxFails failed admin logins from one source
// within failWindow, that source is locked out for lockoutFor.
const (
	maxFails   = 8
	failWindow = 15 * time.Minute
	lockoutFor = 15 * time.Minute
)

// clientKey identifies the login source (IP without port).
func clientKey(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// loginLocked reports whether the source is currently locked out, and for how
// long. Expired windows are reset lazily.
func (s *Server) loginLocked(key string) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.logins[key]
	if a == nil {
		return false, 0
	}
	now := time.Now()
	if !a.until.IsZero() && now.Before(a.until) {
		return true, time.Until(a.until)
	}
	// Drop stale records (lock expired, or no failures in the window).
	if (a.until.IsZero() && now.Sub(a.lastAt) > failWindow) ||
		(!a.until.IsZero() && now.After(a.until)) {
		delete(s.logins, key)
	}
	return false, 0
}

// loginFailed records a failed attempt and may trigger a lockout.
func (s *Server) loginFailed(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	a := s.logins[key]
	if a == nil || now.Sub(a.lastAt) > failWindow {
		a = &loginAttempts{}
		s.logins[key] = a
	}
	a.count++
	a.lastAt = now
	if a.count >= maxFails {
		a.until = now.Add(lockoutFor)
	}
}

// loginOK clears a source's failure record after a successful login.
func (s *Server) loginOK(key string) {
	s.mu.Lock()
	delete(s.logins, key)
	s.mu.Unlock()
}
