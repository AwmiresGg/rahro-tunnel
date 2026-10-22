package api

import (
	"context"
	"time"

	"github.com/awmiresgg/rahro/panel/store"
)

// loginAttempts tracks failed logins per source for brute-force lockout.
type loginAttempts struct {
	count  int
	until  time.Time // lockout expiry; zero = not locked
	lastAt time.Time
}

// RunTrafficLoop periodically reads per-user traffic from Xray, meters it into
// the store, and reapplies the Xray config whenever a user crosses their quota
// or expiry so the core stops serving them. It blocks until ctx is cancelled.
func (s *Server) RunTrafficLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 45 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.pollTraffic()
		}
	}
}

// pollTraffic performs one accounting pass.
func (s *Server) pollTraffic() {
	if s.Xray == nil || !s.Xray.Running() {
		return
	}
	traf, err := s.Xray.QueryTraffic(true) // reset -> each poll is a delta
	if err != nil {
		s.Log.Debug("xray traffic query failed", "err", err)
		return
	}
	users, err := s.Store.ListUsers()
	if err != nil {
		return
	}
	for _, u := range users {
		if add := traf[u.Username]; add > 0 {
			if err := s.Store.AddUsage(u.ID, add); err == nil {
				u.UsedBytes += add // keep in-memory copy current for activeSet
			}
		}
	}
	// If the active membership changed (someone hit quota or expired, even with
	// no new traffic), reapply so Xray drops them.
	if !sameSet(activeSet(users), s.lastActiveSet()) {
		s.ApplyXray()
	}
}

func activeSet(users []*store.User) map[int64]bool {
	m := make(map[int64]bool, len(users))
	for _, u := range users {
		if u.Active() {
			m[u.ID] = true
		}
	}
	return m
}

func (s *Server) setLastActive(m map[int64]bool) {
	s.mu.Lock()
	s.lastActive = m
	s.mu.Unlock()
}

func (s *Server) lastActiveSet() map[int64]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastActive
}

func sameSet(a, b map[int64]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
