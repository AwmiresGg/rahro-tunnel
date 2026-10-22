package api

import (
	"testing"
)

func newTestServer() *Server {
	return &Server{sessions: map[string]session{}, logins: map[string]*loginAttempts{}}
}

func TestLoginLockout(t *testing.T) {
	s := newTestServer()
	key := "1.2.3.4"
	// Below the threshold: never locked.
	for i := 0; i < maxFails-1; i++ {
		s.loginFailed(key)
		if locked, _ := s.loginLocked(key); locked {
			t.Fatalf("locked too early at attempt %d", i+1)
		}
	}
	// The maxFails-th failure trips the lock.
	s.loginFailed(key)
	locked, left := s.loginLocked(key)
	if !locked || left <= 0 {
		t.Fatalf("should be locked after %d failures (left=%v)", maxFails, left)
	}
	// A different source is unaffected.
	if locked, _ := s.loginLocked("9.9.9.9"); locked {
		t.Fatal("unrelated source should not be locked")
	}
	// A successful login clears the record.
	s.loginOK(key)
	if locked, _ := s.loginLocked(key); locked {
		t.Fatal("lock should clear after a successful login")
	}
}

func TestSameSet(t *testing.T) {
	if !sameSet(nil, map[int64]bool{}) {
		t.Fatal("nil and empty should be equal")
	}
	if sameSet(map[int64]bool{1: true}, map[int64]bool{2: true}) {
		t.Fatal("different members should differ")
	}
	if !sameSet(map[int64]bool{1: true, 2: true}, map[int64]bool{2: true, 1: true}) {
		t.Fatal("same members should be equal")
	}
}
