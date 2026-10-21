package crypto

import (
	"fmt"
	"sync"
	"time"
)

// ReplayWindow defends the handshake against replay attacks and active probing
// that records and re-sends a valid authenticator. It rejects authenticators
// whose timestamp is outside an allowed clock-skew window, and remembers recent
// authenticator tags to reject duplicates.
//
// It is safe for concurrent use by multiple server goroutines.
type ReplayWindow struct {
	mu   sync.Mutex
	skew time.Duration
	seen map[string]time.Time // tag -> time after which it may be forgotten
	now  func() time.Time     // injectable for tests
}

// NewReplayWindow creates a window that accepts timestamps within ±skew of the
// current time and remembers each accepted tag for skew afterwards.
func NewReplayWindow(skew time.Duration) *ReplayWindow {
	if skew <= 0 {
		skew = 90 * time.Second
	}
	return &ReplayWindow{
		skew: skew,
		seen: make(map[string]time.Time),
		now:  time.Now,
	}
}

// Check validates a handshake with the given unique tag and timestamp. It
// returns nil if the handshake is fresh and unseen; otherwise an error
// explaining the rejection. A successful Check records the tag so a later
// replay of the same (tag, ts) is rejected.
func (w *ReplayWindow) Check(tag []byte, ts time.Time) error {
	if len(tag) == 0 {
		return fmt.Errorf("replay: empty tag")
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	now := w.now()
	if ts.Before(now.Add(-w.skew)) {
		return fmt.Errorf("replay: timestamp too old (%s outside %s skew)", now.Sub(ts), w.skew)
	}
	if ts.After(now.Add(w.skew)) {
		return fmt.Errorf("replay: timestamp too far in the future (%s outside %s skew)", ts.Sub(now), w.skew)
	}

	w.evictLocked(now)

	key := string(tag)
	if _, dup := w.seen[key]; dup {
		return fmt.Errorf("replay: duplicate authenticator")
	}
	// Remember the tag until it would be rejected by the age check anyway.
	w.seen[key] = ts.Add(w.skew)
	return nil
}

// evictLocked removes tags whose retention time has passed. Caller holds mu.
func (w *ReplayWindow) evictLocked(now time.Time) {
	for k, exp := range w.seen {
		if now.After(exp) {
			delete(w.seen, k)
		}
	}
}

// Size reports how many tags are currently remembered (useful for tests/metrics).
func (w *ReplayWindow) Size() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.seen)
}
