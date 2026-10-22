package api

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/awmiresgg/rahro/panel/xray"
)

// onlineWindow is how recently a source IP must have appeared in the access
// log for a user to count as "online".
const onlineWindow = 70 * time.Second

// ipWindow is how long a source IP is remembered for IP-limit counting.
const ipWindow = 5 * time.Minute

// onlineTracker tails Xray's access log and keeps a recent per-user set of
// source IPs, used for the online indicator and IP-limit enforcement.
type onlineTracker struct {
	mu   sync.Mutex
	off  int64
	size int64
	seen map[string]map[string]time.Time // email -> ip -> last seen
}

func newOnlineTracker() *onlineTracker {
	return &onlineTracker{seen: map[string]map[string]time.Time{}}
}

// poll reads new lines appended to the access log at path and ingests them.
func (t *onlineTracker) poll(path string) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	t.mu.Lock()
	if fi.Size() < t.size {
		t.off = 0 // file was truncated/rotated
	}
	t.size = fi.Size()
	start := t.off
	t.mu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(start, 0); err != nil {
		return
	}
	var lines []string
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	var read int64
	for sc.Scan() {
		lines = append(lines, sc.Text())
		read += int64(len(sc.Bytes())) + 1
	}
	t.ingest(lines, time.Now())
	t.mu.Lock()
	t.off = start + read
	t.mu.Unlock()
}

// ingest records (email, ip) pairs from the given access-log lines and prunes
// entries older than ipWindow. Separated from file IO so it can be tested.
func (t *onlineTracker) ingest(lines []string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ln := range lines {
		ip, email, ok := xray.ParseAccessLine(ln)
		if !ok {
			continue
		}
		m := t.seen[email]
		if m == nil {
			m = map[string]time.Time{}
			t.seen[email] = m
		}
		m[ip] = now
	}
	// Prune stale IPs and empty users.
	for email, m := range t.seen {
		for ip, ts := range m {
			if now.Sub(ts) > ipWindow {
				delete(m, ip)
			}
		}
		if len(m) == 0 {
			delete(t.seen, email)
		}
	}
}

// userIPs returns the recent IPs for a user and how many are currently online.
func (t *onlineTracker) userIPs(email string, now time.Time) (ips []string, online int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for ip, ts := range t.seen[email] {
		ips = append(ips, ip)
		if now.Sub(ts) <= onlineWindow {
			online++
		}
	}
	sort.Strings(ips)
	return ips, online
}

// RunOnlineLoop tails the access log on a fast cadence, exposing online state
// and enforcing per-user IP limits. It blocks until ctx is cancelled.
func (s *Server) RunOnlineLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.pollOnline()
		}
	}
}

func (s *Server) pollOnline() {
	if s.Xray == nil || s.online == nil {
		return
	}
	s.online.poll(s.Xray.AccessLogPath())
	s.enforceIPLimits()
}

// enforceIPLimits disables a user who sustains more distinct source IPs than
// their ip_limit across two consecutive polls (so a brief overlap when roaming
// between networks doesn't trip it). Disabling is reversible by the admin.
func (s *Server) enforceIPLimits() {
	users, err := s.Store.ListUsers()
	if err != nil {
		return
	}
	now := time.Now()
	changed := false
	for _, u := range users {
		if !u.Enabled || u.IPLimit <= 0 {
			delete(s.ipStrikes, u.ID)
			continue
		}
		ips, _ := s.online.userIPs(u.Username, now)
		if len(ips) > u.IPLimit {
			s.ipStrikes[u.ID]++
			if s.ipStrikes[u.ID] >= 2 {
				u.Enabled = false
				if err := s.Store.UpdateUser(u); err == nil {
					s.Log.Warn("user disabled: IP limit exceeded",
						"user", u.Username, "ips", len(ips), "limit", u.IPLimit)
					changed = true
					delete(s.ipStrikes, u.ID)
				}
			}
		} else {
			delete(s.ipStrikes, u.ID)
		}
	}
	if changed {
		s.ApplyXray()
	}
}

// handleOnlines returns recent source IPs and the online count per user.
func (s *Server) handleOnlines(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	if s.online != nil {
		now := time.Now()
		users, _ := s.Store.ListUsers()
		for _, u := range users {
			ips, online := s.online.userIPs(u.Username, now)
			if len(ips) == 0 {
				continue
			}
			out[u.Username] = map[string]any{"ips": ips, "online": online}
		}
	}
	writeJSON(w, http.StatusOK, out)
}
