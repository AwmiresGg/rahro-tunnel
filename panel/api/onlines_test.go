package api

import (
	"testing"
	"time"
)

func TestOnlineTrackerIngestAndWindow(t *testing.T) {
	tr := newOnlineTracker()
	base := time.Now()
	tr.ingest([]string{
		"2024 from 1.1.1.1:2 accepted tcp:x:443 [a -> b] email: alice",
		"2024 from 2.2.2.2:3 accepted tcp:x:443 [a -> b] email: alice",
		"2024 from 3.3.3.3:4 accepted tcp:x:443 [a -> b] email: bob",
	}, base)

	ips, online := tr.userIPs("alice", base)
	if len(ips) != 2 || online != 2 {
		t.Fatalf("alice: ips=%v online=%d, want 2/2", ips, online)
	}
	// After the online window, IPs still remembered but not "online".
	_, online = tr.userIPs("alice", base.Add(onlineWindow+time.Second))
	if online != 0 {
		t.Fatalf("alice should be offline after window, got %d", online)
	}
	// After the IP window, old IPs are pruned on the next ingest.
	tr.ingest(nil, base.Add(ipWindow+time.Second))
	if ips, _ := tr.userIPs("alice", base.Add(ipWindow+time.Second)); len(ips) != 0 {
		t.Fatalf("alice IPs should be pruned, got %v", ips)
	}
}

func TestOnlineTrackerIPCount(t *testing.T) {
	tr := newOnlineTracker()
	now := time.Now()
	tr.ingest([]string{
		"from 1.1.1.1:1 accepted tcp:x:1 [a->b] email: u",
		"from 1.1.1.1:2 accepted tcp:x:1 [a->b] email: u", // same IP, different port
		"from 5.5.5.5:1 accepted tcp:x:1 [a->b] email: u",
	}, now)
	ips, _ := tr.userIPs("u", now)
	if len(ips) != 2 {
		t.Fatalf("distinct IPs = %d, want 2 (ports collapse)", len(ips))
	}
}
