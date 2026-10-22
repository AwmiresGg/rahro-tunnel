package xray

import "testing"

func TestParseTrafficStats(t *testing.T) {
	in := []byte(`{"stat":[
		{"name":"user>>>alice>>>traffic>>>uplink","value":"100"},
		{"name":"user>>>alice>>>traffic>>>downlink","value":"400"},
		{"name":"user>>>bob>>>traffic>>>uplink","value":"7"},
		{"name":"user>>>bob>>>traffic>>>downlink"},
		{"name":"inbound>>>api>>>traffic>>>uplink","value":"999"}
	]}`)
	got := parseTrafficStats(in)
	if got["alice"] != 500 {
		t.Fatalf("alice = %d, want 500", got["alice"])
	}
	if got["bob"] != 7 { // downlink omitted (0)
		t.Fatalf("bob = %d, want 7", got["bob"])
	}
	if _, ok := got["api"]; ok {
		t.Fatal("inbound stats should not be counted as a user")
	}
}

func TestParseTrafficStatsEmpty(t *testing.T) {
	if len(parseTrafficStats([]byte(`{}`))) != 0 {
		t.Fatal("empty stats should yield no users")
	}
	if len(parseTrafficStats([]byte(`garbage`))) != 0 {
		t.Fatal("garbage should yield no users")
	}
}
