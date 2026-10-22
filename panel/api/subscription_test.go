package api

import (
	"net/http/httptest"
	"testing"
)

func TestHostForRequest(t *testing.T) {
	cases := []struct {
		publicBase string
		reqHost    string
		want       string
	}{
		// Good configured host wins.
		{"https://1.2.3.4:2053", "panel.local:2053", "1.2.3.4"},
		{"https://panel.example.com:2053", "1.1.1.1", "panel.example.com"},
		// Placeholder/loopback configured -> fall back to the request host.
		{"https://YOUR_SERVER_IP:2053", "203.0.113.9:2298", "203.0.113.9"},
		{"http://127.0.0.1:2053", "5.6.7.8", "5.6.7.8"},
		{"", "9.9.9.9:443", "9.9.9.9"},
		// IPv6 request host.
		{"https://YOUR_SERVER_IP:2053", "[2001:db8::1]:2298", "2001:db8::1"},
	}
	for _, c := range cases {
		s := &Server{PublicBase: c.publicBase}
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.Host = c.reqHost
		if got := s.hostForRequest(r); got != c.want {
			t.Errorf("publicBase=%q reqHost=%q -> %q, want %q", c.publicBase, c.reqHost, got, c.want)
		}
	}
}

func TestUsableHost(t *testing.T) {
	for _, h := range []string{"", "YOUR_SERVER_IP", "127.0.0.1", "localhost", "0.0.0.0", "::1"} {
		if usableHost(h) {
			t.Errorf("%q should be unusable", h)
		}
	}
	for _, h := range []string{"1.2.3.4", "example.com", "2001:db8::1"} {
		if !usableHost(h) {
			t.Errorf("%q should be usable", h)
		}
	}
}
