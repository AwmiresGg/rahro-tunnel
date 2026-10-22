package xray

import "testing"

func TestParseAccessLine(t *testing.T) {
	cases := []struct {
		line, ip, email string
		ok              bool
	}{
		{"2024/01/02 03:04:05 from 1.2.3.4:5678 accepted tcp:ex.com:443 [in -> direct] email: alice", "1.2.3.4", "alice", true},
		{"2024/01/02 03:04:05 from tcp:9.9.9.9:111 accepted udp:dns:53 [in -> direct] email: bob", "9.9.9.9", "bob", true},
		{"2024/01/02 03:04:05 from [2001:db8::1]:443 accepted tcp:ex.com:443 [in -> direct] email: carol", "2001:db8::1", "carol", true},
		{"2024/01/02 03:04:05 from 1.2.3.4:5678 accepted tcp:ex.com:443 [in -> direct]", "", "", false}, // no email
		{"garbage line", "", "", false},
	}
	for _, c := range cases {
		ip, email, ok := ParseAccessLine(c.line)
		if ok != c.ok {
			t.Errorf("ParseAccessLine(%q) ok=%v, want %v", c.line, ok, c.ok)
			continue
		}
		if ok && (ip != c.ip || email != c.email) {
			t.Errorf("ParseAccessLine(%q) = (%q,%q), want (%q,%q)",
				c.line, ip, email, c.ip, c.email)
		}
	}
}
