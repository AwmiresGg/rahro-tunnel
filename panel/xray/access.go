package xray

import "strings"

// ParseAccessLine extracts the source IP and user email from one Xray access
// log line, if present. Lines look like:
//
//	2024/01/02 03:04:05 from 1.2.3.4:5678 accepted tcp:ex.com:443 [in -> out] email: alice
//
// The "from" address may carry a tcp:/udp: prefix and always has a port; the
// email is the token after "email:". Returns ok=false for lines without both.
func ParseAccessLine(line string) (ip, email string, ok bool) {
	fields := strings.Fields(line)
	for i, f := range fields {
		switch f {
		case "from":
			if i+1 < len(fields) {
				ip = stripToIP(fields[i+1])
			}
		case "email:":
			if i+1 < len(fields) {
				email = fields[i+1]
			}
		}
	}
	return ip, email, ip != "" && email != ""
}

// stripToIP turns "tcp:1.2.3.4:5678" or "[::1]:5678" into the bare IP.
func stripToIP(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "tcp:"), "udp:")
	// IPv6 in brackets: [::1]:port
	if strings.HasPrefix(s, "[") {
		if j := strings.Index(s, "]"); j > 0 {
			return s[1:j]
		}
	}
	// IPv4:port -> drop the last :port.
	if j := strings.LastIndex(s, ":"); j > 0 {
		return s[:j]
	}
	return s
}
