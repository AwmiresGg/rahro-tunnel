package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"
)

// handleDiag runs quick server-side connectivity checks so the admin can see
// exactly where a non-working config breaks, instead of guessing. It reports
// whether Xray is up, whether each enabled inbound's port is actually
// listening, and whether REALITY dests are reachable from the server.
func (s *Server) handleDiag(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}

	out["public_host"] = s.hostForRequest(r)
	if s.Xray != nil {
		xr := map[string]any{"installed": s.Xray.Installed(), "running": s.Xray.Running()}
		if v, err := s.Xray.Version(); err == nil {
			xr["version"] = v
		}
		out["xray"] = xr
	} else {
		out["xray"] = map[string]any{"installed": false, "running": false}
	}

	inbounds, _ := s.Store.ListInbounds()
	var ibs []map[string]any
	destSeen := map[string]bool{}
	var dests []map[string]any
	for _, in := range inbounds {
		if !in.Enabled {
			continue
		}
		ibs = append(ibs, map[string]any{
			"tag":       in.Tag,
			"port":      in.Port,
			"security":  in.Security,
			"listening": portListening(in.Port),
		})
		// For REALITY inbounds, check the dest (borrowed TLS target) is reachable.
		if in.Security == "reality" && in.Settings != "" {
			var ex map[string]any
			if json.Unmarshal([]byte(in.Settings), &ex) == nil {
				if d, _ := ex["dest"].(string); d != "" && !destSeen[d] {
					destSeen[d] = true
					dests = append(dests, map[string]any{"dest": d, "reachable": tcpReachable(d)})
				}
			}
		}
	}
	if ibs == nil {
		ibs = []map[string]any{}
	}
	out["inbounds"] = ibs
	out["reality_dests"] = dests
	writeJSON(w, http.StatusOK, out)
}

// portListening reports whether something is accepting TCP on the local port.
func portListening(port int) bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// tcpReachable reports whether host:port (default :443) accepts a TCP
// connection from this server.
func tcpReachable(hostport string) bool {
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = net.JoinHostPort(hostport, "443")
	}
	c, err := net.DialTimeout("tcp", hostport, 4*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
