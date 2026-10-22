package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/awmiresgg/rahro/panel/xray"
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

	// Parse the config Xray is actually running so we can detect a stale config
	// whose REALITY keys no longer match the database (the usual cause of a link
	// that is correct but still fails with "received real certificate").
	runningPriv := map[string]string{} // inbound tag -> privateKey in running config
	if s.Xray != nil {
		if b, err := s.Xray.ReadConfig(); err == nil {
			var cfg struct {
				Inbounds []struct {
					Tag            string `json:"tag"`
					StreamSettings struct {
						RealitySettings struct {
							PrivateKey string `json:"privateKey"`
						} `json:"realitySettings"`
					} `json:"streamSettings"`
				} `json:"inbounds"`
			}
			if json.Unmarshal(b, &cfg) == nil {
				for _, in := range cfg.Inbounds {
					if in.StreamSettings.RealitySettings.PrivateKey != "" {
						runningPriv[in.Tag] = in.StreamSettings.RealitySettings.PrivateKey
					}
				}
			}
		}
	}

	inbounds, _ := s.Store.ListInbounds()
	var ibs []map[string]any
	destSeen := map[string]bool{}
	var dests []map[string]any
	staleKeys := false
	for _, in := range inbounds {
		if !in.Enabled {
			continue
		}
		row := map[string]any{
			"tag":       in.Tag,
			"port":      in.Port,
			"security":  in.Security,
			"listening": portListening(in.Port),
		}
		// Compare the DB's REALITY key with what Xray is actually running.
		if in.Security == "reality" && in.Settings != "" {
			var ex map[string]any
			if json.Unmarshal([]byte(in.Settings), &ex) == nil {
				dbPriv, _ := ex["privateKey"].(string)
				if run, ok := runningPriv[in.Tag]; ok && dbPriv != "" {
					match := xray.RealityPublicKey(run) == xray.RealityPublicKey(dbPriv)
					row["keys_match_running"] = match
					if !match {
						staleKeys = true
					}
				} else if dbPriv != "" {
					row["keys_match_running"] = false
					staleKeys = true
				}
			}
		}
		ibs = append(ibs, row)
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
	out["stale_keys"] = staleKeys
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
