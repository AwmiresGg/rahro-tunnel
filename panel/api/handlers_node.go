package api

import (
	"net/http"

	"github.com/awmiresgg/rahro/core/crypto"
	"github.com/awmiresgg/rahro/internal/config"
	"github.com/awmiresgg/rahro/panel/auth"
	"github.com/awmiresgg/rahro/panel/store"
)

const settingServerKey = "rahro_server_key"

// serverKey returns the panel-wide Rahro server key pair, creating and
// persisting it on first use. Location nodes run the Rahro server with this
// key; tunnel nodes and clients authenticate to it with the public half.
func (s *Server) serverKey() (*crypto.KeyPair, error) {
	if v, ok, err := s.Store.GetSetting(settingServerKey); err != nil {
		return nil, err
	} else if ok {
		return crypto.PrivateKeyFromBase64(v)
	}
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	if err := s.Store.SetSetting(settingServerKey, kp.PrivateBase64()); err != nil {
		return nil, err
	}
	return kp, nil
}

// ServerPublicKey exposes the panel's Rahro server public key (base64).
func (s *Server) ServerPublicKey() (string, error) {
	kp, err := s.serverKey()
	if err != nil {
		return "", err
	}
	return kp.PublicBase64(), nil
}

// POST /nodeapi/enroll {enroll_token, secret} — a node registers itself.
func (s *Server) handleNodeEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnrollToken string `json:"enroll_token"`
		Secret      string `json:"secret"`
	}
	if err := readJSON(r, &req); err != nil || req.EnrollToken == "" || req.Secret == "" {
		httpError(w, http.StatusBadRequest, "enroll_token and secret required")
		return
	}
	n, err := s.Store.EnrollNode(req.EnrollToken, req.Secret)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "invalid or used enrollment code")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_id": n.ID, "role": n.Role})
}

// POST /nodeapi/config {node_id, secret} — a node pulls its runtime config and
// sends a heartbeat. Authenticated by the shared secret from enrollment.
func (s *Server) handleNodeConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID int64  `json:"node_id"`
		Secret string `json:"secret"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	n, err := s.Store.AuthenticateNode(req.NodeID, req.Secret)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "invalid node credentials")
		return
	}
	s.Store.TouchNode(n.ID)

	kp, err := s.serverKey()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}

	dep := config.NodeDeploy{NodeID: n.ID, Role: n.Role, ServingMode: n.ServingMode}
	decoy := "www.microsoft.com:443"
	if v, ok, _ := s.Store.GetSetting("decoy"); ok && v != "" {
		decoy = v
	}

	switch n.Role {
	case store.RoleLocation, store.RolePanel:
		dep.ServerPrivateKey = kp.PrivateBase64()
		dep.Listen = ":443"
		dep.Decoy = decoy
	case store.RoleTunnel:
		up := n.Upstream
		if up == "" {
			// Fall back to the first enabled location node's address.
			if nodes, _ := s.Store.ListNodes(); nodes != nil {
				for _, cand := range nodes {
					if cand.Role == store.RoleLocation && cand.Enabled && cand.Address != "" {
						up = cand.Address
						break
					}
				}
			}
		}
		dep.UpstreamAddr = up
		dep.ServerPublicKey = kp.PublicBase64()
		dep.SNI = hostOnly(decoy)
		dep.UUID = tunnelUUID(n)
		dep.SOCKS = "0.0.0.0:1080"
		dep.Fingerprint = "chrome"
	}
	writeJSON(w, http.StatusOK, dep)
}

// tunnelUUID derives a stable 32-hex id for a tunnel node from its secret.
func tunnelUUID(n *store.Node) string {
	return auth.HashToken(n.Secret)[:32]
}
