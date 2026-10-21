package config

// NodeDeploy is the runtime configuration the panel pushes to a node after
// enrollment. A location (foreign egress) node runs a Rahro server; a tunnel
// (Iran relay) node runs local inbounds and a Rahro client to its upstream.
type NodeDeploy struct {
	NodeID int64  `json:"node_id"`
	Role   string `json:"role"` // location|tunnel

	// Location-node fields (runs the Rahro server/egress).
	ServerPrivateKey string `json:"server_private_key,omitempty"`
	Listen           string `json:"listen,omitempty"`
	Decoy            string `json:"decoy,omitempty"`

	// Tunnel-node fields (relays to a foreign node over the Rahro tunnel).
	UpstreamAddr    string `json:"upstream_addr,omitempty"`
	ServerPublicKey string `json:"server_public_key,omitempty"`
	SNI             string `json:"sni,omitempty"`
	UUID            string `json:"uuid,omitempty"`
	ServingMode     string `json:"serving_mode,omitempty"`
	SOCKS           string `json:"socks,omitempty"` // local user ingress (demo/standard)
	Fingerprint     string `json:"fingerprint,omitempty"`
}

// NodeLocalFile is what `rahro-node enroll` saves locally so `rahro-node run`
// can authenticate to the panel and pull its NodeDeploy.
type NodeLocalFile struct {
	Panel    string `json:"panel"`    // panel base URL
	NodeID   int64  `json:"node_id"`  // assigned at enrollment
	Secret   string `json:"secret"`   // shared secret
	Insecure bool   `json:"insecure"` // skip TLS verification (self-signed panel)
}
