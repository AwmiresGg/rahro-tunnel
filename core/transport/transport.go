package transport

import (
	"crypto/ecdh"
	"net"
	"time"
)

// Default timeouts for the transport handshake path.
const (
	// DefaultHandshakeTimeout bounds how long the server waits for a client's
	// authenticator (and how long the client allows for the full dial+auth).
	// A genuine Rahro client sends its fixed-size authenticator immediately, so
	// this mainly bounds how long an unauthenticated prober is held before being
	// handed to the decoy.
	DefaultHandshakeTimeout = 8 * time.Second
)

// authADPrefix domain-separates the handshake authenticator's associated data
// so an authenticator can never be replayed into a different protocol/version.
var authADPrefix = []byte("rahro/tls/v1\x00")

// authAD builds the associated data bound into the handshake authenticator.
// Both client and server derive it identically from the server's public key.
//
// M3 binds to the server identity and protocol label. M5 will additionally bind
// to the TLS session (exported keying material) to defeat relay/MITM probing.
func authAD(serverPub *ecdh.PublicKey) []byte {
	ad := make([]byte, 0, len(authADPrefix)+32)
	ad = append(ad, authADPrefix...)
	ad = append(ad, serverPub.Bytes()...)
	return ad
}

// AuthedConn is a connection from a successfully-authenticated Rahro client.
// The embedded net.Conn is positioned immediately after the authenticator, so
// the next bytes are the Rahro mux stream (core/proto).
type AuthedConn struct {
	net.Conn
	// UserID is the authenticated user's identifier from the handshake payload.
	UserID [16]byte
}
