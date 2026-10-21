package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// DeriveKey derives a single key of length n bytes from a secret using
// HKDF-SHA256 with the given salt and info (context/label). info binds the
// derived key to its purpose so the same secret yields independent keys for
// different uses (e.g. "rahro c->s key" vs "rahro s->c key").
func DeriveKey(secret, salt []byte, info string, n int) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, secret, salt, info, n)
	if err != nil {
		return nil, fmt.Errorf("hkdf derive %q: %w", info, err)
	}
	return key, nil
}

// SessionKeys holds the two directional AEAD keys for a tunnel session plus the
// AEAD suite they are to be used with.
type SessionKeys struct {
	// Suite is the AEAD suite name (see aead.go).
	Suite string
	// ClientToServer encrypts traffic from client to server.
	ClientToServer []byte
	// ServerToClient encrypts traffic from server to client.
	ServerToClient []byte
}

// DeriveSessionKeys turns a shared secret into independent directional keys for
// the chosen AEAD suite. salt should be handshake-unique (e.g. a transcript
// hash) so two sessions never derive the same keys.
func DeriveSessionKeys(secret, salt []byte, suite string) (*SessionKeys, error) {
	kl, err := keyLenForSuite(suite)
	if err != nil {
		return nil, err
	}
	c2s, err := DeriveKey(secret, salt, "rahro v1 c2s", kl)
	if err != nil {
		return nil, err
	}
	s2c, err := DeriveKey(secret, salt, "rahro v1 s2c", kl)
	if err != nil {
		return nil, err
	}
	return &SessionKeys{Suite: suite, ClientToServer: c2s, ServerToClient: s2c}, nil
}
