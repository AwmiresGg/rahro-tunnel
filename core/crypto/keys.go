// Package crypto provides Rahro's cryptographic primitives. It is a thin,
// carefully-used layer over the Go standard library and the vetted
// golang.org/x/crypto package. It deliberately implements NO cryptographic
// primitives of its own — only composition (key agreement, KDF, AEAD framing,
// a replay window, and the handshake authenticator used by the REALITY-style
// server).
//
// Primitives used:
//   - X25519 key agreement        (crypto/ecdh)
//   - HKDF-SHA256 key derivation   (crypto/hkdf)
//   - ChaCha20-Poly1305 AEAD       (golang.org/x/crypto/chacha20poly1305)
//   - AES-256-GCM AEAD             (crypto/aes + crypto/cipher)
//   - CSPRNG                        (crypto/rand)
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// KeyPair is an X25519 key pair. The private key is the server's long-term
// identity (or a client's per-session ephemeral); the public key is shared.
type KeyPair struct {
	priv *ecdh.PrivateKey
}

// GenerateKeyPair creates a fresh X25519 key pair using the system CSPRNG.
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return &KeyPair{priv: priv}, nil
}

// PrivateKeyFromBytes rebuilds a KeyPair from 32 raw private-key bytes.
func PrivateKeyFromBytes(b []byte) (*KeyPair, error) {
	priv, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse x25519 private key: %w", err)
	}
	return &KeyPair{priv: priv}, nil
}

// PrivateKeyFromBase64 parses a standard-base64-encoded 32-byte private key.
func PrivateKeyFromBase64(s string) (*KeyPair, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode base64 private key: %w", err)
	}
	return PrivateKeyFromBytes(b)
}

// PrivateBytes returns the 32-byte raw private key. Handle with care.
func (k *KeyPair) PrivateBytes() []byte { return k.priv.Bytes() }

// PrivateBase64 returns the private key as standard base64.
func (k *KeyPair) PrivateBase64() string {
	return base64.StdEncoding.EncodeToString(k.priv.Bytes())
}

// PublicBytes returns the 32-byte raw public key.
func (k *KeyPair) PublicBytes() []byte { return k.priv.PublicKey().Bytes() }

// PublicBase64 returns the public key as standard base64 (for configs/links).
func (k *KeyPair) PublicBase64() string {
	return base64.StdEncoding.EncodeToString(k.priv.PublicKey().Bytes())
}

// PublicKey returns the underlying ecdh public key.
func (k *KeyPair) PublicKey() *ecdh.PublicKey { return k.priv.PublicKey() }

// PublicKeyFromBytes parses 32 raw public-key bytes.
func PublicKeyFromBytes(b []byte) (*ecdh.PublicKey, error) {
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse x25519 public key: %w", err)
	}
	return pub, nil
}

// PublicKeyFromBase64 parses a standard-base64-encoded 32-byte public key.
func PublicKeyFromBase64(s string) (*ecdh.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode base64 public key: %w", err)
	}
	return PublicKeyFromBytes(b)
}

// SharedSecret performs the X25519 Diffie-Hellman between a local private key
// and a remote public key, returning the 32-byte shared secret.
//
// Both sides compute the same value: client does SharedSecret(e_priv, S_pub)
// and server does SharedSecret(S_priv, e_pub).
func (k *KeyPair) SharedSecret(remote *ecdh.PublicKey) ([]byte, error) {
	secret, err := k.priv.ECDH(remote)
	if err != nil {
		return nil, fmt.Errorf("x25519 ecdh: %w", err)
	}
	return secret, nil
}
