package crypto

import (
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"time"
)

// authVersion is the current handshake-authenticator wire version.
const authVersion uint8 = 1

// authInfo is the HKDF context label for the authenticator key.
const authInfo = "rahro v1 auth"

// UserIDLen is the fixed length of a user identifier inside the authenticator.
const UserIDLen = 16

// authNonceLen is the length of the per-handshake random nonce that also
// serves as the replay tag.
const authNonceLen = 16

// authPayloadLen is the fixed marshaled size of an AuthPayload.
//
//	version(1) + unixSeconds(8) + userID(16) + nonce(16)
const authPayloadLen = 1 + 8 + UserIDLen + authNonceLen

// ephemeralPubLen is the length of the X25519 public key prepended by
// SealHandshake.
const ephemeralPubLen = 32

// HandshakeMessageSize is the exact byte length of a SealHandshake output under
// the default suite. Because the authenticated payload is fixed-size, the whole
// handshake message is a constant size, which lets the server read exactly this
// many bytes before deciding whether a connection is a genuine Rahro client or
// an unauthenticated probe to be sent to the decoy.
//
//	ephemeralPub(32) + nonce(12) + payload(41) + AEAD tag(16) = 101
const HandshakeMessageSize = ephemeralPubLen + NonceSize + authPayloadLen + TagSize

// AuthPayload is the authenticated plaintext a client proves to the server
// during the handshake. It identifies the user and carries freshness material
// (timestamp + nonce) consumed by a ReplayWindow.
type AuthPayload struct {
	Version uint8
	UserID  [UserIDLen]byte
	Time    time.Time
	Nonce   [authNonceLen]byte
}

// marshal encodes the payload into its fixed-size wire form.
func (p *AuthPayload) marshal() []byte {
	b := make([]byte, authPayloadLen)
	b[0] = p.Version
	binary.BigEndian.PutUint64(b[1:9], uint64(p.Time.Unix()))
	copy(b[9:9+UserIDLen], p.UserID[:])
	copy(b[9+UserIDLen:], p.Nonce[:])
	return b
}

// unmarshalAuthPayload decodes the fixed-size wire form.
func unmarshalAuthPayload(b []byte) (AuthPayload, error) {
	var p AuthPayload
	if len(b) != authPayloadLen {
		return p, fmt.Errorf("auth payload: want %d bytes, got %d", authPayloadLen, len(b))
	}
	p.Version = b[0]
	if p.Version != authVersion {
		return p, fmt.Errorf("auth payload: unsupported version %d", p.Version)
	}
	p.Time = time.Unix(int64(binary.BigEndian.Uint64(b[1:9])), 0)
	copy(p.UserID[:], b[9:9+UserIDLen])
	copy(p.Nonce[:], b[9+UserIDLen:])
	return p, nil
}

// authKey derives the one-shot AEAD key from the DH shared secret.
func authKey(secret []byte) ([]byte, error) {
	return DeriveKey(secret, nil, authInfo, 32)
}

// SealAuthenticator produces the authenticator blob. The client derives a key
// from X25519(ephemeralPriv, serverPub), encrypts the payload under a random
// nonce, and binds the result to associatedData (e.g. the ClientHello bytes) as
// AEAD additional data. The ephemeral public key is transmitted separately by
// the transport (the TLS key_share in the REALITY design).
func SealAuthenticator(ephemeralPriv *KeyPair, serverPub *ecdh.PublicKey, associatedData []byte, payload AuthPayload) ([]byte, error) {
	if payload.Version == 0 {
		payload.Version = authVersion
	}
	secret, err := ephemeralPriv.SharedSecret(serverPub)
	if err != nil {
		return nil, err
	}
	key, err := authKey(secret)
	if err != nil {
		return nil, err
	}
	aead, err := NewAEAD(DefaultSuite, key)
	if err != nil {
		return nil, err
	}
	return SealWithRandomNonce(aead, payload.marshal(), associatedData)
}

// OpenAuthenticator reverses SealAuthenticator on the server side. It derives
// the same key from X25519(serverPriv, ephemeralPub) and authenticates the
// blob against associatedData. A failure here is how an unauthenticated prober
// is detected: the server then falls back to proxying the connection to the
// real decoy site (that fallback lives in the server package, M3).
//
// The caller is responsible for passing payload.Nonce / payload.Time to a
// ReplayWindow to reject replays.
func OpenAuthenticator(serverPriv *KeyPair, ephemeralPub *ecdh.PublicKey, associatedData, sealed []byte) (AuthPayload, error) {
	secret, err := serverPriv.SharedSecret(ephemeralPub)
	if err != nil {
		return AuthPayload{}, err
	}
	key, err := authKey(secret)
	if err != nil {
		return AuthPayload{}, err
	}
	aead, err := NewAEAD(DefaultSuite, key)
	if err != nil {
		return AuthPayload{}, err
	}
	pt, err := OpenWithPrefixedNonce(aead, sealed, associatedData)
	if err != nil {
		return AuthPayload{}, err
	}
	return unmarshalAuthPayload(pt)
}

// SealHandshake is a self-contained convenience wrapper used by transports that
// do not carry a separate key_share channel: it generates an ephemeral key pair
// and returns ephemeralPublic(32) || authenticator, plus the ephemeral KeyPair
// (so the caller can continue a key schedule if desired).
func SealHandshake(serverPub *ecdh.PublicKey, associatedData []byte, payload AuthPayload) (msg []byte, ephemeral *KeyPair, err error) {
	ephemeral, err = GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	sealed, err := SealAuthenticator(ephemeral, serverPub, associatedData, payload)
	if err != nil {
		return nil, nil, err
	}
	pub := ephemeral.PublicBytes()
	msg = make([]byte, 0, len(pub)+len(sealed))
	msg = append(msg, pub...)
	msg = append(msg, sealed...)
	return msg, ephemeral, nil
}

// OpenHandshake reverses SealHandshake: it splits the leading 32-byte ephemeral
// public key, then authenticates the remainder.
func OpenHandshake(serverPriv *KeyPair, associatedData, msg []byte) (AuthPayload, *ecdh.PublicKey, error) {
	if len(msg) < ephemeralPubLen {
		return AuthPayload{}, nil, fmt.Errorf("handshake too short (%d < %d)", len(msg), ephemeralPubLen)
	}
	ephemeralPub, err := PublicKeyFromBytes(msg[:ephemeralPubLen])
	if err != nil {
		return AuthPayload{}, nil, err
	}
	payload, err := OpenAuthenticator(serverPriv, ephemeralPub, associatedData, msg[ephemeralPubLen:])
	if err != nil {
		return AuthPayload{}, nil, err
	}
	return payload, ephemeralPub, nil
}
