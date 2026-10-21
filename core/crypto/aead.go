package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD suite identifiers.
const (
	// SuiteChaCha20Poly1305 is the default: fast in software, constant-time,
	// ideal for devices without AES hardware acceleration.
	SuiteChaCha20Poly1305 = "chacha20poly1305"
	// SuiteAES256GCM is offered for hosts with AES-NI where it can be faster.
	SuiteAES256GCM = "aes-256-gcm"

	// DefaultSuite is what we pick when nothing is specified.
	DefaultSuite = SuiteChaCha20Poly1305
)

// keyLenForSuite returns the required key length in bytes for a suite.
func keyLenForSuite(suite string) (int, error) {
	switch suite {
	case SuiteChaCha20Poly1305, SuiteAES256GCM:
		return 32, nil
	case "":
		return 32, nil // default suite
	default:
		return 0, fmt.Errorf("unknown AEAD suite %q", suite)
	}
}

// NewAEAD constructs a cipher.AEAD for the given suite and key. The key length
// must match the suite (32 bytes for both supported suites).
func NewAEAD(suite string, key []byte) (cipher.AEAD, error) {
	if suite == "" {
		suite = DefaultSuite
	}
	want, err := keyLenForSuite(suite)
	if err != nil {
		return nil, err
	}
	if len(key) != want {
		return nil, fmt.Errorf("suite %q needs a %d-byte key, got %d", suite, want, len(key))
	}
	switch suite {
	case SuiteChaCha20Poly1305:
		return chacha20poly1305.New(key)
	case SuiteAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aes cipher: %w", err)
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("unknown AEAD suite %q", suite)
	}
}

// NonceSize is the AEAD nonce size in bytes. Both supported suites use a
// 12-byte (96-bit) nonce.
const NonceSize = chacha20poly1305.NonceSize

// TagSize is the AEAD authentication tag size in bytes. Both ChaCha20-Poly1305
// and AES-GCM append a 16-byte tag.
const TagSize = 16

// NonceSequence produces monotonically increasing deterministic nonces for a
// single key/direction. It encodes a 64-bit big-endian counter in the low 8
// bytes of a 12-byte nonce (the high 4 bytes stay zero). Reusing a (key, nonce)
// pair would be catastrophic for AEAD security, so each direction of a session
// MUST use its own key and its own NonceSequence, and the counter must never
// wrap — Next returns an error on overflow instead of silently reusing 0.
type NonceSequence struct {
	counter uint64
	buf     [NonceSize]byte
	// maxed becomes true once the counter space is exhausted.
	maxed bool
}

// Next returns the next nonce and advances the counter. The returned slice is
// backed by internal storage and is only valid until the following Next call;
// callers that retain it must copy. It returns an error once the 2^64 nonce
// space is exhausted (the caller should rekey well before this).
func (s *NonceSequence) Next() ([]byte, error) {
	if s.maxed {
		return nil, fmt.Errorf("nonce sequence exhausted; rekey required")
	}
	binary.BigEndian.PutUint64(s.buf[NonceSize-8:], s.counter)
	if s.counter == ^uint64(0) {
		s.maxed = true
	} else {
		s.counter++
	}
	return s.buf[:], nil
}

// SealWithRandomNonce encrypts plaintext under a fresh random nonce and returns
// nonce||ciphertext. Use this for one-shot messages where no sequencing state
// exists (the handshake authenticator). The random nonce makes reuse
// cryptographically negligible without any shared counter.
func SealWithRandomNonce(aead cipher.AEAD, plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read random nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, additionalData)
	return append(nonce, ct...), nil
}

// OpenWithPrefixedNonce reverses SealWithRandomNonce: it splits the leading
// nonce from nonce||ciphertext and authenticates/decrypts.
func OpenWithPrefixedNonce(aead cipher.AEAD, sealed, additionalData []byte) ([]byte, error) {
	ns := aead.NonceSize()
	if len(sealed) < ns {
		return nil, fmt.Errorf("sealed message too short (%d < nonce %d)", len(sealed), ns)
	}
	nonce, ct := sealed[:ns], sealed[ns:]
	pt, err := aead.Open(nil, nonce, ct, additionalData)
	if err != nil {
		return nil, fmt.Errorf("aead open (auth failed): %w", err)
	}
	return pt, nil
}
