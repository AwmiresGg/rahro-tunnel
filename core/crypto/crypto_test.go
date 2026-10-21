package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestKeyPairBase64RoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := PrivateKeyFromBase64(kp.PrivateBase64())
	if err != nil {
		t.Fatal(err)
	}
	if kp.PublicBase64() != kp2.PublicBase64() {
		t.Fatal("public key mismatch after private key round-trip")
	}
	if _, err := PublicKeyFromBase64(kp.PublicBase64()); err != nil {
		t.Fatalf("public key base64 parse: %v", err)
	}
}

func TestSharedSecretAgreement(t *testing.T) {
	a, _ := GenerateKeyPair()
	b, _ := GenerateKeyPair()
	ssA, err := a.SharedSecret(b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	ssB, err := b.SharedSecret(a.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ssA, ssB) {
		t.Fatal("DH shared secrets do not agree")
	}
	if len(ssA) != 32 {
		t.Fatalf("shared secret length = %d, want 32", len(ssA))
	}
}

func TestDeriveSessionKeysIndependent(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	salt := []byte("handshake-transcript")
	sk, err := DeriveSessionKeys(secret, salt, DefaultSuite)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sk.ClientToServer, sk.ServerToClient) {
		t.Fatal("directional keys must differ")
	}
	// Determinism: same inputs -> same keys.
	sk2, _ := DeriveSessionKeys(secret, salt, DefaultSuite)
	if !bytes.Equal(sk.ClientToServer, sk2.ClientToServer) {
		t.Fatal("HKDF derivation not deterministic")
	}
	// Different salt -> different keys.
	sk3, _ := DeriveSessionKeys(secret, []byte("other"), DefaultSuite)
	if bytes.Equal(sk.ClientToServer, sk3.ClientToServer) {
		t.Fatal("different salt should yield different keys")
	}
}

func TestAEADRoundTripBothSuites(t *testing.T) {
	for _, suite := range []string{SuiteChaCha20Poly1305, SuiteAES256GCM} {
		t.Run(suite, func(t *testing.T) {
			key := make([]byte, 32)
			rand.Read(key)
			aead, err := NewAEAD(suite, key)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("the quick brown fox")
			ad := []byte("associated")
			sealed, err := SealWithRandomNonce(aead, msg, ad)
			if err != nil {
				t.Fatal(err)
			}
			got, err := OpenWithPrefixedNonce(aead, sealed, ad)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("round-trip mismatch: %q", got)
			}
			// Tamper with ciphertext.
			sealed[len(sealed)-1] ^= 0xff
			if _, err := OpenWithPrefixedNonce(aead, sealed, ad); err == nil {
				t.Fatal("tampered ciphertext should fail to open")
			}
			sealed[len(sealed)-1] ^= 0xff // restore
			// Wrong associated data.
			if _, err := OpenWithPrefixedNonce(aead, sealed, []byte("wrong")); err == nil {
				t.Fatal("wrong associated data should fail to open")
			}
		})
	}
}

func TestNewAEADKeyLengthValidation(t *testing.T) {
	if _, err := NewAEAD(SuiteChaCha20Poly1305, make([]byte, 16)); err == nil {
		t.Fatal("short key should be rejected")
	}
	if _, err := NewAEAD("bogus-suite", make([]byte, 32)); err == nil {
		t.Fatal("unknown suite should be rejected")
	}
}

func TestNonceSequenceMonotonic(t *testing.T) {
	var ns NonceSequence
	n1, _ := ns.Next()
	first := append([]byte(nil), n1...)
	n2, _ := ns.Next()
	second := append([]byte(nil), n2...)
	if bytes.Equal(first, second) {
		t.Fatal("consecutive nonces must differ")
	}
	if len(first) != NonceSize {
		t.Fatalf("nonce size = %d, want %d", len(first), NonceSize)
	}
}

func TestNonceSequenceOverflow(t *testing.T) {
	ns := NonceSequence{counter: ^uint64(0)}
	if _, err := ns.Next(); err != nil {
		t.Fatalf("last nonce should succeed: %v", err)
	}
	if _, err := ns.Next(); err == nil {
		t.Fatal("exhausted nonce sequence must error, not wrap to 0")
	}
}

func TestReplayWindow(t *testing.T) {
	w := NewReplayWindow(60 * time.Second)
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return base }

	tag := []byte("tag-1")
	if err := w.Check(tag, base); err != nil {
		t.Fatalf("fresh tag should pass: %v", err)
	}
	if err := w.Check(tag, base); err == nil {
		t.Fatal("duplicate tag must be rejected")
	}
	// Stale timestamp.
	if err := w.Check([]byte("tag-2"), base.Add(-2*time.Minute)); err == nil {
		t.Fatal("stale timestamp must be rejected")
	}
	// Future timestamp.
	if err := w.Check([]byte("tag-3"), base.Add(2*time.Minute)); err == nil {
		t.Fatal("future timestamp must be rejected")
	}
	// A different fresh tag passes.
	if err := w.Check([]byte("tag-4"), base.Add(10*time.Second)); err != nil {
		t.Fatalf("distinct fresh tag should pass: %v", err)
	}
}

func TestReplayWindowEviction(t *testing.T) {
	w := NewReplayWindow(30 * time.Second)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return now }
	w.Check([]byte("old"), now)
	if w.Size() != 1 {
		t.Fatalf("expected 1 remembered tag, got %d", w.Size())
	}
	// Advance beyond retention; a new check should evict the old tag.
	now = now.Add(5 * time.Minute)
	w.Check([]byte("new"), now)
	if w.Size() != 1 {
		t.Fatalf("old tag should have been evicted, size=%d", w.Size())
	}
}

func randPayload(t *testing.T) AuthPayload {
	t.Helper()
	var p AuthPayload
	p.Version = authVersion
	p.Time = time.Now()
	rand.Read(p.UserID[:])
	rand.Read(p.Nonce[:])
	return p
}

func TestHandshakeRoundTrip(t *testing.T) {
	server, _ := GenerateKeyPair()
	ad := []byte("clienthello-bytes")
	payload := randPayload(t)

	msg, _, err := SealHandshake(server.PublicKey(), ad, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, ephPub, err := OpenHandshake(server, ad, msg)
	if err != nil {
		t.Fatalf("legitimate handshake should open: %v", err)
	}
	if got.UserID != payload.UserID || got.Nonce != payload.Nonce {
		t.Fatal("recovered payload does not match")
	}
	if ephPub == nil {
		t.Fatal("expected ephemeral public key")
	}
}

func TestHandshakeMessageSizeIsConstant(t *testing.T) {
	server, _ := GenerateKeyPair()
	for i := 0; i < 50; i++ {
		msg, _, err := SealHandshake(server.PublicKey(), []byte("ad"), randPayload(t))
		if err != nil {
			t.Fatal(err)
		}
		if len(msg) != HandshakeMessageSize {
			t.Fatalf("handshake size = %d, want constant %d", len(msg), HandshakeMessageSize)
		}
	}
}

func TestHandshakeWrongServerKeyFails(t *testing.T) {
	server, _ := GenerateKeyPair()
	attacker, _ := GenerateKeyPair()
	ad := []byte("clienthello")
	msg, _, err := SealHandshake(server.PublicKey(), ad, randPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	// A server (or prober) without the right private key cannot open it —
	// this is exactly what triggers the REALITY fallback to the decoy.
	if _, _, err := OpenHandshake(attacker, ad, msg); err == nil {
		t.Fatal("handshake must not open under the wrong server key")
	}
}

func TestHandshakeTamperedADFails(t *testing.T) {
	server, _ := GenerateKeyPair()
	msg, _, err := SealHandshake(server.PublicKey(), []byte("hello-A"), randPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenHandshake(server, []byte("hello-B"), msg); err == nil {
		t.Fatal("different associated data must fail authentication")
	}
}

func TestHandshakeTamperedMessageFails(t *testing.T) {
	server, _ := GenerateKeyPair()
	ad := []byte("hello")
	msg, _, err := SealHandshake(server.PublicKey(), ad, randPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	msg[len(msg)-1] ^= 0x01
	if _, _, err := OpenHandshake(server, ad, msg); err == nil {
		t.Fatal("tampered handshake must fail authentication")
	}
}

func TestLowLevelAuthenticatorWithExternalEphemeralKey(t *testing.T) {
	// Mirrors the real transport path: ephemeral public is carried separately
	// (as the TLS key_share), not inside the authenticator blob.
	server, _ := GenerateKeyPair()
	eph, _ := GenerateKeyPair()
	ad := []byte("transcript")
	payload := randPayload(t)

	sealed, err := SealAuthenticator(eph, server.PublicKey(), ad, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenAuthenticator(server, eph.PublicKey(), ad, sealed)
	if err != nil {
		t.Fatalf("open with external ephemeral pub failed: %v", err)
	}
	if got.UserID != payload.UserID {
		t.Fatal("payload mismatch")
	}
}

// TestHandshakeReplayIntegration shows the authenticator + replay window
// working together: the same captured handshake replayed is rejected.
func TestHandshakeReplayIntegration(t *testing.T) {
	server, _ := GenerateKeyPair()
	w := NewReplayWindow(90 * time.Second)
	ad := []byte("hello")
	payload := randPayload(t)
	msg, _, _ := SealHandshake(server.PublicKey(), ad, payload)

	open := func() error {
		p, _, err := OpenHandshake(server, ad, msg)
		if err != nil {
			return err
		}
		return w.Check(p.Nonce[:], p.Time)
	}
	if err := open(); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	if err := open(); err == nil {
		t.Fatal("replayed capture must be rejected by the replay window")
	}
}
