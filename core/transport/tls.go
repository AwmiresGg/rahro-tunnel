package transport

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/awmiresgg/rahro/core/crypto"
)

// --- client ---

// TLSClient dials a Rahro server over TLS and authenticates with the REALITY-
// style handshake. On success Dial returns a net.Conn positioned at the start
// of the Rahro mux stream (wrap it with proto.Client).
type TLSClient struct {
	// ServerAddr is the server's "host:port".
	ServerAddr string
	// SNI is the TLS server name to present; it should match the decoy the
	// server borrows (e.g. "www.microsoft.com").
	SNI string
	// ServerPub is the server's long-term X25519 public key.
	ServerPub *ecdh.PublicKey
	// UserID identifies this client to the server.
	UserID [16]byte
	// PinnedRootCAs, when non-nil, verifies the server certificate against it.
	// When nil, the certificate is NOT verified: in the REALITY model trust is
	// established by the X25519 authenticator, not the (borrowed) certificate.
	PinnedRootCAs *x509.CertPool
	// HandshakeTimeout bounds the dial+TLS+auth phase (default
	// DefaultHandshakeTimeout).
	HandshakeTimeout time.Duration
	// Dialer is the underlying TCP dialer (default &net.Dialer{}).
	Dialer *net.Dialer
	// Fingerprint, when set, makes the client present a browser's TLS
	// ClientHello via uTLS: "chrome" (default), "firefox", "safari", "edge",
	// or "ios". Empty uses the Go standard library ClientHello. ("random" is
	// also accepted but may not negotiate with a strict TLS 1.3-only server.)
	Fingerprint string
}

// Dial connects, performs the TLS handshake, sends the authenticator, and
// returns the live connection.
func (c *TLSClient) Dial(ctx context.Context) (net.Conn, error) {
	if c.ServerPub == nil {
		return nil, fmt.Errorf("transport: ServerPub is required")
	}
	timeout := c.HandshakeTimeout
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := c.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	raw, err := dialer.DialContext(dctx, "tcp", c.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: dial: %w", err)
	}

	sec, err := c.secureHandshake(dctx, raw, timeout)
	if err != nil {
		raw.Close()
		return nil, err
	}

	payload := crypto.AuthPayload{UserID: c.UserID, Time: time.Now()}
	if _, err := rand.Read(payload.Nonce[:]); err != nil {
		sec.Close()
		return nil, fmt.Errorf("transport: nonce: %w", err)
	}
	msg, _, err := crypto.SealHandshake(c.ServerPub, authAD(c.ServerPub), payload)
	if err != nil {
		sec.Close()
		return nil, fmt.Errorf("transport: seal handshake: %w", err)
	}
	if _, err := sec.Write(msg); err != nil {
		sec.Close()
		return nil, fmt.Errorf("transport: write handshake: %w", err)
	}
	// Clear the handshake deadline; the data phase manages its own timeouts.
	_ = sec.SetDeadline(time.Time{})
	return sec, nil
}

// secureHandshake performs the TLS 1.3 handshake, using uTLS to present a
// browser ClientHello fingerprint when c.Fingerprint is set, otherwise the Go
// standard library.
func (c *TLSClient) secureHandshake(ctx context.Context, raw net.Conn, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	if c.Fingerprint != "" {
		ucfg := &utls.Config{ServerName: c.SNI, MinVersion: tls.VersionTLS12}
		if c.PinnedRootCAs != nil {
			ucfg.RootCAs = c.PinnedRootCAs
		} else {
			ucfg.InsecureSkipVerify = true
		}
		uconn := utls.UClient(raw, ucfg, fingerprintID(c.Fingerprint))
		_ = uconn.SetDeadline(deadline)
		if err := uconn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("transport: utls handshake: %w", err)
		}
		return uconn, nil
	}

	tlsCfg := &tls.Config{ServerName: c.SNI, MinVersion: tls.VersionTLS13}
	if c.PinnedRootCAs != nil {
		tlsCfg.RootCAs = c.PinnedRootCAs
	} else {
		tlsCfg.InsecureSkipVerify = true // trust comes from the Rahro authenticator
	}
	tconn := tls.Client(raw, tlsCfg)
	_ = tconn.SetDeadline(deadline)
	if err := tconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("transport: tls handshake: %w", err)
	}
	return tconn, nil
}

// fingerprintID maps a friendly name to a uTLS ClientHello fingerprint.
func fingerprintID(name string) utls.ClientHelloID {
	switch strings.ToLower(name) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "random":
		return utls.HelloRandomized
	default: // "chrome" and anything unrecognized
		return utls.HelloChrome_Auto
	}
}

// --- server ---

// TLSServer accepts Rahro connections over TLS and applies the REALITY-style
// probe defense.
type TLSServer struct {
	// Key is the server's long-term X25519 key pair.
	Key *crypto.KeyPair
	// Certificate is the server's TLS certificate (M3: self-signed for the
	// decoy SNI; M5: real/borrowed).
	Certificate tls.Certificate
	// Decoy is the real site unauthenticated connections are proxied to,
	// "host:port" (e.g. "www.microsoft.com:443").
	Decoy string
	// Replay rejects replayed authenticators (optional but recommended).
	Replay *crypto.ReplayWindow
	// HandshakeTimeout bounds the TLS handshake + authenticator read.
	HandshakeTimeout time.Duration
	// DecoyTLSConfig configures the TLS dial to the decoy. When nil, the decoy's
	// real certificate is verified against the host's name.
	DecoyTLSConfig *tls.Config
	// Logger receives structured logs (nil => discard).
	Logger *slog.Logger
}

func (s *TLSServer) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.New(slog.DiscardHandler)
}

func (s *TLSServer) timeout() time.Duration {
	if s.HandshakeTimeout > 0 {
		return s.HandshakeTimeout
	}
	return DefaultHandshakeTimeout
}

// Listener yields authenticated Rahro connections via Accept. Connections that
// fail authentication are transparently proxied to the decoy in the background
// and never surface through Accept.
type Listener struct {
	inner  net.Listener
	srv    *TLSServer
	tlsCfg *tls.Config
	accept chan *AuthedConn
	errc   chan error

	closeOnce sync.Once
	done      chan struct{}
}

// NewListener wraps an existing net.Listener (e.g. a TCP listener on :443) and
// starts accepting in the background.
func (s *TLSServer) NewListener(inner net.Listener) (*Listener, error) {
	if s.Key == nil {
		return nil, fmt.Errorf("transport: server Key is required")
	}
	if s.Decoy == "" {
		return nil, fmt.Errorf("transport: server Decoy is required")
	}
	l := &Listener{
		inner:  inner,
		srv:    s,
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{s.Certificate}, MinVersion: tls.VersionTLS13},
		accept: make(chan *AuthedConn),
		errc:   make(chan error, 1),
		done:   make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

func (l *Listener) acceptLoop() {
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			select {
			case l.errc <- err:
			case <-l.done:
			}
			return
		}
		go l.handle(raw)
	}
}

func (l *Listener) handle(raw net.Conn) {
	srv := l.srv
	tconn := tls.Server(raw, l.tlsCfg)
	_ = tconn.SetDeadline(time.Now().Add(srv.timeout()))

	if err := tconn.Handshake(); err != nil {
		// Not a valid TLS client (or hung). M3 drops it; raw-TCP forwarding of
		// non-TLS probes to the decoy is an M5 refinement.
		srv.logger().Debug("tls handshake failed", "remote", raw.RemoteAddr().String(), "err", err)
		tconn.Close()
		return
	}

	buf := make([]byte, crypto.HandshakeMessageSize)
	n, rerr := io.ReadFull(tconn, buf)

	authed := false
	var payload crypto.AuthPayload
	if rerr == nil {
		p, _, e := crypto.OpenHandshake(srv.Key, authAD(srv.Key.PublicKey()), buf)
		if e == nil {
			if srv.Replay == nil || srv.Replay.Check(p.Nonce[:], p.Time) == nil {
				authed = true
				payload = p
			} else {
				srv.logger().Warn("replayed authenticator rejected", "remote", raw.RemoteAddr().String())
			}
		}
	}

	// Clear the handshake deadline for the data phase / fallback.
	_ = tconn.SetDeadline(time.Time{})

	if authed {
		srv.logger().Debug("authenticated client", "remote", raw.RemoteAddr().String())
		ac := &AuthedConn{Conn: tconn, UserID: payload.UserID}
		select {
		case l.accept <- ac:
		case <-l.done:
			tconn.Close()
		}
		return
	}

	srv.logger().Debug("unauthenticated connection -> decoy fallback",
		"remote", raw.RemoteAddr().String(), "bytes_read", n, "decoy", srv.Decoy)
	srv.fallbackToDecoy(tconn, buf[:n])
}

// fallbackToDecoy transparently reverse-proxies an unauthenticated connection
// to the real decoy site, first replaying the bytes already read so the decoy
// sees the original request intact.
func (s *TLSServer) fallbackToDecoy(client net.Conn, prefix []byte) {
	defer client.Close()

	host, _, err := net.SplitHostPort(s.Decoy)
	if err != nil {
		host = s.Decoy
	}
	dconf := s.DecoyTLSConfig
	if dconf == nil {
		dconf = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	upstream, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", s.Decoy, dconf)
	if err != nil {
		s.logger().Debug("decoy dial failed", "decoy", s.Decoy, "err", err)
		return
	}
	defer upstream.Close()

	if len(prefix) > 0 {
		if _, err := upstream.Write(prefix); err != nil {
			return
		}
	}
	proxyBoth(client, upstream)
}

// proxyBoth pipes two connections together and returns when either direction
// ends, closing both (via the callers' defers).
func proxyBoth(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	// Unblock the other copy by closing both ends.
	a.Close()
	b.Close()
	<-done
}

// Accept returns the next authenticated Rahro connection.
func (l *Listener) Accept() (*AuthedConn, error) {
	select {
	case ac := <-l.accept:
		return ac, nil
	case err := <-l.errc:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops the listener. In-flight authenticated connections are not closed.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.inner.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }
