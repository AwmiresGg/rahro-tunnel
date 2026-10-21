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
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"

	"github.com/awmiresgg/rahro/core/crypto"
)

// WSClient tunnels over a WebSocket (wss://), which survives CDNs and
// HTTP-aware middleboxes and enables domain fronting. The authenticator and
// mux stream ride inside the WebSocket as binary messages.
//
// Note: uTLS browser-fingerprint mimicry is not yet applied on the WS path
// (the TLS here is driven by net/http); that is an M5+ refinement. WS mode's
// primary stealth comes from living behind a real CDN/host on a secret path.
type WSClient struct {
	// URL is the full endpoint, e.g. "wss://cdn.example.com/secretpath".
	URL string
	// ServerPub is the server's long-term X25519 public key.
	ServerPub *ecdh.PublicKey
	// UserID identifies this client.
	UserID [16]byte
	// SNI overrides the TLS server name (defaults to the URL host).
	SNI string
	// PinnedRootCAs, when non-nil, verifies the TLS certificate; otherwise the
	// certificate is not verified (trust is the Rahro authenticator).
	PinnedRootCAs *x509.CertPool
	// HandshakeTimeout bounds dial+auth (default DefaultHandshakeTimeout).
	HandshakeTimeout time.Duration
	// HTTPClient overrides the HTTP client (for custom TLS/CDN setups).
	HTTPClient *http.Client
}

// Dial opens the WebSocket, authenticates, and returns the connection.
func (c *WSClient) Dial(ctx context.Context) (net.Conn, error) {
	if c.ServerPub == nil {
		return nil, fmt.Errorf("transport: ServerPub is required")
	}
	timeout := c.HandshakeTimeout
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpClient := c.HTTPClient
	if httpClient == nil {
		sni := c.SNI
		if sni == "" {
			if u, err := url.Parse(c.URL); err == nil {
				sni = u.Hostname()
			}
		}
		tlsConf := &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}
		if c.PinnedRootCAs != nil {
			tlsConf.RootCAs = c.PinnedRootCAs
		} else {
			tlsConf.InsecureSkipVerify = true
		}
		httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}
	}

	ws, _, err := websocket.Dial(dctx, c.URL, &websocket.DialOptions{HTTPClient: httpClient})
	if err != nil {
		return nil, fmt.Errorf("transport: ws dial: %w", err)
	}
	ws.SetReadLimit(-1)
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)

	payload := crypto.AuthPayload{UserID: c.UserID, Time: time.Now()}
	if _, err := rand.Read(payload.Nonce[:]); err != nil {
		conn.Close()
		return nil, err
	}
	msg, _, err := crypto.SealHandshake(c.ServerPub, authAD(c.ServerPub), payload)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		conn.Close()
		return nil, fmt.Errorf("transport: ws write handshake: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})
	return conn, nil
}

// WSServer is an http.Handler that upgrades WebSocket requests on a secret path,
// authenticates them, and exposes authenticated connections through Accept.
// Mount it under your HTTPS server (or behind nginx/a CDN); unmatched paths
// should be served by your own handler (a real site), which doubles as the
// decoy for probers.
type WSServer struct {
	Key              *crypto.KeyPair
	Replay           *crypto.ReplayWindow
	HandshakeTimeout time.Duration
	Logger           *slog.Logger

	accept chan *AuthedConn
	once   bool
}

// NewWSServer creates a WSServer ready to serve HTTP and be Accept()ed from.
func NewWSServer(key *crypto.KeyPair, replay *crypto.ReplayWindow, log *slog.Logger) *WSServer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &WSServer{
		Key:    key,
		Replay: replay,
		Logger: log,
		accept: make(chan *AuthedConn),
	}
}

func (s *WSServer) timeout() time.Duration {
	if s.HandshakeTimeout > 0 {
		return s.HandshakeTimeout
	}
	return DefaultHandshakeTimeout
}

// ServeHTTP upgrades the request to a WebSocket and authenticates it.
func (s *WSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	ws.SetReadLimit(-1)
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)

	_ = conn.SetReadDeadline(time.Now().Add(s.timeout()))
	buf := make([]byte, crypto.HandshakeMessageSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	payload, _, err := crypto.OpenHandshake(s.Key, authAD(s.Key.PublicKey()), buf)
	if err != nil {
		s.Logger.Debug("ws auth failed", "remote", r.RemoteAddr)
		conn.Close()
		return
	}
	if s.Replay != nil && s.Replay.Check(payload.Nonce[:], payload.Time) != nil {
		s.Logger.Warn("ws replayed authenticator", "remote", r.RemoteAddr)
		conn.Close()
		return
	}

	select {
	case s.accept <- &AuthedConn{Conn: conn, UserID: payload.UserID}:
		// Hold ServeHTTP open; closing it would tear down the websocket. The
		// consumer closes the AuthedConn when the tunnel session ends.
		<-r.Context().Done()
	case <-r.Context().Done():
		conn.Close()
	}
}

// Accept returns the next authenticated WebSocket connection.
func (s *WSServer) Accept() (*AuthedConn, error) {
	ac, ok := <-s.accept
	if !ok {
		return nil, net.ErrClosed
	}
	return ac, nil
}
