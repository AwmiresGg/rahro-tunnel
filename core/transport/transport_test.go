package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/awmiresgg/rahro/core/crypto"
	"github.com/awmiresgg/rahro/core/proto"
)

// testServer spins up a decoy HTTPS site and a Rahro TLS server in front of it.
func testServer(t *testing.T) (addr string, serverKey *crypto.KeyPair) {
	t.Helper()

	decoy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "DECOY-OK: welcome to the real site")
	}))
	t.Cleanup(decoy.Close)
	decoyAddr := decoy.Listener.Addr().String()

	key, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := GenerateSelfSignedCert("localhost", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	srv := &TLSServer{
		Key:              key,
		Certificate:      cert,
		Decoy:            decoyAddr,
		Replay:           crypto.NewReplayWindow(90 * time.Second),
		HandshakeTimeout: 3 * time.Second,
		// The decoy is a local httptest server with its own cert; trust it.
		DecoyTLSConfig: &tls.Config{InsecureSkipVerify: true},
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := srv.NewListener(inner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	// Echo server for authenticated Rahro clients.
	go func() {
		for {
			ac, err := l.Accept()
			if err != nil {
				return
			}
			go func(c *AuthedConn) {
				sess := proto.Server(c, nil)
				for {
					st, err := sess.AcceptStream()
					if err != nil {
						return
					}
					go func(st *proto.Stream) {
						io.Copy(st, st)
						st.Close()
					}(st)
				}
			}(ac)
		}
	}()

	return l.Addr().String(), key
}

func TestAuthenticatedClientEchoes(t *testing.T) {
	addr, key := testServer(t)

	var uid [16]byte
	rand.Read(uid[:])
	client := &TLSClient{
		ServerAddr: addr,
		SNI:        "localhost",
		ServerPub:  key.PublicKey(),
		UserID:     uid,
	}

	done := make(chan error, 1)
	go func() {
		conn, err := client.Dial(context.Background())
		if err != nil {
			done <- fmt.Errorf("dial: %w", err)
			return
		}
		sess := proto.Client(conn, nil)
		st, err := sess.OpenStream()
		if err != nil {
			done <- fmt.Errorf("open: %w", err)
			return
		}
		msg := []byte("hello through the rahro tunnel")
		if _, err := st.Write(msg); err != nil {
			done <- fmt.Errorf("write: %w", err)
			return
		}
		st.Close()
		got, err := io.ReadAll(st)
		if err != nil {
			done <- fmt.Errorf("read: %w", err)
			return
		}
		if string(got) != string(msg) {
			done <- fmt.Errorf("echo mismatch: got %q", got)
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out")
	}
}

// TestProbeGetsDecoy models a censor's active prober: a plain TLS client that
// completes the handshake and sends an HTTP request. It must be transparently
// served the real decoy site, learning nothing about Rahro.
func TestProbeGetsDecoy(t *testing.T) {
	addr, _ := testServer(t)

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // the probe sees our (self-signed) cert
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// A full HTTP/1.1 request, padded past HandshakeMessageSize so the server
	// decides immediately rather than waiting for the handshake timeout.
	req := "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"User-Agent: censor-active-probe-0000000000000000000000000000\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"
	if len(req) <= crypto.HandshakeMessageSize {
		t.Fatalf("test bug: probe request must exceed %d bytes", crypto.HandshakeMessageSize)
	}
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp), "DECOY-OK") {
		t.Fatalf("probe should have received the decoy response, got:\n%s", resp)
	}
}

// TestWrongKeyClientGetsNoTunnel proves authentication is enforced: a client
// with the wrong server public key is routed to the decoy and cannot establish
// a working Rahro tunnel (it never receives its echo back).
func TestWrongKeyClientGetsNoTunnel(t *testing.T) {
	addr, _ := testServer(t)

	wrong, _ := crypto.GenerateKeyPair()
	var uid [16]byte
	rand.Read(uid[:])
	client := &TLSClient{
		ServerAddr: addr,
		SNI:        "localhost",
		ServerPub:  wrong.PublicKey(), // not the server's key
		UserID:     uid,
	}

	done := make(chan string, 1)
	go func() {
		conn, err := client.Dial(context.Background())
		if err != nil {
			done <- "" // dial failure also means no tunnel
			return
		}
		// A working tunnel would echo within this window; the wrong-key path is
		// routed to the decoy, so no echo arrives and the read deadline fires.
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		sess := proto.Client(conn, nil)
		st, err := sess.OpenStream()
		if err != nil {
			done <- ""
			return
		}
		st.Write([]byte("hello"))
		st.Close()
		got, _ := io.ReadAll(st)
		done <- string(got)
	}()

	select {
	case got := <-done:
		if got == "hello" {
			t.Fatal("wrong-key client must not get a working echo tunnel")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out")
	}
}
