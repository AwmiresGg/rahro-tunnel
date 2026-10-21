package transport

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/awmiresgg/rahro/core/crypto"
	"github.com/awmiresgg/rahro/core/proto"
)

func TestWebSocketTunnelEchoes(t *testing.T) {
	key, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wss := NewWSServer(key, crypto.NewReplayWindow(90*time.Second), nil)

	mux := http.NewServeMux()
	mux.Handle("/tunnel", wss)
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// Echo server over accepted WS tunnels.
	go func() {
		for {
			ac, err := wss.Accept()
			if err != nil {
				return
			}
			go func() {
				sess := proto.Server(ac, nil)
				st, err := sess.AcceptStream()
				if err != nil {
					return
				}
				io.Copy(st, st)
				st.Close()
			}()
		}
	}()

	var uid [16]byte
	rand.Read(uid[:])
	wsURL := strings.Replace(ts.URL, "https://", "wss://", 1) + "/tunnel"
	client := &WSClient{
		URL:        wsURL,
		ServerPub:  key.PublicKey(),
		UserID:     uid,
		HTTPClient: ts.Client(), // trusts the test server's certificate
	}

	done := make(chan error, 1)
	go func() {
		conn, err := client.Dial(context.Background())
		if err != nil {
			done <- err
			return
		}
		sess := proto.Client(conn, nil)
		st, err := sess.OpenStream()
		if err != nil {
			done <- err
			return
		}
		msg := []byte("hello over websocket tunnel")
		st.Write(msg)
		st.Close()
		got, err := io.ReadAll(st)
		if err != nil {
			done <- err
			return
		}
		if string(got) != string(msg) {
			t.Errorf("ws echo mismatch: %q", got)
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out")
	}
}
