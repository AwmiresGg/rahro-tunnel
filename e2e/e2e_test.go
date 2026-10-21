// Package e2e wires a full Rahro client+transport+server stack over loopback
// and pushes real traffic through it.
package e2e

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/awmiresgg/rahro/client"
	"github.com/awmiresgg/rahro/core/crypto"
	"github.com/awmiresgg/rahro/core/transport"
	"github.com/awmiresgg/rahro/server"
)

// stack builds a decoy, a Rahro server+egress, and a Rahro client+SOCKS5
// inbound. It returns the local SOCKS5 address.
func stack(t *testing.T) (socksAddr string) {
	t.Helper()

	decoy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "DECOY")
	}))
	t.Cleanup(decoy.Close)

	key, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := transport.GenerateSelfSignedCert("localhost", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srv := &transport.TLSServer{
		Key:            key,
		Certificate:    cert,
		Decoy:          decoy.Listener.Addr().String(),
		Replay:         crypto.NewReplayWindow(90 * time.Second),
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

	egress := &server.Egress{}
	go egress.Serve(l)

	var uid [16]byte
	rand.Read(uid[:])
	tc := &transport.TLSClient{
		ServerAddr: l.Addr().String(),
		SNI:        "localhost",
		ServerPub:  key.PublicKey(),
		UserID:     uid,
	}
	c := client.New(tc, nil)
	t.Cleanup(func() { c.Close() })

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socksLn.Close() })
	socks := &client.SOCKS5{Client: c}
	go socks.Serve(socksLn)

	return socksLn.Addr().String()
}

func TestEndToEndSOCKS(t *testing.T) {
	socksAddr := stack(t)

	// The real origin the user wants to reach.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "TARGET-OK")
	}))
	defer target.Close()

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		},
	}

	resp, err := httpClient.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "TARGET-OK" {
		t.Fatalf("got %q through the tunnel, want TARGET-OK", body)
	}
}

func TestEndToEndMultipleStreams(t *testing.T) {
	socksAddr := stack(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok-%s", r.URL.Query().Get("n"))
	}))
	defer target.Close()

	dialer, _ := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: func(_ context.Context, n, a string) (net.Conn, error) { return dialer.Dial(n, a) }},
	}

	for i := 0; i < 10; i++ {
		resp, err := httpClient.Get(fmt.Sprintf("%s/?n=%d", target.URL, i))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if want := fmt.Sprintf("ok-%d", i); string(body) != want {
			t.Fatalf("req %d: got %q want %q", i, body, want)
		}
	}
}
