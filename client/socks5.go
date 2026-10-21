package client

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/awmiresgg/rahro/core/relay"
)

// SOCKS5 is a minimal SOCKS5 inbound (no auth, CONNECT only) that forwards each
// connection through the Rahro tunnel.
type SOCKS5 struct {
	Addr   string
	Client *Client
	Log    *slog.Logger
}

// ListenAndServe binds Addr and serves until the listener errors.
func (s *SOCKS5) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("socks5 listen %s: %w", s.Addr, err)
	}
	return s.Serve(ln)
}

// Serve accepts connections on ln.
func (s *SOCKS5) Serve(ln net.Listener) error {
	if s.Log == nil {
		s.Log = slog.New(slog.DiscardHandler)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *SOCKS5) handle(c net.Conn) {
	defer c.Close()

	// Greeting: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// Reply: no authentication required.
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER CMD RSV, then ATYP+ADDR+PORT (same wire shape as relay addr).
	rhdr := make([]byte, 3)
	if _, err := io.ReadFull(c, rhdr); err != nil {
		return
	}
	if rhdr[1] != 0x01 { // only CONNECT
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // command not supported
		return
	}
	target, err := relay.ReadAddr(c)
	if err != nil {
		c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	st, err := s.Client.Dial(context.Background(), target)
	if err != nil {
		s.Log.Debug("socks5 dial failed", "target", target, "err", err)
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer st.Close()

	// Success reply (bound addr 0.0.0.0:0).
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	relay.Pipe(c, st)
}
