package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/awmiresgg/rahro/core/relay"
)

// HTTPProxy is an HTTP/HTTPS forward proxy inbound. It supports CONNECT
// (tunnelled HTTPS) and plain HTTP requests, forwarding both through the tunnel.
type HTTPProxy struct {
	Addr   string
	Client *Client
	Log    *slog.Logger
}

// ListenAndServe binds Addr and serves until the listener errors.
func (p *HTTPProxy) ListenAndServe() error {
	ln, err := net.Listen("tcp", p.Addr)
	if err != nil {
		return fmt.Errorf("http proxy listen %s: %w", p.Addr, err)
	}
	return p.Serve(ln)
}

// Serve accepts connections on ln.
func (p *HTTPProxy) Serve(ln net.Listener) error {
	if p.Log == nil {
		p.Log = slog.New(slog.DiscardHandler)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handle(c)
	}
}

// rwConn presents a buffered reader plus the underlying conn as one
// io.ReadWriteCloser so buffered bytes are not lost when we start piping.
type rwConn struct {
	r io.Reader
	net.Conn
}

func (c rwConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (p *HTTPProxy) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		target := withDefaultPort(req.Host, "443")
		st, err := p.Client.Dial(context.Background(), target)
		if err != nil {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer st.Close()
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		relay.Pipe(rwConn{r: br, Conn: c}, st)
		return
	}

	// Plain HTTP: forward the request to the origin through the tunnel.
	target := withDefaultPort(req.Host, "80")
	st, err := p.Client.Dial(context.Background(), target)
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer st.Close()

	req.RequestURI = ""
	if err := req.Write(st); err != nil {
		return
	}
	relay.Pipe(rwConn{r: br, Conn: c}, st)
}

func withDefaultPort(host, defPort string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, defPort)
}
