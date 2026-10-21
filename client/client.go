// Package client implements the Rahro user-side client: local inbounds
// (SOCKS5, HTTP proxy) that funnel application traffic through a multiplexed
// Rahro tunnel to the server.
package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/awmiresgg/rahro/core/obfs"
	"github.com/awmiresgg/rahro/core/proto"
	"github.com/awmiresgg/rahro/core/relay"
)

// Dialer establishes an authenticated transport connection to the server.
// transport.TLSClient satisfies it.
type Dialer interface {
	Dial(ctx context.Context) (net.Conn, error)
}

// Client maintains a multiplexed session to the server and opens a new stream
// per inbound connection, re-dialing transparently if the session drops.
type Client struct {
	dialer Dialer
	log    *slog.Logger

	mu   sync.Mutex
	sess *proto.Session
}

// New creates a Client over the given transport dialer.
func New(d Dialer, log *slog.Logger) *Client {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Client{dialer: d, log: log}
}

// session returns a live session, dialing/creating one if needed.
func (c *Client) session(ctx context.Context) (*proto.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != nil && !dead(c.sess) {
		return c.sess, nil
	}
	conn, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, err
	}
	c.sess = proto.Client(conn, &proto.Config{Padder: obfs.NewRandomPadder()})
	c.log.Debug("opened new tunnel session")
	return c.sess, nil
}

func dead(s *proto.Session) bool {
	select {
	case <-s.CloseChan():
		return true
	default:
		return false
	}
}

// Dial opens a tunnel stream to target ("host:port") via the server's egress.
func (c *Client) Dial(ctx context.Context, target string) (*proto.Stream, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		sess, err := c.session(ctx)
		if err != nil {
			return nil, err
		}
		st, err := sess.OpenStream()
		if err != nil {
			lastErr = err
			c.mu.Lock()
			if c.sess == sess {
				c.sess = nil // force a redial next attempt
			}
			c.mu.Unlock()
			continue
		}
		if err := relay.WriteAddr(st, target); err != nil {
			st.Close()
			return nil, fmt.Errorf("client: write target: %w", err)
		}
		return st, nil
	}
	return nil, fmt.Errorf("client: open stream: %w", lastErr)
}

// Close tears down the current session, if any.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != nil {
		err := c.sess.Close()
		c.sess = nil
		return err
	}
	return nil
}
