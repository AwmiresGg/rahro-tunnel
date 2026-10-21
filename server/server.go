// Package server implements the Rahro server-side egress: it accepts
// authenticated tunnel connections, demultiplexes their streams, reads each
// stream's destination address, dials it, and pipes bytes to the Internet.
package server

import (
	"log/slog"
	"net"
	"time"

	"github.com/awmiresgg/rahro/core/proto"
	"github.com/awmiresgg/rahro/core/relay"
	"github.com/awmiresgg/rahro/core/transport"
)

// Egress accepts authenticated connections and relays their streams out.
type Egress struct {
	// DialTimeout bounds each upstream dial (default 15s).
	DialTimeout time.Duration
	// Resolver/Dialer override for tests (default net.Dialer).
	Dialer *net.Dialer
	Log    *slog.Logger
}

// Serve accepts authenticated connections from l until it errors.
func (e *Egress) Serve(l *transport.Listener) error {
	if e.Log == nil {
		e.Log = slog.New(slog.DiscardHandler)
	}
	for {
		ac, err := l.Accept()
		if err != nil {
			return err
		}
		go e.handleConn(ac)
	}
}

func (e *Egress) handleConn(ac *transport.AuthedConn) {
	sess := proto.Server(ac, nil)
	e.Log.Debug("tunnel session up", "user", shortID(ac.UserID))
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go e.handleStream(st)
	}
}

func (e *Egress) handleStream(st *proto.Stream) {
	defer st.Close()

	target, err := relay.ReadAddr(st)
	if err != nil {
		e.Log.Debug("read target failed", "err", err)
		return
	}

	timeout := e.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dialer := e.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	up, err := dialer.Dial("tcp", target)
	if err != nil {
		e.Log.Debug("egress dial failed", "target", target, "err", err)
		return
	}
	defer up.Close()

	relay.Pipe(st, up)
}

func shortID(id [16]byte) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 8)
	for i := 0; i < 4; i++ {
		b[i*2] = hex[id[i]>>4]
		b[i*2+1] = hex[id[i]&0xf]
	}
	return string(b)
}
