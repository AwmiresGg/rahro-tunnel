package proto

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// ErrSessionClosed is returned by Session operations after the session has been
// torn down.
var ErrSessionClosed = errors.New("rahro/proto: session closed")

// Default session parameters.
const (
	defaultMaxFrameSize  = 16 * 1024  // 16 KiB payload per DATA frame
	defaultInitialWindow = 256 * 1024 // 256 KiB per-stream receive window
	defaultAcceptBacklog = 256
)

// Padder decides how many padding bytes to append to a frame to shape the
// length distribution seen by an on-path observer. It is implemented by
// core/obfs; nil means no padding. It must be safe for concurrent use.
type Padder interface {
	PadLen(t FrameType, payloadLen int) uint16
}

// Config tunes a Session. Both peers must agree on InitialWindow (it defines
// how much unacknowledged data a sender may have outstanding per stream); the
// defaults match, so two Sessions created with nil/zero config interoperate.
type Config struct {
	MaxFrameSize  int
	InitialWindow int
	AcceptBacklog int
	// Padder, if set, appends length-shaping padding to outbound frames.
	Padder Padder
}

func (c *Config) withDefaults() Config {
	out := Config{}
	if c != nil {
		out = *c
	}
	if out.MaxFrameSize <= 0 {
		out.MaxFrameSize = defaultMaxFrameSize
	}
	if out.MaxFrameSize > MaxPayloadSize {
		out.MaxFrameSize = MaxPayloadSize
	}
	if out.InitialWindow <= 0 {
		out.InitialWindow = defaultInitialWindow
	}
	if out.AcceptBacklog <= 0 {
		out.AcceptBacklog = defaultAcceptBacklog
	}
	return out
}

// Session multiplexes many Streams over a single transport connection.
type Session struct {
	conn     io.ReadWriteCloser
	cfg      Config
	isClient bool

	writeMu sync.Mutex // serializes frame writes to conn

	mu       sync.Mutex // guards streams, nextID, closing
	streams  map[uint32]*Stream
	nextID   uint32
	acceptCh chan *Stream
	closing  bool

	dieOnce sync.Once
	die     chan struct{}
	dieErr  error
}

// Client creates a session that initiates streams (odd stream IDs).
func Client(conn io.ReadWriteCloser, cfg *Config) *Session {
	return newSession(conn, cfg, true)
}

// Server creates a session that accepts streams (even stream IDs for the ones
// it opens itself).
func Server(conn io.ReadWriteCloser, cfg *Config) *Session {
	return newSession(conn, cfg, false)
}

func newSession(conn io.ReadWriteCloser, cfg *Config, isClient bool) *Session {
	s := &Session{
		conn:     conn,
		cfg:      cfg.withDefaults(),
		isClient: isClient,
		streams:  make(map[uint32]*Stream),
		acceptCh: make(chan *Stream, cfg.withDefaults().AcceptBacklog),
		die:      make(chan struct{}),
	}
	// Client-opened streams are odd, server-opened are even; this prevents the
	// two sides from ever choosing the same ID for a stream they each initiate.
	if isClient {
		s.nextID = 1
	} else {
		s.nextID = 2
	}
	go s.recvLoop()
	return s
}

// OpenStream creates a new outbound stream and sends its SYN.
func (s *Session) OpenStream() (*Stream, error) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil, s.exitErr()
	}
	id := s.nextID
	s.nextID += 2
	st := newStream(id, s, s.cfg.InitialWindow)
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.writeFrame(Frame{Type: FrameSYN, StreamID: id}); err != nil {
		s.removeStream(id)
		return nil, err
	}
	return st, nil
}

// AcceptStream returns the next inbound stream opened by the peer.
func (s *Session) AcceptStream() (*Stream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-s.die:
		// Drain any stream that raced in before death.
		select {
		case st := <-s.acceptCh:
			return st, nil
		default:
			return nil, s.exitErr()
		}
	}
}

// Close tears down the session and its underlying connection.
func (s *Session) Close() error {
	return s.closeWith(ErrSessionClosed)
}

// CloseChan returns a channel closed when the session dies.
func (s *Session) CloseChan() <-chan struct{} { return s.die }

// NumStreams reports the number of live streams (for tests/metrics).
func (s *Session) NumStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

// writeFrame serializes and writes one frame to the transport.
func (s *Session) writeFrame(f Frame) error {
	select {
	case <-s.die:
		return s.exitErr()
	default:
	}
	if s.cfg.Padder != nil && f.PadLen == 0 {
		f.PadLen = s.cfg.Padder.PadLen(f.Type, len(f.Payload))
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := WriteFrame(s.conn, f); err != nil {
		s.closeWith(err)
		return err
	}
	return nil
}

func (s *Session) sendWindowUpdate(id uint32, delta uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], delta)
	return s.writeFrame(Frame{Type: FrameWndUpdate, StreamID: id, Payload: b[:]})
}

// Ping sends a keepalive/timing-cover frame.
func (s *Session) Ping() error {
	return s.writeFrame(Frame{Type: FramePing})
}

func (s *Session) lookup(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// maybeRemove drops a stream once both directions are finished.
func (s *Session) maybeRemove(st *Stream) {
	st.recvMu.Lock()
	recvDone := st.recvFin
	st.recvMu.Unlock()
	st.sendMu.Lock()
	sendDone := st.sendClosed
	st.sendMu.Unlock()
	if recvDone && sendDone {
		s.removeStream(st.id)
	}
}

func (s *Session) recvLoop() {
	for {
		f, err := ReadFrame(s.conn)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				s.closeWith(io.EOF)
			} else {
				s.closeWith(err)
			}
			return
		}
		s.dispatch(f)
	}
}

func (s *Session) dispatch(f Frame) {
	switch f.Type {
	case FrameSYN:
		s.handleSYN(f)
	case FrameData:
		if st := s.lookup(f.StreamID); st != nil {
			if overflow := st.pushData(f.Payload); overflow {
				_ = st.reset()
			}
		}
	case FrameWndUpdate:
		if st := s.lookup(f.StreamID); st != nil && len(f.Payload) == 4 {
			st.grantWindow(binary.BigEndian.Uint32(f.Payload))
		}
	case FrameFin:
		if st := s.lookup(f.StreamID); st != nil {
			st.remoteFin()
			s.maybeRemove(st)
		}
	case FrameRst:
		if st := s.lookup(f.StreamID); st != nil {
			st.setTerm(ErrStreamReset)
			s.removeStream(f.StreamID)
		}
	case FramePing:
		// Keepalive/timing-cover: nothing to do for now.
	default:
		// Unknown frame types are ignored for forward compatibility.
	}
}

func (s *Session) handleSYN(f Frame) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	if _, exists := s.streams[f.StreamID]; exists {
		s.mu.Unlock()
		return // duplicate SYN; ignore
	}
	st := newStream(f.StreamID, s, s.cfg.InitialWindow)
	// Any SYN payload (e.g. a destination address in M4) is delivered as the
	// first readable bytes of the stream.
	if len(f.Payload) > 0 {
		st.recvBuf.Write(f.Payload)
	}
	s.streams[f.StreamID] = st
	s.mu.Unlock()

	select {
	case s.acceptCh <- st:
	default:
		// Accept backlog full: refuse the stream rather than block the read loop.
		_ = st.reset()
	}
}

func (s *Session) closeWith(err error) error {
	s.dieOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.dieErr = err
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.mu.Unlock()

		// Wake everyone blocked on these streams.
		for _, st := range streams {
			st.setTerm(err)
		}
		close(s.die)
		s.conn.Close()
	})
	return nil
}

// exitErr returns the reason the session died, or ErrSessionClosed.
func (s *Session) exitErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dieErr != nil && s.dieErr != io.EOF {
		return s.dieErr
	}
	return ErrSessionClosed
}
