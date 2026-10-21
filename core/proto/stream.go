package proto

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"time"
)

// ErrStreamClosed is returned when operating on a locally-closed stream.
var ErrStreamClosed = errors.New("rahro/proto: stream closed")

// ErrStreamReset is returned when the peer abortively reset the stream.
var ErrStreamReset = errors.New("rahro/proto: stream reset by peer")

// Stream is a bidirectional, flow-controlled logical connection multiplexed
// over a Session. It satisfies the read/write/close subset of net.Conn; the
// deadline methods are provided for net.Conn compatibility (M4 wires real
// deadline support).
type Stream struct {
	id   uint32
	sess *Session

	// receive side
	recvMu   sync.Mutex
	recvCond *sync.Cond
	recvBuf  bytes.Buffer
	recvFin  bool // peer sent FIN: no more data will arrive
	consumed int  // bytes read since the last window update was sent

	// send side
	sendMu     sync.Mutex
	sendCond   *sync.Cond
	sendWindow int  // bytes we may still send before awaiting WND_UPDATE
	sendClosed bool // we sent FIN / called Close

	// shared terminal error (session death or peer RST); guarded by both conds
	errMu  sync.Mutex
	resetE error
}

func newStream(id uint32, sess *Session, window int) *Stream {
	s := &Stream{id: id, sess: sess, sendWindow: window}
	s.recvCond = sync.NewCond(&s.recvMu)
	s.sendCond = sync.NewCond(&s.sendMu)
	return s
}

// ID returns the stream identifier.
func (s *Stream) ID() uint32 { return s.id }

func (s *Stream) termErr() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.resetE
}

// Read reads decrypted application bytes from the stream. It blocks until data
// is available, the peer half-closes (io.EOF), or the stream/session fails.
func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.recvMu.Lock()
	for s.recvBuf.Len() == 0 {
		if err := s.termErr(); err != nil {
			s.recvMu.Unlock()
			return 0, err
		}
		if s.recvFin {
			s.recvMu.Unlock()
			return 0, io.EOF
		}
		s.recvCond.Wait()
	}
	n, _ := s.recvBuf.Read(p) // bytes.Buffer.Read never errors when Len>0
	s.consumed += n
	// Return flow-control credit once we have consumed a meaningful chunk, so
	// the peer can keep sending without a stall, but we avoid a WND_UPDATE per
	// Read.
	var credit int
	if s.consumed*2 >= s.sess.cfg.InitialWindow {
		credit = s.consumed
		s.consumed = 0
	}
	s.recvMu.Unlock()

	if credit > 0 {
		// Best-effort: if the session is dying this will error and be ignored;
		// the next Read will surface the terminal error.
		_ = s.sess.sendWindowUpdate(s.id, uint32(credit))
	}
	return n, nil
}

// Write writes application bytes to the stream, respecting the peer's
// advertised flow-control window and splitting into frames no larger than the
// configured max frame size. It blocks while the window is exhausted.
func (s *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		s.sendMu.Lock()
		for s.sendWindow == 0 {
			if s.sendClosed {
				s.sendMu.Unlock()
				return total, ErrStreamClosed
			}
			if err := s.termErr(); err != nil {
				s.sendMu.Unlock()
				return total, err
			}
			s.sendCond.Wait()
		}
		if s.sendClosed {
			s.sendMu.Unlock()
			return total, ErrStreamClosed
		}
		if err := s.termErr(); err != nil {
			s.sendMu.Unlock()
			return total, err
		}
		can := min(len(p), s.sendWindow, s.sess.cfg.MaxFrameSize)
		s.sendWindow -= can
		chunk := p[:can]
		p = p[can:]
		s.sendMu.Unlock()

		if err := s.sess.writeFrame(Frame{Type: FrameData, StreamID: s.id, Payload: chunk}); err != nil {
			return total, err
		}
		total += can
	}
	return total, nil
}

// Close half-closes the write side by sending FIN. Reads may continue to drain
// until the peer also closes. It is safe to call multiple times.
func (s *Stream) Close() error {
	s.sendMu.Lock()
	if s.sendClosed {
		s.sendMu.Unlock()
		return nil
	}
	s.sendClosed = true
	s.sendCond.Broadcast()
	s.sendMu.Unlock()

	err := s.sess.writeFrame(Frame{Type: FrameFin, StreamID: s.id})
	s.sess.maybeRemove(s)
	return err
}

// reset abortively tears down the stream, sending RST to the peer.
func (s *Stream) reset() error {
	s.setTerm(ErrStreamReset)
	err := s.sess.writeFrame(Frame{Type: FrameRst, StreamID: s.id})
	s.sess.removeStream(s.id)
	return err
}

// --- internal callbacks driven by the session receive loop ---

// pushData appends peer bytes to the receive buffer. It enforces the advertised
// receive window: a peer that overruns it is violating flow control.
func (s *Stream) pushData(b []byte) (overflow bool) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if s.recvFin || s.termErr() != nil {
		return false // ignore late data on a finished stream
	}
	if s.recvBuf.Len()+len(b) > s.sess.cfg.InitialWindow {
		return true // flow-control violation; caller resets the stream
	}
	s.recvBuf.Write(b)
	s.recvCond.Signal()
	return false
}

// remoteFin records that the peer will send no more data.
func (s *Stream) remoteFin() {
	s.recvMu.Lock()
	s.recvFin = true
	s.recvCond.Broadcast()
	s.recvMu.Unlock()
}

// grantWindow increases the send window and wakes a blocked Write.
func (s *Stream) grantWindow(delta uint32) {
	s.sendMu.Lock()
	s.sendWindow += int(delta)
	s.sendCond.Broadcast()
	s.sendMu.Unlock()
}

// setTerm sets the terminal error and wakes all blocked readers/writers.
func (s *Stream) setTerm(err error) {
	s.errMu.Lock()
	if s.resetE == nil {
		s.resetE = err
	}
	s.errMu.Unlock()

	s.recvMu.Lock()
	s.recvCond.Broadcast()
	s.recvMu.Unlock()
	s.sendMu.Lock()
	s.sendCond.Broadcast()
	s.sendMu.Unlock()
}

// --- net.Conn deadline stubs (filled in M4) ---

// SetDeadline is a stub for net.Conn compatibility; wired in M4.
func (s *Stream) SetDeadline(time.Time) error { return nil }

// SetReadDeadline is a stub for net.Conn compatibility; wired in M4.
func (s *Stream) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline is a stub for net.Conn compatibility; wired in M4.
func (s *Stream) SetWriteDeadline(time.Time) error { return nil }
