// Package proto implements the Rahro wire protocol: a compact frame format and
// a stream multiplexer with per-stream flow control. Many logical streams ride
// over one authenticated transport flow, which reduces the number of TLS
// sessions a censor can fingerprint and lowers latency for new app
// connections.
//
// This package is transport-agnostic: it operates over any
// io.ReadWriteCloser. The encryption/authentication lives below it (the TLS
// transport + handshake authenticator, M3); the SOCKS/egress logic lives above
// it (M4).
package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// FrameType identifies the purpose of a frame.
type FrameType uint8

const (
	// FrameSYN opens a new stream (payload may carry a destination address).
	FrameSYN FrameType = 1
	// FrameData carries stream payload bytes.
	FrameData FrameType = 2
	// FrameWndUpdate replenishes the sender's flow-control window; payload is a
	// 4-byte big-endian increment (bytes the receiver has consumed).
	FrameWndUpdate FrameType = 3
	// FrameFin signals the sender will send no more data on the stream.
	FrameFin FrameType = 4
	// FrameRst abortively closes a stream.
	FrameRst FrameType = 5
	// FramePing is a keepalive / timing-cover frame (not tied to a stream).
	FramePing FrameType = 6
)

func (t FrameType) String() string {
	switch t {
	case FrameSYN:
		return "SYN"
	case FrameData:
		return "DATA"
	case FrameWndUpdate:
		return "WND_UPDATE"
	case FrameFin:
		return "FIN"
	case FrameRst:
		return "RST"
	case FramePing:
		return "PING"
	default:
		return fmt.Sprintf("FrameType(%d)", uint8(t))
	}
}

// HeaderSize is the fixed frame header length in bytes.
//
//	type(1) | flags(1) | streamID(4) | payloadLen(2) | padLen(2)
const HeaderSize = 10

// MaxPayloadSize is the largest payload a single frame can carry (uint16).
const MaxPayloadSize = 65535

// MaxPaddingSize is the largest padding a single frame can carry (uint16).
const MaxPaddingSize = 65535

// Frame flag bits.
const (
	flagNone uint8 = 0
)

// Frame is a decoded Rahro frame. Padding is write-only cover: it is emitted on
// the wire (to shape lengths, M5) but discarded on read, so Payload holds only
// meaningful bytes.
type Frame struct {
	Type     FrameType
	Flags    uint8
	StreamID uint32
	Payload  []byte
	// PadLen is the number of random padding bytes to append after the payload
	// when writing. It is not populated on read.
	PadLen uint16
}

// WriteFrame encodes f to w. Padding bytes are written by the caller-provided
// padding source via writePadding; here we require the caller to pass explicit
// padding through PadLen and we emit zero bytes (M5 swaps in random padding).
func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxPayloadSize {
		return fmt.Errorf("frame payload %d exceeds max %d", len(f.Payload), MaxPayloadSize)
	}
	var hdr [HeaderSize]byte
	hdr[0] = byte(f.Type)
	hdr[1] = f.Flags
	binary.BigEndian.PutUint32(hdr[2:6], f.StreamID)
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(f.Payload)))
	binary.BigEndian.PutUint16(hdr[8:10], f.PadLen)

	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if len(f.Payload) > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return fmt.Errorf("write frame payload: %w", err)
		}
	}
	if f.PadLen > 0 {
		// Padding content is irrelevant to the decoder; zero bytes here. M5
		// replaces this with CSPRNG bytes as part of traffic shaping.
		pad := make([]byte, f.PadLen)
		if _, err := w.Write(pad); err != nil {
			return fmt.Errorf("write frame padding: %w", err)
		}
	}
	return nil
}

// ReadFrame decodes a single frame from r. Padding is read and discarded. The
// returned Frame.Payload is a freshly-allocated slice owned by the caller.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		// Propagate io.EOF / io.ErrUnexpectedEOF unwrapped so callers can detect
		// a cleanly-closed transport.
		return Frame{}, err
	}
	f := Frame{
		Type:     FrameType(hdr[0]),
		Flags:    hdr[1],
		StreamID: binary.BigEndian.Uint32(hdr[2:6]),
	}
	payloadLen := binary.BigEndian.Uint16(hdr[6:8])
	padLen := binary.BigEndian.Uint16(hdr[8:10])

	if payloadLen > 0 {
		f.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, fmt.Errorf("read frame payload: %w", err)
		}
	}
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return Frame{}, fmt.Errorf("read frame padding: %w", err)
		}
	}
	return f, nil
}
