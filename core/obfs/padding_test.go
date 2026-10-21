package obfs

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/awmiresgg/rahro/core/proto"
)

// TestPaddingTransparentOverSession proves padded frames still decode and that
// a mux session with padding enabled echoes data unchanged.
func TestPaddingTransparentOverSession(t *testing.T) {
	cfg := &proto.Config{Padder: NewRandomPadder()}
	a, b := net.Pipe()
	client := proto.Client(a, cfg)
	srv := proto.Server(b, cfg)
	defer client.Close()
	defer srv.Close()

	go func() {
		st, err := srv.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(st, st)
		st.Close()
	}()

	done := make(chan error, 1)
	go func() {
		st, err := client.OpenStream()
		if err != nil {
			done <- err
			return
		}
		msg := bytes.Repeat([]byte("rahro-"), 500)
		st.Write(msg)
		st.Close()
		got, err := io.ReadAll(st)
		if err != nil {
			done <- err
			return
		}
		if !bytes.Equal(got, msg) {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

func TestRandomPadderControlFrames(t *testing.T) {
	p := NewRandomPadder()
	for i := 0; i < 1000; i++ {
		pad := p.PadLen(proto.FrameSYN, 10)
		total := 10 + int(pad)
		if total < p.CtrlMin || total > p.CtrlMax {
			t.Fatalf("control total %d outside [%d,%d]", total, p.CtrlMin, p.CtrlMax)
		}
	}
}

func TestRandomPadderDataFrames(t *testing.T) {
	p := NewRandomPadder()
	for i := 0; i < 1000; i++ {
		pad := int(p.PadLen(proto.FrameData, 1200))
		if pad < 0 || pad > p.DataMax {
			t.Fatalf("data pad %d outside [0,%d]", pad, p.DataMax)
		}
	}
}

func TestRandomPadderLargeControlPayloadNoUnderflow(t *testing.T) {
	p := NewRandomPadder()
	// Payload already larger than CtrlMax -> no padding, no underflow.
	if pad := p.PadLen(proto.FrameSYN, 10000); pad != 0 {
		t.Fatalf("expected 0 pad for oversized control payload, got %d", pad)
	}
}
