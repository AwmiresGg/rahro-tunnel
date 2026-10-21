package proto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// --- frame codec tests ---

func TestFrameRoundTrip(t *testing.T) {
	cases := []Frame{
		{Type: FrameSYN, StreamID: 1},
		{Type: FrameData, StreamID: 3, Payload: []byte("hello world")},
		{Type: FrameWndUpdate, StreamID: 5, Payload: []byte{0, 0, 1, 0}},
		{Type: FrameFin, StreamID: 7},
		{Type: FrameRst, StreamID: 9},
		{Type: FramePing},
		{Type: FrameData, StreamID: 11, Payload: []byte("padded"), PadLen: 32},
	}
	for _, in := range cases {
		t.Run(in.Type.String(), func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, in); err != nil {
				t.Fatal(err)
			}
			got, err := ReadFrame(&buf)
			if err != nil {
				t.Fatal(err)
			}
			if got.Type != in.Type || got.StreamID != in.StreamID {
				t.Fatalf("header mismatch: got %+v want %+v", got, in)
			}
			if !bytes.Equal(got.Payload, in.Payload) {
				t.Fatalf("payload mismatch: got %q want %q", got.Payload, in.Payload)
			}
			if buf.Len() != 0 {
				t.Fatalf("padding not fully consumed, %d bytes left", buf.Len())
			}
		})
	}
}

func TestReadFrameTruncated(t *testing.T) {
	// Header claims a 10-byte payload but only 3 bytes follow.
	var buf bytes.Buffer
	WriteFrame(&buf, Frame{Type: FrameData, StreamID: 1, Payload: []byte("0123456789")})
	truncated := buf.Bytes()[:HeaderSize+3]
	if _, err := ReadFrame(bytes.NewReader(truncated)); err == nil {
		t.Fatal("expected error on truncated payload")
	}
}

func TestReadFrameEOF(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on empty reader, got %v", err)
	}
}

// --- session / mux tests ---

// pair wires a client and server session over an in-memory synchronous pipe.
func pair(t *testing.T, cfg *Config) (client, server *Session) {
	t.Helper()
	c, s := net.Pipe()
	client = Client(c, cfg)
	server = Server(s, cfg)
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

// withTimeout fails the test if fn does not finish in time (catches deadlocks).
func withTimeout(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("timed out (possible deadlock)")
	}
}

func TestStreamBidirectionalEcho(t *testing.T) {
	client, server := pair(t, nil)

	// Server: accept one stream and echo everything back.
	go func() {
		st, err := server.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(st, st) // echo until client half-closes
		st.Close()
	}()

	withTimeout(t, 5*time.Second, func() {
		st, err := client.OpenStream()
		if err != nil {
			t.Error(err)
			return
		}
		msg := []byte("hello rahro")
		if _, err := st.Write(msg); err != nil {
			t.Error(err)
			return
		}
		st.Close() // signal EOF to the echo server's io.Copy

		got, err := io.ReadAll(st)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("echo mismatch: got %q want %q", got, msg)
		}
	})
}

func TestSYNPayloadDeliveredAsFirstBytes(t *testing.T) {
	// A SYN can carry a payload (used in M4 to carry the destination address);
	// it must arrive as the first readable bytes of the accepted stream.
	c, s := net.Pipe()
	client := Client(c, nil)
	server := Server(s, nil)
	defer client.Close()
	defer server.Close()

	// Manually send a SYN with payload by using a stream Write right after open.
	go func() {
		st, _ := client.OpenStream()
		st.Write([]byte("DEST:example.com:443"))
		// keep open
	}()

	withTimeout(t, 5*time.Second, func() {
		st, err := server.AcceptStream()
		if err != nil {
			t.Error(err)
			return
		}
		buf := make([]byte, 64)
		n, err := st.Read(buf)
		if err != nil {
			t.Error(err)
			return
		}
		if string(buf[:n]) != "DEST:example.com:443" {
			t.Errorf("got %q", buf[:n])
		}
	})
}

func TestConcurrentStreams(t *testing.T) {
	client, server := pair(t, nil)

	const n = 20
	// Server echoes each accepted stream.
	go func() {
		for {
			st, err := server.AcceptStream()
			if err != nil {
				return
			}
			go func(st *Stream) {
				io.Copy(st, st)
				st.Close()
			}(st)
		}
	}()

	withTimeout(t, 10*time.Second, func() {
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				st, err := client.OpenStream()
				if err != nil {
					t.Error(err)
					return
				}
				payload := bytes.Repeat([]byte{byte(i)}, 1000)
				st.Write(payload)
				st.Close()
				got, err := io.ReadAll(st)
				if err != nil {
					t.Error(err)
					return
				}
				if !bytes.Equal(got, payload) {
					t.Errorf("stream %d echo mismatch", i)
				}
			}(i)
		}
		wg.Wait()
	})
}

// TestFlowControlLargeTransfer pushes far more than one window through a stream
// with a deliberately tiny window, exercising WND_UPDATE backpressure.
func TestFlowControlLargeTransfer(t *testing.T) {
	cfg := &Config{MaxFrameSize: 1024, InitialWindow: 4096}
	client, server := pair(t, cfg)

	const total = 1 << 20 // 1 MiB, 256x the window
	data := make([]byte, total)
	rand.Read(data)
	resultCh := make(chan []byte, 1)

	go func() {
		st, err := server.AcceptStream()
		if err != nil {
			resultCh <- nil
			return
		}
		got, _ := io.ReadAll(st)
		st.Close()
		resultCh <- got
	}()

	withTimeout(t, 20*time.Second, func() {
		st, err := client.OpenStream()
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := st.Write(data); err != nil {
			t.Error(err)
			return
		}
		st.Close()
		got := <-resultCh
		if len(got) != total {
			t.Errorf("received %d bytes, want %d", len(got), total)
			return
		}
		if !bytes.Equal(got, data) {
			t.Error("large transfer corrupted under flow control")
		}
	})
}

func TestHalfCloseEOF(t *testing.T) {
	client, server := pair(t, nil)
	go func() {
		st, err := server.AcceptStream()
		if err != nil {
			return
		}
		st.Write([]byte("one message"))
		st.Close() // half-close: client should read data then EOF
	}()

	withTimeout(t, 5*time.Second, func() {
		st, err := client.OpenStream()
		if err != nil {
			t.Error(err)
			return
		}
		got, err := io.ReadAll(st) // ReadAll stops at EOF
		if err != nil {
			t.Error(err)
			return
		}
		if string(got) != "one message" {
			t.Errorf("got %q", got)
		}
	})
}

func TestSessionCloseWakesBlockedRead(t *testing.T) {
	client, server := pair(t, nil)
	_ = server

	withTimeout(t, 5*time.Second, func() {
		st, err := client.OpenStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Close the session while a Read is blocked; the Read must return.
		go func() {
			time.Sleep(50 * time.Millisecond)
			client.Close()
		}()
		buf := make([]byte, 16)
		if _, err := st.Read(buf); err == nil {
			t.Error("blocked Read should return an error after session close")
		}
	})
}

func TestOpenStreamAfterCloseFails(t *testing.T) {
	client, _ := pair(t, nil)
	client.Close()
	if _, err := client.OpenStream(); err == nil {
		t.Fatal("OpenStream after Close should fail")
	}
}
