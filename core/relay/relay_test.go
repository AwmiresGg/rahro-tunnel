package relay

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestAddrRoundTrip(t *testing.T) {
	cases := []string{
		"1.2.3.4:443",
		"[2001:db8::1]:8443",
		"www.example.com:443",
		"localhost:80",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteAddr(&buf, in); err != nil {
				t.Fatal(err)
			}
			got, err := ReadAddr(&buf)
			if err != nil {
				t.Fatal(err)
			}
			// Normalize both through SplitHostPort for comparison.
			wantH, wantP, _ := net.SplitHostPort(in)
			gotH, gotP, _ := net.SplitHostPort(got)
			if net.ParseIP(wantH) != nil {
				if !net.ParseIP(wantH).Equal(net.ParseIP(gotH)) || wantP != gotP {
					t.Fatalf("got %q want %q", got, in)
				}
			} else if gotH != wantH || gotP != wantP {
				t.Fatalf("got %q want %q", got, in)
			}
		})
	}
}

func TestReadAddrBadType(t *testing.T) {
	if _, err := ReadAddr(bytes.NewReader([]byte{9, 1, 2})); err == nil {
		t.Fatal("expected error on unknown atyp")
	}
}

func TestPipe(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	// Pipe a2<->b1; write into a1, read from b2.
	go Pipe(a2, b1)

	msg := []byte("relayed bytes")
	go func() { a1.Write(msg); a1.Close() }()

	got, err := io.ReadAll(b2)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q want %q", got, msg)
	}
}
