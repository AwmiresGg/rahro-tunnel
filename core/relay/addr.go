// Package relay carries application traffic between a local inbound and the
// remote egress over a Rahro mux stream. It defines the destination-address
// header written at the start of each stream and a bidirectional pipe helper.
package relay

import (
	"fmt"
	"io"
	"net"
	"strconv"
)

// Address types, matching SOCKS5 ATYP so the header is self-describing (no
// outer length prefix is needed — the type byte determines how much follows).
const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

// WriteAddr writes a destination "host:port" as a self-describing address
// header. The server reads this as the first bytes of a stream to learn where
// to egress.
func WriteAddr(w io.Writer, hostport string) error {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return fmt.Errorf("relay: split %q: %w", hostport, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("relay: bad port %q", portStr)
	}

	var buf []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append([]byte{atypIPv4}, v4...)
		} else {
			buf = append([]byte{atypIPv6}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("relay: domain length %d out of range", len(host))
		}
		buf = append([]byte{atypDomain, byte(len(host))}, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("relay: write addr: %w", err)
	}
	return nil
}

// ReadAddr reads an address header written by WriteAddr and returns a
// dial-ready "host:port" string.
func ReadAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", fmt.Errorf("relay: read atyp: %w", err)
	}

	var host string
	switch atyp[0] {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("relay: read ipv4: %w", err)
		}
		host = net.IP(b[:]).String()
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("relay: read ipv6: %w", err)
		}
		host = net.IP(b[:]).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", fmt.Errorf("relay: read domain len: %w", err)
		}
		d := make([]byte, l[0])
		if _, err := io.ReadFull(r, d); err != nil {
			return "", fmt.Errorf("relay: read domain: %w", err)
		}
		host = string(d)
	default:
		return "", fmt.Errorf("relay: unknown atyp %d", atyp[0])
	}

	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", fmt.Errorf("relay: read port: %w", err)
	}
	port := int(p[0])<<8 | int(p[1])
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
