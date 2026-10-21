// Package transport implements Rahro's wire transports. The first and default
// transport is TLS: the tunnel rides inside a genuine TLS 1.3 session on port
// 443 so that, to passive DPI, it is indistinguishable from ordinary HTTPS.
//
// This package also implements the REALITY-style active-probing defense: the
// server reads a fixed-size authenticator right after the TLS handshake and,
// for any connection that fails it (a browser, a censor's prober, a scanner),
// transparently reverse-proxies the connection to a real decoy site. Only a
// client that proves knowledge of the server's X25519 public key is treated as
// a Rahro client.
//
// Staging note: M3 terminates TLS and detects Rahro-vs-probe immediately after
// the handshake, falling back at the application layer to the decoy. Full
// REALITY (embedding the authenticator in the TLS ClientHello key_share and
// forwarding the raw TCP stream so the probe sees the decoy's own certificate),
// plus uTLS browser-fingerprint mimicry, are the M5 hardening step. The layer
// boundaries here are designed so that M5 can replace the detection mechanism
// without changing the client/server/mux code above it.
package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateSelfSignedCert creates an ECDSA P-256 self-signed certificate valid
// for the given hostnames/IPs. It is used as a placeholder server certificate
// until M5 swaps in a real or REALITY-borrowed certificate. The returned
// tls.Certificate is ready to drop into a tls.Config.
func GenerateSelfSignedCert(hosts ...string) (tls.Certificate, error) {
	if len(hosts) == 0 {
		return tls.Certificate{}, fmt.Errorf("at least one host is required")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}
