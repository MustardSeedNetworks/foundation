// SPDX-License-Identifier: BUSL-1.1

package httpserver_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/httpserver"
)

// handshake measures a full TLS handshake against a listener, with and
// without the redirect wrapper in front of it. The wrapper reads one byte
// before handing the connection on; this is the evidence that the cost of
// keeping a browser off a connection-refused page is not paid by every TLS
// client.
func handshake(b *testing.B, wrap bool) {
	b.Helper()

	certPEM, keyPEM, genErr := benchPEM()
	if genErr != nil {
		b.Fatalf("generate certificate: %v", genErr)
	}
	cert, certErr := tls.X509KeyPair(certPEM, keyPEM)
	if certErr != nil {
		b.Fatalf("X509KeyPair: %v", certErr)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		b.Fatal("generated certificate is not a usable trust anchor")
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	var lc net.ListenConfig
	raw, listenErr := lc.Listen(b.Context(), "tcp", "127.0.0.1:0")
	if listenErr != nil {
		b.Fatalf("listen: %v", listenErr)
	}
	inner := raw
	if wrap {
		inner = httpserver.PlaintextRedirect(raw, httpserver.RedirectOptions{})
	}
	ln := tls.NewListener(inner, serverTLS)
	b.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.HandshakeContext(context.Background())
				}
				_ = conn.Close()
			}()
		}
	}()

	addr := "localhost:" + portString(raw.Addr().String())
	clientTLS := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13}

	b.ResetTimer()
	for range b.N {
		dialer := &tls.Dialer{Config: clientTLS}
		conn, dialErr := dialer.DialContext(b.Context(), "tcp", addr)
		if dialErr != nil {
			b.Fatalf("dial: %v", dialErr)
		}
		_ = conn.Close()
	}
}

// benchPEM writes a certificate to a temporary directory and returns its PEM
// bytes, so the benchmark's client can verify rather than skip verification.
func benchPEM() (certPEM, keyPEM []byte, err error) {
	dir, dirErr := os.MkdirTemp("", "httpserver-bench")
	if dirErr != nil {
		return nil, nil, dirErr
	}
	certPath := filepath.Join(dir, httpserver.DefaultCertFileName)
	keyPath := filepath.Join(dir, httpserver.DefaultKeyFileName)
	if _, ensureErr := httpserver.EnsureCertificate(certPath, keyPath, httpserver.CertOptions{DNSNames: []string{"localhost"}}); ensureErr != nil {
		return nil, nil, ensureErr
	}
	if certPEM, err = os.ReadFile(certPath); err != nil {
		return nil, nil, err
	}
	if keyPEM, err = os.ReadFile(keyPath); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

func BenchmarkHandshakeWithoutRedirectWrapper(b *testing.B) { handshake(b, false) }
func BenchmarkHandshakeWithRedirectWrapper(b *testing.B)    { handshake(b, true) }

// portString returns just the port from a host:port address.
func portString(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return p
}
