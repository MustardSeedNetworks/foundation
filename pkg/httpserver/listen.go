// SPDX-License-Identifier: BUSL-1.1

package httpserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
)

// DefaultCertFileName and DefaultKeyFileName are the names [Listen] uses
// inside Config.CertDir when the operator configured no certificate.
const (
	DefaultCertFileName = "server.crt"
	DefaultKeyFileName  = "server.key"
)

// Config describes the one listener the products bind.
type Config struct {
	// Addr is the address to listen on, "host:port".
	Addr string

	// Explicit marks Addr as operator-supplied. An operator who names a port
	// is asking for that port, so the canonical-port fallback does not run and
	// a collision is reported instead of hidden. Leave it false for the
	// product's own default port.
	Explicit bool

	// MinVersion is the minimum TLS version. Zero means TLS 1.3, which is what
	// seed, stem and niac already require; [tls.VersionTLS12] is the floor the
	// fleet allows and anything below it is refused.
	MinVersion uint16

	// CertFile and KeyFile are an operator's certificate. When either is
	// empty, [Listen] uses CertDir and generates a self-signed pair there.
	CertFile string
	KeyFile  string

	// CertDir holds the generated self-signed pair. Empty means the working
	// directory's "certs".
	CertDir string

	// Cert describes the certificate to generate when none is configured.
	Cert CertOptions

	// Logger records the fallback warning and plaintext redirects.
	Logger *slog.Logger
}

// Listen binds the product's HTTPS listener: the canonical-port fallback, the
// TLS configuration, the self-signed default, and the same-port plaintext
// redirect, in one call.
//
// The returned listener already serves TLS, so the caller passes it to
// [net/http.Server.Serve] rather than ServeTLS, and reads the port it actually
// got from Addr — the fallback windows of the four products overlap, so the
// bound port is the only honest source for a log line or a /__version answer.
//
// A product that deliberately serves plaintext (trellis on loopback, until an
// operator credential exists) calls [Bind] instead and wraps it itself. This
// call is the TLS one; it does not take a "no TLS" mode.
func Listen(ctx context.Context, cfg Config) (net.Listener, error) {
	tlsConfig, tlsErr := cfg.tlsConfig()
	if tlsErr != nil {
		return nil, tlsErr
	}

	bindFunc := Bind
	if cfg.Explicit {
		bindFunc = BindExact
	}
	raw, bindErr := bindFunc(ctx, cfg.Logger, cfg.Addr)
	if bindErr != nil {
		return nil, bindErr
	}

	redirecting := PlaintextRedirect(raw, RedirectOptions{
		Host:   raw.Addr().String(),
		Logger: cfg.Logger,
	})
	return tls.NewListener(redirecting, tlsConfig), nil
}

func (cfg Config) tlsConfig() (*tls.Config, error) {
	minVersion := cfg.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS13
	}
	if minVersion < tls.VersionTLS12 {
		return nil, fmt.Errorf("minimum TLS version %#04x is below the fleet floor of TLS 1.2", minVersion)
	}

	cert, certErr := cfg.certificate()
	if certErr != nil {
		return nil, certErr
	}
	// ServeTLS would add these itself; Serve on this pre-wrapped listener
	// cannot, so without them every client falls back to HTTP/1.1.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

func (cfg Config) certificate() (tls.Certificate, error) {
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load certificate %s: %w", cfg.CertFile, err)
		}
		return cert, nil
	}

	dir := cfg.CertDir
	if dir == "" {
		dir = "certs"
	}
	return EnsureCertificate(filepath.Join(dir, DefaultCertFileName), filepath.Join(dir, DefaultKeyFileName), cfg.Cert)
}
