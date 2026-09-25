// SPDX-License-Identifier: BUSL-1.1

package httpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// certValidity is how long a generated self-signed certificate lasts. One year
// matches what every product already issued; a developer certificate that
// outlives the machine is not a feature.
const certValidity = 365 * 24 * time.Hour

// certFileMode and keyFileMode are the on-disk permissions. The private key is
// owner-only: a world-readable key in a shared dev box is a real leak. Windows
// has no mode bits, so keyFileMode is the unix half of that promise and
// writePrivateKey carries the other half; see cert_windows.go.
const (
	certFileMode os.FileMode = 0o644
	keyFileMode  os.FileMode = 0o600
)

// CertOptions describes the self-signed certificate [EnsureCertificate]
// generates when no operator certificate is configured.
type CertOptions struct {
	// CommonName is the subject CN. Empty means "localhost".
	CommonName string

	// DNSNames are the names the certificate must cover, beyond the loopback
	// IP SANs that are always present. Empty means "localhost".
	DNSNames []string
}

// SelfSignedCertificate generates an in-memory self-signed certificate.
//
// ECDSA P-256, not the RSA-4096 three of the four products generated: it is
// the modern default, the handshake is materially cheaper, and the key
// generation does not stall a first start on a small box. The certificate is
// its own CA so an operator can install it in a trust store (what seed's
// truststore and mkcert do with it) rather than clicking through a warning.
func SelfSignedCertificate(opts CertOptions) (tls.Certificate, error) {
	certPEM, keyPEM, err := selfSignedPEM(opts)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// EnsureCertificate returns the certificate at certPath/keyPath, generating a
// self-signed pair there when the files are missing, unreadable as a pair, or
// no longer cover what opts asks for.
//
// The coverage check is why this is not "if the file exists, use it": niac
// learned that a certificate generated before loopback IP SANs were added
// keeps being reused and keeps failing the browser. A certificate that does
// not cover the names the daemon advertises is not usable, whatever its age.
//
// Every pair it writes is logged with the reason, the expiry and the
// fingerprint. A replacement is a warning: an operator who installed the
// previous certificate in a trust store gets a browser warning until they
// install this one, and the log is the only place that can tell them why.
// A nil logger logs nothing, as with [Bind].
func EnsureCertificate(logger *slog.Logger, certPath, keyPath string, opts CertOptions) (tls.Certificate, error) {
	existing, loadErr := tls.LoadX509KeyPair(certPath, keyPath)
	reason := "missing"
	switch {
	case loadErr == nil:
		reason = certificateProblem(existing, opts)
		if reason == "" {
			return existing, nil
		}
	case !errors.Is(loadErr, fs.ErrNotExist):
		reason = "unreadable: " + loadErr.Error()
	}

	certPEM, keyPEM, genErr := selfSignedPEM(opts)
	if genErr != nil {
		return tls.Certificate{}, genErr
	}

	for _, path := range []string{certPath, keyPath} {
		if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o750); mkdirErr != nil {
			return tls.Certificate{}, fmt.Errorf("create certificate directory for %s: %w", path, mkdirErr)
		}
	}
	if writeErr := os.WriteFile(certPath, certPEM, certFileMode); writeErr != nil {
		return tls.Certificate{}, fmt.Errorf("write certificate %s: %w", certPath, writeErr)
	}
	if writeErr := writePrivateKey(keyPath, keyPEM); writeErr != nil {
		return tls.Certificate{}, writeErr
	}

	cert, pairErr := tls.X509KeyPair(certPEM, keyPEM)
	if pairErr != nil {
		return tls.Certificate{}, pairErr
	}
	if logger != nil {
		logGenerated(logger, cert, certPath, reason)
	}
	return cert, nil
}

func logGenerated(logger *slog.Logger, cert tls.Certificate, certPath, reason string) {
	leaf, parseErr := x509.ParseCertificate(cert.Certificate[0])
	if parseErr != nil {
		return
	}
	attrs := []any{
		"cert_file", certPath,
		"reason", reason,
		"valid_until", leaf.NotAfter.UTC().Format(time.RFC3339),
		"sha256", fingerprint(leaf.Raw),
	}
	if reason == "missing" {
		logger.Info("generated self-signed TLS certificate", attrs...)
		return
	}
	logger.Warn("replaced self-signed TLS certificate; re-install it wherever the previous one was trusted", attrs...)
}

// fingerprint is the SHA-256 of der as colon-separated uppercase hex pairs,
// the form browsers and `openssl x509 -fingerprint -sha256` display.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	pairs := make([]string, len(sum))
	for i, b := range sum {
		pairs[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(pairs, ":")
}

// certificateProblem reports why cert is no longer usable for opts — expired,
// or not covering a name asked for or loopback — and "" when it still is.
func certificateProblem(cert tls.Certificate, opts CertOptions) string {
	if len(cert.Certificate) == 0 {
		return "no certificate in the file"
	}
	leaf, parseErr := x509.ParseCertificate(cert.Certificate[0])
	if parseErr != nil {
		return "unparsable: " + parseErr.Error()
	}
	if time.Now().After(leaf.NotAfter) {
		return "expired"
	}
	for _, name := range names(opts) {
		if leaf.VerifyHostname(name) != nil {
			return "does not cover " + name
		}
	}
	for _, ip := range loopbackIPs() {
		if leaf.VerifyHostname(ip.String()) != nil {
			return "does not cover " + ip.String()
		}
	}
	return ""
}

func names(opts CertOptions) []string {
	if len(opts.DNSNames) == 0 {
		return []string{"localhost"}
	}
	return opts.DNSNames
}

func loopbackIPs() []net.IP {
	return []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
}

func selfSignedPEM(opts CertOptions) (certPEM, keyPEM []byte, err error) {
	key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		return nil, nil, fmt.Errorf("generate key: %w", keyErr)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, serialErr := rand.Int(rand.Reader, serialLimit)
	if serialErr != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", serialErr)
	}

	commonName := opts.CommonName
	if commonName == "" {
		commonName = "localhost"
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              names(opts),
		IPAddresses:           loopbackIPs(),
	}

	der, createErr := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if createErr != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", createErr)
	}
	keyDER, marshalErr := x509.MarshalECPrivateKey(key)
	if marshalErr != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", marshalErr)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if certPEM == nil || keyPEM == nil {
		return nil, nil, errors.New("encode certificate PEM")
	}
	return certPEM, keyPEM, nil
}
