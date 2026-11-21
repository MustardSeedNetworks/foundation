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
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/MustardSeedNetworks/foundation/pkg/securedir"
)

// certValidity is how long a generated self-signed certificate lasts. One year
// matches what every product already issued; a developer certificate that
// outlives the machine is not a feature.
const certValidity = 365 * 24 * time.Hour

// CertOptions describes the self-signed certificate [EnsureCertificate]
// generates when no operator certificate is configured.
type CertOptions struct {
	// CommonName is the subject CN. Empty means "localhost".
	CommonName string

	// DNSNames are the names the certificate must cover, beyond the loopback
	// IP SANs that are always present. Empty means "localhost".
	DNSNames []string

	// Dir tunes how the directories holding the certificate and key are
	// secured. Services that run as a dedicated account add it to
	// Dir.ExtraTrustedSIDs so replacing the directory's access control does
	// not lock that account out; Dir.Files is not used here.
	Dir securedir.Options
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
// An existing pair is trusted only if it comes from directories and files that
// pass [securedir.Verify] (trusted owner, no links, nothing writable by an
// untrusted principal), read through [securedir.OpenFile] and parsed from the
// bytes that were read. A pair that fails that is not loaded: it is replaced
// with a freshly generated one, and the log says why. A directory that cannot
// be taken over (a link, an untrusted owner, untrusted content) is an error
// instead, since replacing the pair there would not make it safe.
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
	dirOpts, optsErr := certDirOptions(opts.Dir)
	if optsErr != nil {
		return tls.Certificate{}, optsErr
	}
	keyOpts := dirOpts
	keyOpts.ExcludeAdministrators = true

	// securedir never follows a link, so the paths are resolved once here; a
	// link an unprivileged user planted in them is an error, not a pair to use.
	certReal, resolveErr := resolvePath(certPath, dirOpts)
	if resolveErr != nil {
		return tls.Certificate{}, resolveErr
	}
	keyReal, resolveErr := resolvePath(keyPath, dirOpts)
	if resolveErr != nil {
		return tls.Certificate{}, resolveErr
	}

	existing, reason := loadTrustedPair(certReal, keyReal, dirOpts)
	if reason == "" {
		if reason = certificateProblem(existing, opts); reason == "" {
			return existing, nil
		}
	}

	certPEM, keyPEM, genErr := selfSignedPEM(opts)
	if genErr != nil {
		return tls.Certificate{}, genErr
	}
	for _, dir := range uniqueDirs(certReal, keyReal) {
		if ensureErr := securedir.Ensure(dir, dirOpts); ensureErr != nil {
			return tls.Certificate{}, fmt.Errorf("secure certificate directory %s: %w", dir, ensureErr)
		}
	}
	if writeErr := securedir.WriteFile(certReal, certPEM, dirOpts); writeErr != nil {
		return tls.Certificate{}, fmt.Errorf("write certificate %s: %w", certPath, writeErr)
	}
	if writeErr := securedir.WriteFile(keyReal, keyPEM, keyOpts); writeErr != nil {
		return tls.Certificate{}, fmt.Errorf("write private key %s: %w", keyPath, writeErr)
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

// resolvePath returns path with its directory resolved by securedir.Canonical.
func resolvePath(path string, opts securedir.Options) (string, error) {
	dir, err := securedir.Canonical(filepath.Dir(path), opts)
	if err != nil {
		return "", fmt.Errorf("resolve directory for %s: %w", path, err)
	}
	return filepath.Join(dir, filepath.Base(path)), nil
}

// loadTrustedPair loads an existing pair only from directories and files that
// pass securedir.Verify, reading both through securedir.OpenFile so a link is
// never followed, and parsing the bytes it read. A pair that is missing,
// unreadable or fails verification is not trusted: the reason is returned and
// the caller regenerates (securedir.Ensure then refuses a directory it cannot
// take over, which is an error rather than a pair to load). An empty reason
// means cert is the loaded pair.
func loadTrustedPair(certPath, keyPath string, opts securedir.Options) (cert tls.Certificate, reason string) {
	for _, dir := range uniqueDirs(certPath, keyPath) {
		verify := opts
		for _, path := range []string{certPath, keyPath} {
			if filepath.Dir(path) == dir {
				verify.Files = append(verify.Files, filepath.Base(path))
			}
		}
		if err := securedir.Verify(dir, verify); err != nil {
			return tls.Certificate{}, untrustedReason(err)
		}
	}
	certPEM, err := readTrusted(certPath, opts)
	if err != nil {
		return tls.Certificate{}, untrustedReason(err)
	}
	keyPEM, err := readTrusted(keyPath, opts)
	if err != nil {
		return tls.Certificate{}, untrustedReason(err)
	}
	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "unreadable: " + err.Error()
	}
	return cert, ""
}

func untrustedReason(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "missing"
	}
	return "untrusted: " + err.Error()
}

func readTrusted(path string, opts securedir.Options) ([]byte, error) {
	file, err := securedir.OpenFile(path, os.O_RDONLY, opts)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func uniqueDirs(paths ...string) []string {
	var dirs []string
	for _, path := range paths {
		if dir := filepath.Dir(path); !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
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
