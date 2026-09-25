// SPDX-License-Identifier: BUSL-1.1

package httpserver_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MustardSeedNetworks/foundation/pkg/httpserver"
)

func leaf(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return parsed
}

// The generated certificate must cover what the daemons actually advertise.
// niac advertises https://127.0.0.1:8445, and a certificate without loopback
// IP SANs fails that URL in every browser — which is why loopback is not
// optional here.
func TestSelfSignedCertificateCoversLoopbackAndTheRequestedNames(t *testing.T) {
	cert, err := httpserver.SelfSignedCertificate(httpserver.CertOptions{DNSNames: []string{"niac.local", "localhost"}})
	if err != nil {
		t.Fatalf("SelfSignedCertificate: %v", err)
	}

	for _, name := range []string{"niac.local", "localhost", "127.0.0.1", "::1"} {
		if verifyErr := leaf(t, cert).VerifyHostname(name); verifyErr != nil {
			t.Errorf("certificate does not cover %q: %v", name, verifyErr)
		}
	}
}

// An operator installs this certificate in a trust store, so it has to be one:
// a leaf that is not a CA cannot be an anchor and the warning never goes away.
func TestSelfSignedCertificateIsInstallableAsATrustAnchor(t *testing.T) {
	cert, err := httpserver.SelfSignedCertificate(httpserver.CertOptions{})
	if err != nil {
		t.Fatalf("SelfSignedCertificate: %v", err)
	}
	parsed := leaf(t, cert)

	if !parsed.IsCA {
		t.Error("certificate is not a CA; it cannot be installed as a trust anchor")
	}
	if parsed.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("certificate lacks KeyUsageCertSign")
	}
	if parsed.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("public key algorithm = %v; want ECDSA", parsed.PublicKeyAlgorithm)
	}
}

// A second start reuses the pair on disk: regenerating on every start would
// invalidate an operator's trust-store install each time the daemon restarts.
func TestEnsureCertificateReusesAPairThatStillCovers(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	opts := httpserver.CertOptions{DNSNames: []string{"localhost"}}

	first, firstErr := httpserver.EnsureCertificate(nil, certPath, keyPath, opts)
	if firstErr != nil {
		t.Fatalf("first EnsureCertificate: %v", firstErr)
	}
	second, secondErr := httpserver.EnsureCertificate(nil, certPath, keyPath, opts)
	if secondErr != nil {
		t.Fatalf("second EnsureCertificate: %v", secondErr)
	}

	if leaf(t, first).SerialNumber.Cmp(leaf(t, second).SerialNumber) != 0 {
		t.Error("EnsureCertificate regenerated a certificate that still covers")
	}
}

// The check is coverage, not existence. A certificate generated before a name
// was added keeps being reused and keeps failing — niac hit exactly this with
// loopback SANs.
func TestEnsureCertificateReplacesAPairThatNoLongerCovers(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	old, oldErr := httpserver.EnsureCertificate(nil, certPath, keyPath, httpserver.CertOptions{DNSNames: []string{"localhost"}})
	if oldErr != nil {
		t.Fatalf("EnsureCertificate: %v", oldErr)
	}

	replaced, replaceErr := httpserver.EnsureCertificate(nil, certPath, keyPath, httpserver.CertOptions{DNSNames: []string{"localhost", "seed.local"}})
	if replaceErr != nil {
		t.Fatalf("EnsureCertificate with a new name: %v", replaceErr)
	}
	if leaf(t, old).SerialNumber.Cmp(leaf(t, replaced).SerialNumber) == 0 {
		t.Fatal("EnsureCertificate reused a certificate that does not cover the new name")
	}
	if verifyErr := leaf(t, replaced).VerifyHostname("seed.local"); verifyErr != nil {
		t.Errorf("replacement does not cover the new name: %v", verifyErr)
	}
}

// An upgrade that replaces the certificate breaks every trust store the old
// one was installed in, so each write must say why and which certificate the
// operator now has to trust; stem's STM-23 upgrade audit found the
// replacement silent (foundation#76). Reuse must stay quiet.
func TestEnsureCertificateLogsEveryPairItWrites(t *testing.T) {
	opts := httpserver.CertOptions{DNSNames: []string{"localhost", "stem.local"}}
	cases := []struct {
		name       string
		existing   func(t *testing.T, certPath, keyPath string)
		wantLevel  string
		wantReason string
	}{
		{
			name:       "missing",
			existing:   func(*testing.T, string, string) {},
			wantLevel:  "INFO",
			wantReason: "missing",
		},
		{
			name: "unreadable",
			existing: func(t *testing.T, certPath, keyPath string) {
				t.Helper()
				writeFile(t, certPath, []byte("not a certificate"))
				writeFile(t, keyPath, []byte("not a key"))
			},
			wantLevel:  "WARN",
			wantReason: "unreadable",
		},
		{
			name: "expired",
			existing: func(t *testing.T, certPath, keyPath string) {
				t.Helper()
				writeExpiredPair(t, certPath, keyPath, opts.DNSNames)
			},
			wantLevel:  "WARN",
			wantReason: "expired",
		},
		{
			name: "does not cover a name",
			existing: func(t *testing.T, certPath, keyPath string) {
				t.Helper()
				if _, err := httpserver.EnsureCertificate(nil, certPath, keyPath, httpserver.CertOptions{}); err != nil {
					t.Fatalf("EnsureCertificate: %v", err)
				}
			},
			wantLevel:  "WARN",
			wantReason: "does not cover stem.local",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath := filepath.Join(dir, "server.crt")
			keyPath := filepath.Join(dir, "server.key")
			tc.existing(t, certPath, keyPath)

			var buf bytes.Buffer
			cert, err := httpserver.EnsureCertificate(slog.New(slog.NewJSONHandler(&buf, nil)), certPath, keyPath, opts)
			if err != nil {
				t.Fatalf("EnsureCertificate: %v", err)
			}

			records := logRecords(t, &buf)
			if len(records) != 1 {
				t.Fatalf("logged %d records, want 1: %s", len(records), buf.String())
			}
			got := records[0]
			if got["level"] != tc.wantLevel {
				t.Errorf("level = %v, want %s", got["level"], tc.wantLevel)
			}
			if reason, _ := got["reason"].(string); !strings.HasPrefix(reason, tc.wantReason) {
				t.Errorf("reason = %q, want prefix %q", reason, tc.wantReason)
			}
			if got["cert_file"] != certPath {
				t.Errorf("cert_file = %v, want %s", got["cert_file"], certPath)
			}
			written := leaf(t, cert)
			if want := written.NotAfter.UTC().Format(time.RFC3339); got["valid_until"] != want {
				t.Errorf("valid_until = %v, want %s", got["valid_until"], want)
			}
			if want := sha256Fingerprint(written.Raw); got["sha256"] != want {
				t.Errorf("sha256 = %v, want %s", got["sha256"], want)
			}

			buf.Reset()
			if _, reuseErr := httpserver.EnsureCertificate(slog.New(slog.NewJSONHandler(&buf, nil)), certPath, keyPath, opts); reuseErr != nil {
				t.Fatalf("EnsureCertificate on the written pair: %v", reuseErr)
			}
			if buf.Len() != 0 {
				t.Errorf("reusing the pair logged %s, want nothing", buf.String())
			}
		})
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeExpiredPair writes a valid pair covering names and loopback whose
// certificate expired an hour ago, so expiry is the only thing wrong with it.
func writeExpiredPair(t *testing.T, certPath, keyPath string, names []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now.Add(-48 * time.Hour),
		NotAfter:     now.Add(-time.Hour),
		DNSNames:     names,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func logRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for line := range strings.Lines(buf.String()) {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

// sha256Fingerprint is computed independently of the package so the test
// checks the format an operator compares against openssl and /__version.
func sha256Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	digits := strings.ToUpper(hex.EncodeToString(sum[:]))
	pairs := make([]string, 0, len(sum))
	for i := 0; i < len(digits); i += 2 {
		pairs = append(pairs, digits[i:i+2])
	}
	return strings.Join(pairs, ":")
}
