// SPDX-License-Identifier: BUSL-1.1

package httpserver_test

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"testing"

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

	first, firstErr := httpserver.EnsureCertificate(certPath, keyPath, opts)
	if firstErr != nil {
		t.Fatalf("first EnsureCertificate: %v", firstErr)
	}
	second, secondErr := httpserver.EnsureCertificate(certPath, keyPath, opts)
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

	old, oldErr := httpserver.EnsureCertificate(certPath, keyPath, httpserver.CertOptions{DNSNames: []string{"localhost"}})
	if oldErr != nil {
		t.Fatalf("EnsureCertificate: %v", oldErr)
	}

	replaced, replaceErr := httpserver.EnsureCertificate(certPath, keyPath, httpserver.CertOptions{DNSNames: []string{"localhost", "seed.local"}})
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
