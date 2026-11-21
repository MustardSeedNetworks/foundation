// SPDX-License-Identifier: BUSL-1.1

package httpserver_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/httpserver"
)

// writePair writes a valid, unexpired pair into dir with plain os.WriteFile, the
// way something other than EnsureCertificate would have planted it.
func writePair(t *testing.T, dir string) (certPath, keyPath string, cert tls.Certificate) {
	t.Helper()
	cert, err := httpserver.SelfSignedCertificate(httpserver.CertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPath, keyPath = filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err = os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, cert
}
