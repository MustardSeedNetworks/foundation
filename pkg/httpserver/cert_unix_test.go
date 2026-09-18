// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package httpserver_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/httpserver"
)

// The private key must not be world-readable: these run on shared dev boxes
// and lab containers. The Windows half of the same promise is asserted against
// the file's DACL in cert_windows_test.go, because Windows has no mode bits.
func TestEnsureCertificateWritesAnOwnerOnlyKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	if _, err := httpserver.EnsureCertificate(filepath.Join(dir, "server.crt"), keyPath, httpserver.CertOptions{}); err != nil {
		t.Fatalf("EnsureCertificate: %v", err)
	}

	info, statErr := os.Stat(keyPath)
	if statErr != nil {
		t.Fatalf("stat key: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode = %#o; want 0600", perm)
	}
}
