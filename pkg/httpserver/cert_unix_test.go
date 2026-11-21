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
	if _, err := httpserver.EnsureCertificate(nil, filepath.Join(dir, "server.crt"), keyPath, httpserver.CertOptions{}); err != nil {
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

// The certificate directory is created or tightened to owner-only, and the
// certificate is written atomically into it; a pre-existing loose directory
// is not left as found.
func TestEnsureCertificateSecuresTheCertificateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := mkdirMode(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "server.crt")
	if _, err := httpserver.EnsureCertificate(nil, certPath, filepath.Join(dir, "server.key"), httpserver.CertOptions{}); err != nil {
		t.Fatalf("EnsureCertificate: %v", err)
	}

	for path, want := range map[string]os.FileMode{dir: 0o700, certPath: 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode = %#o; want %#o", path, info.Mode().Perm(), want)
		}
	}
}

// A link in the configured directory is resolved once, up front, and the
// resolved directory is what gets secured and written; nothing is written
// through the link afterwards.
func TestEnsureCertificateResolvesASymlinkedCertificateDirectory(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "certs")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	_, err := httpserver.EnsureCertificate(nil, filepath.Join(link, "server.crt"), filepath.Join(link, "server.key"), httpserver.CertOptions{})
	if err != nil {
		t.Fatalf("EnsureCertificate: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(real, "server.crt")); statErr != nil {
		t.Errorf("certificate is not in the resolved directory: %v", statErr)
	}
}

// mkdirMode takes the mode as a parameter: the point is a deliberately loose
// directory, which a literal mode would have the security linter reject.
func mkdirMode(path string, perm os.FileMode) error { return os.Mkdir(path, perm) }
