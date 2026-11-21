// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package httpserver_test

import (
	"bytes"
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

// A link planted in the configured path is refused, not resolved: securedir
// follows only links owned by root.
func TestEnsureCertificateRefusesASymlinkedCertificateDirectory(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "certs")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(link, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	_, err := httpserver.EnsureCertificate(nil, filepath.Join(link, "server.crt"), filepath.Join(link, "server.key"), httpserver.CertOptions{})
	if err == nil {
		t.Fatal("EnsureCertificate wrote through a symlinked directory")
	}
	if _, statErr := os.Stat(filepath.Join(real, "server.crt")); statErr == nil {
		t.Error("the certificate was written through the link")
	}
}

// mkdirMode takes the mode as a parameter: the point is a deliberately loose
// directory, which a literal mode would have the security linter reject.
func mkdirMode(path string, perm os.FileMode) error { return os.Mkdir(path, perm) }

// The key is written through securedir like the certificate: a key directory
// that is a link planted by an unprivileged user is refused, and a link at the
// key's own path is replaced rather than written through.
func TestEnsureCertificateRefusesALinkedKeyDirectory(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "keys")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(link, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	_, err := httpserver.EnsureCertificate(nil, filepath.Join(base, "certs", "server.crt"), filepath.Join(link, "server.key"), httpserver.CertOptions{})
	if err == nil {
		t.Fatal("EnsureCertificate wrote a key through a linked directory")
	}
	if _, statErr := os.Stat(filepath.Join(real, "server.key")); statErr == nil {
		t.Error("the key was written through the link")
	}
}

// A link sitting at the key's own path is refused (the directory's contents
// are judged before anything is written) and nothing is written through it.
func TestEnsureCertificateRefusesALinkAtTheKeyPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "server.key")
	if err := os.Symlink(victim, keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := httpserver.EnsureCertificate(nil, filepath.Join(dir, "server.crt"), keyPath, httpserver.CertOptions{}); err == nil {
		t.Fatal("EnsureCertificate accepted a link at the key path")
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Errorf("the key was written through the link: %q", got)
	}
}

// A valid pair planted where a user can write to the directory is not the
// server's identity: it is replaced.
func TestEnsureCertificateDoesNotLoadAPairFromAnUnverifiedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := mkdirMode(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := chmodMode(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, planted := writePair(t, dir)

	got, err := httpserver.EnsureCertificate(nil, certPath, keyPath, httpserver.CertOptions{})
	if err != nil {
		t.Fatalf("EnsureCertificate: %v", err)
	}
	if bytes.Equal(got.Certificate[0], planted.Certificate[0]) {
		t.Fatal("the planted certificate was loaded as the server's identity")
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %#o; want 0700 after the take-over", info.Mode().Perm())
	}
}

// A pair reached through a link planted by an unprivileged user is not loaded
// either; the path is refused outright.
func TestEnsureCertificateDoesNotLoadAPairThroughALink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	writePair(t, real)
	link := filepath.Join(base, "certs")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(link, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	got, err := httpserver.EnsureCertificate(nil, filepath.Join(link, "server.crt"), filepath.Join(link, "server.key"), httpserver.CertOptions{})
	if err == nil {
		t.Fatalf("EnsureCertificate loaded a pair through a link: %v", got.Leaf)
	}
}

// A planted pair in a hard-linked or linked file is not loaded.
func TestEnsureCertificateDoesNotLoadAHardLinkedKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, planted := writePair(t, dir)
	if err := os.Link(keyPath, filepath.Join(t.TempDir(), "other-name")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	got, err := httpserver.EnsureCertificate(nil, certPath, keyPath, httpserver.CertOptions{})
	if err == nil && bytes.Equal(got.Certificate[0], planted.Certificate[0]) {
		t.Fatal("a key with a second name was loaded")
	}
}

func chmodMode(path string, perm os.FileMode) error { return os.Chmod(path, perm) }
