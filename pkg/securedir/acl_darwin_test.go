// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package securedir_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/securedir"
)

// plantACL adds an extended ACL entry with the system chmod, the way a user or
// an installer's leftover would have.
func plantACL(t *testing.T, path, entry string) {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "/bin/chmod", "+a", entry, path).CombinedOutput()
	if err != nil {
		t.Skipf("cannot set an ACL here: %v: %s", err, out)
	}
}

func TestExtendedACLOnTheDirectoryIsRefusedAndStrippedByEnsure(t *testing.T) {
	dir := filepath.Join(tempDir(t), "data")
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := securedir.Verify(dir, securedir.Options{}); err != nil {
		t.Fatalf("Verify before: %v", err)
	}
	plantACL(t, dir, "everyone allow write,delete,add_file,add_subdirectory")

	if err := securedir.Verify(dir, securedir.Options{}); !errors.Is(err, securedir.ErrUnsafeAccess) {
		t.Fatalf("Verify with a planted ACL = %v; want ErrUnsafeAccess", err)
	}
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := securedir.Verify(dir, securedir.Options{}); err != nil {
		t.Errorf("Verify after Ensure stripped the ACL: %v", err)
	}
}

func TestExtendedACLOnAFileInTheTreeIsRefused(t *testing.T) {
	dir := filepath.Join(tempDir(t), "data")
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	plantACL(t, file, "everyone allow write")

	if err := securedir.Verify(dir, securedir.Options{}); !errors.Is(err, securedir.ErrUnsafeAccess) {
		t.Errorf("Verify = %v; want ErrUnsafeAccess", err)
	}
	if err := securedir.Ensure(dir, securedir.Options{}); !errors.Is(err, securedir.ErrUnsafeAccess) {
		t.Errorf("Ensure = %v; want ErrUnsafeAccess", err)
	}
}

func TestExtendedACLOnAnAncestorIsRefused(t *testing.T) {
	base := tempDir(t)
	dir := filepath.Join(base, "mid", "data")
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	plantACL(t, filepath.Join(base, "mid"), "everyone allow delete_child")

	if err := securedir.Verify(dir, securedir.Options{}); !errors.Is(err, securedir.ErrUnsafeAccess) {
		t.Errorf("Verify = %v; want ErrUnsafeAccess", err)
	}
}

// An ACL grant on the directory that holds a link lets that principal retarget
// it. The directory is checked before the link is looked at, so this is refused
// as unsafe access, not as a link (which is what the unprivileged owner of the
// link would otherwise get).
func TestCanonicalRefusesALinkInADirectoryWithAnACLGrant(t *testing.T) {
	base := tempDir(t)
	link := plantedLink(t, base)
	plantACL(t, base, "everyone allow delete_child")

	_, err := securedir.Canonical(filepath.Join(link, "mid", "data"), securedir.Options{})
	if !errors.Is(err, securedir.ErrUnsafeAccess) {
		t.Fatalf("Canonical = %v; want ErrUnsafeAccess", err)
	}
}
