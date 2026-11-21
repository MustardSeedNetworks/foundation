// SPDX-License-Identifier: BUSL-1.1

//go:build linux

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

func setfacl(t *testing.T, args ...string) {
	t.Helper()
	path, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl is not installed")
	}
	if out, runErr := exec.CommandContext(context.Background(), path, args...).CombinedOutput(); runErr != nil {
		t.Skipf("cannot set an ACL here: %v: %s", runErr, out)
	}
}

func TestPOSIXACLOnTheDirectoryIsRefusedAndStrippedByEnsure(t *testing.T) {
	for name, args := range map[string][]string{
		"access":  {"-m", "u:65534:rwx"},
		"default": {"-d", "-m", "u:65534:rwx"},
		"group":   {"-m", "g:65534:rwx"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(tempDir(t), "data")
			if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
				t.Fatal(err)
			}
			setfacl(t, append(args, dir)...)

			if err := securedir.Verify(dir, securedir.Options{}); !errors.Is(err, securedir.ErrUnsafeAccess) {
				t.Fatalf("Verify with a planted ACL = %v; want ErrUnsafeAccess", err)
			}
			if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
				t.Fatalf("Ensure: %v", err)
			}
			if err := securedir.Verify(dir, securedir.Options{}); err != nil {
				t.Errorf("Verify after Ensure stripped the ACL: %v", err)
			}
		})
	}
}

func TestPOSIXACLOnAFileInTheTreeIsRefused(t *testing.T) {
	dir := filepath.Join(tempDir(t), "data")
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	setfacl(t, "-m", "u:65534:rw", file)

	if err := securedir.Verify(dir, securedir.Options{}); !errors.Is(err, securedir.ErrUnsafeAccess) {
		t.Errorf("Verify = %v; want ErrUnsafeAccess", err)
	}
	if err := securedir.Ensure(dir, securedir.Options{}); !errors.Is(err, securedir.ErrUnsafeAccess) {
		t.Errorf("Ensure = %v; want ErrUnsafeAccess", err)
	}
}

func TestCanonicalRefusesALinkInADirectoryWithAnACLGrant(t *testing.T) {
	base := tempDir(t)
	link := plantedLink(t, base)
	setfacl(t, "-m", "g:65534:rwx", base)

	_, err := securedir.Canonical(filepath.Join(link, "mid", "data"), securedir.Options{})
	if !errors.Is(err, securedir.ErrUnsafeAccess) {
		t.Fatalf("Canonical = %v; want ErrUnsafeAccess", err)
	}
}

func TestOpenFileRefusesAFileWithAnACLWriteGrant(t *testing.T) {
	dir := filepath.Join(tempDir(t), "data")
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config")
	mustWrite(t, path, 0o600)
	setfacl(t, "-m", "u:65534:rw", path)

	file, err := securedir.OpenFile(path, os.O_RDONLY, securedir.Options{})
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, securedir.ErrUnsafeAccess) {
		t.Fatalf("OpenFile = %v; want ErrUnsafeAccess", err)
	}
}
