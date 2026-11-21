// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package securedir

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The directory is replaced by a symlink to an attacker's directory after it
// has been checked and before the file operation runs. The operation has to
// land in the directory that was checked, which has been moved aside, or fail;
// it must never go through the link.
func TestSwapAfterTheCheckDoesNotRedirectTheOperation(t *testing.T) {
	for _, op := range []string{"WriteFile", "OpenFile"} {
		t.Run(op, func(t *testing.T) {
			base := canonicalTemp(t)
			data := filepath.Join(base, "data")
			if err := Ensure(data, Options{}); err != nil {
				t.Fatal(err)
			}
			attacker := filepath.Join(base, "attacker")
			if err := os.Mkdir(attacker, 0o700); err != nil {
				t.Fatal(err)
			}
			moved := filepath.Join(base, "moved")

			afterPin = func() {
				if err := os.Rename(data, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(attacker, data); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { afterPin = nil })

			var err error
			switch op {
			case "WriteFile":
				err = WriteFile(filepath.Join(data, "f"), []byte("secret"), Options{})
			case "OpenFile":
				var file *os.File
				if file, err = OpenFile(filepath.Join(data, "f"), os.O_WRONLY|os.O_CREATE, Options{}); err == nil {
					_, err = file.WriteString("secret")
					_ = file.Close()
				}
			}
			if err != nil {
				t.Fatalf("%s: %v", op, err)
			}
			if _, statErr := os.Stat(filepath.Join(moved, "f")); statErr != nil {
				t.Errorf("the file is not in the directory that was checked: %v", statErr)
			}
			if entries, _ := os.ReadDir(attacker); len(entries) != 0 {
				t.Errorf("the operation went through the symlink: %v", entries)
			}
		})
	}
}

// A swap that happens before the call is seen by the call's own walk.
func TestSwapBeforeTheCallIsRefused(t *testing.T) {
	base := canonicalTemp(t)
	data := filepath.Join(base, "data")
	if err := Ensure(data, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Verify(data, Options{}); err != nil {
		t.Fatal(err)
	}
	attacker := filepath.Join(base, "attacker")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(data, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(attacker, data); err != nil {
		t.Fatal(err)
	}

	if err := WriteFile(filepath.Join(data, "f"), []byte("x"), Options{}); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("WriteFile = %v; want ErrReparsePoint", err)
	}
	if entries, _ := os.ReadDir(attacker); len(entries) != 0 {
		t.Errorf("a file landed in the attacker's directory: %v", entries)
	}
}

func canonicalTemp(t *testing.T) string {
	t.Helper()
	dir, err := Canonical(t.TempDir(), Options{})
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	return dir
}
