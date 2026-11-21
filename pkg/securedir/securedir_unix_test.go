// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package securedir_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/securedir"
)

// chmod and mkdirMode take the mode as a parameter: these tests need loose
// permissions on purpose, which a literal would have the security linter reject.
func chmod(path string, perm fs.FileMode) error { return os.Chmod(path, perm) }

func mkdirMode(path string, perm fs.FileMode) error { return os.Mkdir(path, perm) }

func mode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return info.Mode()
}

func TestEnsureCreatesPrivateDirectoriesAndAncestors(t *testing.T) {
	leaf := filepath.Join(t.TempDir(), "a", "b", "data")
	if err := securedir.Ensure(leaf, securedir.Options{}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, dir := range []string{leaf, filepath.Dir(leaf), filepath.Dir(filepath.Dir(leaf))} {
		if got := mode(t, dir).Perm(); got != 0o700 {
			t.Errorf("%s mode = %#o; want 0700", dir, got)
		}
	}
	if err := securedir.Ensure(leaf, securedir.Options{}); err != nil {
		t.Errorf("second Ensure: %v", err)
	}
}

func TestEnsureTightensAnExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := mkdirMode(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := chmod(dir, 0o777|fs.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got := mode(t, dir); got != fs.ModeDir|0o700 {
		t.Errorf("mode = %v; want drwx------", got)
	}
}

func TestEnsureRefusesASymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "elsewhere")
	if err := mkdirMode(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "data")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := securedir.Ensure(link, securedir.Options{}); !errors.Is(err, securedir.ErrReparsePoint) {
		t.Fatalf("Ensure(symlink) = %v; want ErrReparsePoint", err)
	}
	if got := mode(t, target).Perm(); got != 0o755 {
		t.Errorf("the symlink target was chmodded to %#o", got)
	}
}

func TestEnsureRefusesAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := securedir.Ensure(path, securedir.Options{}); err == nil {
		t.Fatal("Ensure succeeded on a regular file")
	}
}

func TestVerify(t *testing.T) {
	newDir := func(t *testing.T) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "data")
		if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("accepts what Ensure made", func(t *testing.T) {
		dir := newDir(t)
		if err := securedir.WriteFile(filepath.Join(dir, "server.key"), []byte("k"), securedir.Options{}); err != nil {
			t.Fatal(err)
		}
		if err := securedir.Verify(dir, securedir.Options{Files: []string{"server.key"}}); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	t.Run("missing directory", func(t *testing.T) {
		err := securedir.Verify(filepath.Join(t.TempDir(), "absent"), securedir.Options{})
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Verify(missing) = %v; want fs.ErrNotExist", err)
		}
	})

	t.Run("group or world writable", func(t *testing.T) {
		for _, perm := range []fs.FileMode{0o770, 0o707, 0o777} {
			dir := newDir(t)
			if err := chmod(dir, perm); err != nil {
				t.Fatal(err)
			}
			if err := securedir.Verify(dir, securedir.Options{}); !errors.Is(err, securedir.ErrUnsafeAccess) {
				t.Errorf("mode %#o: Verify = %v; want ErrUnsafeAccess", perm, err)
			}
		}
	})

	t.Run("symlink", func(t *testing.T) {
		real := newDir(t)
		link := filepath.Join(filepath.Dir(real), "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if err := securedir.Verify(link, securedir.Options{}); !errors.Is(err, securedir.ErrReparsePoint) {
			t.Fatalf("Verify(symlink) = %v; want ErrReparsePoint", err)
		}
	})

	t.Run("writable parent", func(t *testing.T) {
		dir := newDir(t)
		parent := filepath.Dir(dir)
		if err := chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := securedir.Verify(dir, securedir.Options{}); !errors.Is(err, securedir.ErrUnsafeAccess) {
			t.Fatalf("Verify = %v; want ErrUnsafeAccess", err)
		}
		if err := chmod(parent, 0o777|fs.ModeSticky); err != nil {
			t.Fatal(err)
		}
		if err := securedir.Verify(dir, securedir.Options{}); err != nil {
			t.Errorf("sticky world-writable parent (the /tmp shape): %v", err)
		}
	})

	t.Run("files must exist", func(t *testing.T) {
		dir := newDir(t)
		if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(dir, "sub", "ok"), 0o600)

		if err := securedir.Verify(dir, securedir.Options{Files: []string{"sub/ok"}}); err != nil {
			t.Errorf("Verify = %v", err)
		}
		if err := securedir.Verify(dir, securedir.Options{Files: []string{"sub/ok", "absent"}}); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("missing file: Verify = %v; want fs.ErrNotExist", err)
		}
		if err := securedir.Verify(dir, securedir.Options{Files: []string{"../escape"}}); err == nil {
			t.Error("Files entry escaping the directory accepted")
		}
	})
}

func TestWriteFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "server.crt")

	for _, content := range []string{"first", "second, longer than the first"} {
		if err := securedir.WriteFile(path, []byte(content), securedir.Options{}); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("read back %q, %v; want %q", got, err, content)
		}
		if perm := mode(t, path).Perm(); perm != 0o600 {
			t.Errorf("mode = %#o; want 0600", perm)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory holds %v (%v); want only server.crt, no temp file", entries, err)
	}
}

// A symlink planted at the destination is replaced, not written through.
func TestWriteFileReplacesASymlinkAtTheDestination(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "server.crt")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}

	if err := securedir.WriteFile(path, []byte("new"), securedir.Options{}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Errorf("the symlink target was written through: %q", got)
	}
	if mode(t, path)&fs.ModeSymlink != 0 {
		t.Error("destination is still a symlink")
	}
}

func TestWriteFileRefusesASymlinkedDirectory(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := securedir.Ensure(real, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := securedir.WriteFile(filepath.Join(link, "f"), []byte("x"), securedir.Options{}); !errors.Is(err, securedir.ErrReparsePoint) {
		t.Fatalf("WriteFile through a symlinked directory = %v; want ErrReparsePoint", err)
	}
}

func TestPathsMustBeAbsoluteAndSIDsValid(t *testing.T) {
	if securedir.Ensure("relative/dir", securedir.Options{}) == nil ||
		securedir.Verify("relative/dir", securedir.Options{}) == nil ||
		securedir.WriteFile("relative/file", nil, securedir.Options{}) == nil {
		t.Error("a relative path was accepted")
	}
	bad := securedir.Options{ExtraTrustedSIDs: []string{"not-a-sid"}}
	dir := filepath.Join(t.TempDir(), "data")
	if securedir.Ensure(dir, bad) == nil {
		t.Error("an invalid SID was accepted")
	}
	if _, err := os.Lstat(dir); err == nil {
		t.Error("Ensure created the directory despite the invalid option")
	}
}

// Verify and Ensure judge the whole tree, not only the files that were named.
func TestTreeWalk(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  error
	}{
		{"clean tree", func(t *testing.T, dir string) {
			mustMkdir(t, filepath.Join(dir, "a", "b"))
			mustWrite(t, filepath.Join(dir, "a", "b", "f"), 0o600)
		}, nil},
		{"deep symlink", func(t *testing.T, dir string) {
			mustMkdir(t, filepath.Join(dir, "a", "b"))
			if err := os.Symlink(dir, filepath.Join(dir, "a", "b", "loop")); err != nil {
				t.Fatal(err)
			}
		}, securedir.ErrReparsePoint},
		{"dangling symlink", func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling")); err != nil {
				t.Fatal(err)
			}
		}, securedir.ErrReparsePoint},
		{"deep writable file", func(t *testing.T, dir string) {
			mustMkdir(t, filepath.Join(dir, "a", "b"))
			mustWrite(t, filepath.Join(dir, "a", "b", "f"), 0o666)
		}, securedir.ErrUnsafeAccess},
		{"hard link to a file outside", func(t *testing.T, dir string) {
			outside := filepath.Join(t.TempDir(), "outside")
			mustWrite(t, outside, 0o600)
			if err := os.Link(outside, filepath.Join(dir, "linked")); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
		}, securedir.ErrUnsafeAccess},
		{"two names inside the tree", func(t *testing.T, dir string) {
			mustMkdir(t, filepath.Join(dir, "a"))
			mustWrite(t, filepath.Join(dir, "one"), 0o600)
			if err := os.Link(filepath.Join(dir, "one"), filepath.Join(dir, "a", "two")); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
		}, securedir.ErrUnsafeAccess},
		{"deep writable directory", func(t *testing.T, dir string) {
			mustMkdir(t, filepath.Join(dir, "a", "b"))
			if err := chmod(filepath.Join(dir, "a", "b"), 0o777); err != nil {
				t.Fatal(err)
			}
		}, securedir.ErrUnsafeAccess},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, dir)

			err := securedir.Verify(dir, securedir.Options{})
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Errorf("Verify = %v; want %v", err, tc.want)
			}

			// Ensure on the same existing tree must agree. It locks the
			// directory down before judging the contents, so a tree that fails
			// is reported with the directory already at 0700, never left open.
			if err := chmod(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			err = securedir.Ensure(dir, securedir.Options{})
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Errorf("Ensure = %v; want %v", err, tc.want)
			}
			if got := mode(t, dir).Perm(); got != 0o700 {
				t.Errorf("directory mode after Ensure = %#o; want 0700 whatever the verdict", got)
			}
		})
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, perm fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

func TestOpenFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	opts := securedir.Options{}

	t.Run("creates owner-only and reads back", func(t *testing.T) {
		path := filepath.Join(dir, "app.log")
		file, err := securedir.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, opts)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		if _, err = file.WriteString("line\n"); err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
		if perm := mode(t, path).Perm(); perm != 0o600 {
			t.Errorf("mode = %#o; want 0600", perm)
		}
		file, err = securedir.OpenFile(path, os.O_RDONLY, opts)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		_ = file.Close()
	})

	t.Run("refuses a symlink", func(t *testing.T) {
		victim := filepath.Join(t.TempDir(), "victim")
		mustWrite(t, victim, 0o600)
		link := filepath.Join(dir, "link")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		for _, flag := range []int{os.O_RDONLY, os.O_WRONLY | os.O_CREATE | os.O_TRUNC} {
			file, err := securedir.OpenFile(link, flag, opts)
			if !errors.Is(err, securedir.ErrReparsePoint) {
				_ = file.Close()
				t.Errorf("flag %#x: OpenFile(symlink) = %v; want ErrReparsePoint", flag, err)
			}
		}
		if got, _ := os.ReadFile(victim); string(got) != "x" {
			t.Errorf("the symlink target was modified: %q", got)
		}
	})

	t.Run("refuses a symlinked directory", func(t *testing.T) {
		link := filepath.Join(filepath.Dir(dir), "dirlink")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		if _, err := securedir.OpenFile(filepath.Join(link, "app.log"), os.O_RDONLY, opts); !errors.Is(err, securedir.ErrReparsePoint) {
			t.Fatalf("OpenFile = %v; want ErrReparsePoint", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := securedir.OpenFile(filepath.Join(dir, "absent"), os.O_RDONLY, opts); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("OpenFile = %v; want fs.ErrNotExist", err)
		}
	})
}

func TestOpenFileRefusesAHardLinkAndDoesNotTruncateIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "app.log")
	if err := os.Link(outside, linked); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	for _, flag := range []int{os.O_RDONLY, os.O_WRONLY | os.O_TRUNC, os.O_WRONLY | os.O_CREATE | os.O_TRUNC} {
		file, err := securedir.OpenFile(linked, flag, securedir.Options{})
		if !errors.Is(err, securedir.ErrUnsafeAccess) {
			if file != nil {
				_ = file.Close()
			}
			t.Errorf("flag %#x: OpenFile(hard link) = %v; want ErrUnsafeAccess", flag, err)
		}
	}
	if got, _ := os.ReadFile(outside); string(got) != "precious" {
		t.Errorf("the other name's content was changed: %q", got)
	}
}

func TestOpenFileTruncatesAnOrdinaryFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := securedir.Ensure(dir, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "f")
	mustWrite(t, path, 0o600)
	file, err := securedir.OpenFile(path, os.O_WRONLY|os.O_TRUNC, securedir.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if info, _ := os.Stat(path); info.Size() != 0 {
		t.Errorf("size = %d; want 0", info.Size())
	}
}

// Ensure must close the window between "this directory is acceptable" and "it
// is private": the directory is 0700 by the time the contents are examined, so
// an entry another user adds while the walk runs cannot be missed. The hook is
// the walk itself: a loose child makes Ensure fail, and the failure must find
// the directory already locked.
func TestEnsureLocksDownBeforeItWalks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := mkdirMode(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "loose"), 0o666)

	if err := securedir.Ensure(dir, securedir.Options{}); !errors.Is(err, securedir.ErrUnsafeAccess) {
		t.Fatalf("Ensure = %v; want ErrUnsafeAccess", err)
	}
	if got := mode(t, dir).Perm(); got != 0o700 {
		t.Errorf("directory left at %#o after a refused take-over; want 0700", got)
	}
}

// ancestorFixture builds <base>/real/mid/data as a private directory and
// returns the pieces.
func ancestorFixture(t *testing.T) (base, grand, data string) {
	t.Helper()
	base = t.TempDir()
	grand = filepath.Join(base, "real")
	data = filepath.Join(grand, "mid", "data")
	if err := securedir.Ensure(data, securedir.Options{}); err != nil {
		t.Fatal(err)
	}
	return base, grand, data
}

func allEntryPoints(t *testing.T, dir string) map[string]func() error {
	t.Helper()
	opts := securedir.Options{}
	return map[string]func() error{
		"Verify":    func() error { return securedir.Verify(dir, opts) },
		"WriteFile": func() error { return securedir.WriteFile(filepath.Join(dir, "f"), []byte("x"), opts) },
		"OpenFile": func() error {
			file, err := securedir.OpenFile(filepath.Join(dir, "f"), os.O_RDONLY, opts)
			if file != nil {
				_ = file.Close()
			}
			return err
		},
	}
}

func TestAncestorTwoLevelsUpThatIsWritableIsRefused(t *testing.T) {
	_, grand, data := ancestorFixture(t)
	if err := chmod(grand, 0o777); err != nil {
		t.Fatal(err)
	}
	for name, call := range allEntryPoints(t, data) {
		if err := call(); !errors.Is(err, securedir.ErrUnsafeAccess) {
			t.Errorf("%s = %v; want ErrUnsafeAccess", name, err)
		}
	}
}

func TestAncestorWithAnUntrustedOwnerIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("handing a directory to another user needs root")
	}
	_, grand, data := ancestorFixture(t)
	if err := os.Chown(grand, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	for name, call := range allEntryPoints(t, data) {
		if err := call(); !errors.Is(err, securedir.ErrUntrustedOwner) {
			t.Errorf("%s = %v; want ErrUntrustedOwner", name, err)
		}
	}
}

// A symlink two levels up that an unprivileged user could have planted.
func TestAncestorSymlinkIsRefused(t *testing.T) {
	base, _, _ := ancestorFixture(t)
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, "real"), link); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(link, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	for name, call := range allEntryPoints(t, filepath.Join(link, "mid", "data")) {
		if err := call(); !errors.Is(err, securedir.ErrReparsePoint) {
			t.Errorf("%s = %v; want ErrReparsePoint", name, err)
		}
	}
}
