// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package securedir

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	dirMode  fs.FileMode = 0o700
	fileMode fs.FileMode = 0o600
	// writableByOthers is any group or world write bit.
	writableByOthers fs.FileMode = 0o022
)

// openDir returns a root for dir after refusing a symlink at dir itself and
// checking that what was opened is the thing that was looked at, so a swap
// between the two is an error instead of a followed link. The returned file
// is a descriptor on the directory, for fchmod and fstat.
func openDir(dir string) (*os.Root, *os.File, fs.FileInfo, error) {
	parent, err := os.OpenRoot(filepath.Dir(dir))
	if err != nil {
		return nil, nil, nil, err
	}
	defer parent.Close()

	base := filepath.Base(dir)
	linkInfo, err := parent.Lstat(base)
	if err != nil {
		return nil, nil, nil, err
	}
	if linkInfo.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, nil, fmt.Errorf("%w: %s", ErrReparsePoint, dir)
	}
	if !linkInfo.IsDir() {
		return nil, nil, nil, fmt.Errorf("securedir: %s is not a directory", dir)
	}

	root, err := parent.OpenRoot(base)
	if err != nil {
		return nil, nil, nil, err
	}
	handle, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, nil, nil, err
	}
	info, err := handle.Stat()
	if err != nil {
		_ = handle.Close()
		_ = root.Close()
		return nil, nil, nil, err
	}
	if !os.SameFile(linkInfo, info) {
		_ = handle.Close()
		_ = root.Close()
		return nil, nil, nil, fmt.Errorf("%w: %s changed while being opened", ErrReparsePoint, dir)
	}
	return root, handle, info, nil
}

func ownerTrusted(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("securedir: cannot read the owner on this platform")
	}
	if uid := int(stat.Uid); uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("%w: owned by uid %d", ErrUntrustedOwner, uid)
	}
	return nil
}

func ensure(path string, _ trustSet) error {
	parent, err := os.OpenRoot(filepath.Dir(path))
	if errors.Is(err, fs.ErrNotExist) && filepath.Dir(path) != path {
		if err = ensure(filepath.Dir(path), trustSet{}); err != nil {
			return err
		}
		parent, err = os.OpenRoot(filepath.Dir(path))
	}
	if err != nil {
		return err
	}
	defer parent.Close()

	if err = parent.Mkdir(filepath.Base(path), dirMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}

	root, handle, info, err := openDir(path)
	if err != nil {
		return err
	}
	defer root.Close()
	defer handle.Close()
	if err = ownerTrusted(info); err != nil {
		return fmt.Errorf("%w (%s)", err, path)
	}
	if err = walkTree(root); err != nil {
		return fmt.Errorf("refusing to take over %s: %w", path, err)
	}
	return handle.Chmod(dirMode)
}

// walkTree checks everything under root at any depth: no symlinks, every owner
// root or the effective user, nothing writable by group or others. Links are
// reported, never followed.
func walkTree(root *os.Root) error {
	return fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrReparsePoint, name)
		}
		return checkEntry(name, info)
	})
}

func verify(path string, files []string, _ trustSet) error {
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	parentInfo, err := parent.Stat(".")
	_ = parent.Close()
	if err != nil {
		return err
	}
	if mode := parentInfo.Mode(); mode&writableByOthers != 0 && mode&fs.ModeSticky == 0 {
		return fmt.Errorf("%w: parent of %s is writable by group or others", ErrUnsafeAccess, path)
	}

	root, handle, info, err := openDir(path)
	if err != nil {
		return err
	}
	defer root.Close()
	defer handle.Close()
	if err = checkEntry(path, info); err != nil {
		return err
	}

	if err = walkTree(root); err != nil {
		return err
	}
	for _, rel := range files {
		if err = verifyFile(root, rel); err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
	}
	return nil
}

// checkEntry is the owner and write-bit check shared by the directory and its
// files.
func checkEntry(path string, info fs.FileInfo) error {
	if err := ownerTrusted(info); err != nil {
		return fmt.Errorf("%w (%s)", err, path)
	}
	if info.Mode().Perm()&writableByOthers != 0 {
		return fmt.Errorf("%w: %s is writable by group or others", ErrUnsafeAccess, path)
	}
	return nil
}

// verifyFile checks every component of rel, so a directory swapped for a
// symlink partway down is caught as well as the file itself.
func verifyFile(root *os.Root, rel string) error {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i := range parts {
		name := filepath.Join(parts[:i+1]...)
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w", ErrReparsePoint)
		}
		if err = checkEntry(name, info); err != nil {
			return err
		}
	}
	return nil
}

func writeFile(path string, data []byte, _ trustSet) error {
	dir, base := filepath.Split(path)
	dir = filepath.Clean(dir)
	root, handle, _, err := openDir(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	defer handle.Close()

	suffix := make([]byte, 8)
	if _, err = rand.Read(suffix); err != nil {
		return err
	}
	tmp := "." + base + ".tmp-" + hex.EncodeToString(suffix)

	file, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = root.Rename(tmp, base)
	}
	if err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func openFile(path string, flag int, _ trustSet) (*os.File, error) {
	dir, base := filepath.Split(path)
	root, handle, _, err := openDir(filepath.Clean(dir))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	defer handle.Close()

	// Root.OpenFile reports a symlink that leaves the root as a generic escape
	// error, so look at the entry first to give the caller the typed one.
	if info, lstatErr := root.Lstat(base); lstatErr == nil && info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrReparsePoint, path)
	}
	file, err := root.OpenFile(base, flag|syscall.O_NOFOLLOW, fileMode)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%w: %s", ErrReparsePoint, path)
	}
	return file, err
}
