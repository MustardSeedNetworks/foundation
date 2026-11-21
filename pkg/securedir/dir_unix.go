// SPDX-License-Identifier: BUSL-1.1

//go:build unix

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

	"golang.org/x/sys/unix"
)

const (
	dirMode  = 0o700
	fileMode = 0o600
	// writableByOthers is any group or world write bit.
	writableByOthers = 0o022
)

func isDir(st *unix.Stat_t) bool  { return st.Mode&unix.S_IFMT == unix.S_IFDIR }
func isLink(st *unix.Stat_t) bool { return st.Mode&unix.S_IFMT == unix.S_IFLNK }

func ownerTrusted(st *unix.Stat_t) error {
	if uid := int(st.Uid); uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("%w: owned by uid %d", ErrUntrustedOwner, uid)
	}
	return nil
}

// checkEntry is the check for the directory itself, its contents and the
// directory each file lives in: trusted owner, not writable by group or others,
// and no second name for a file.
func checkEntry(path string, st *unix.Stat_t) error {
	if err := ownerTrusted(st); err != nil {
		return fmt.Errorf("%w (%s)", err, path)
	}
	if st.Mode&writableByOthers != 0 {
		return fmt.Errorf("%w: %s is writable by group or others", ErrUnsafeAccess, path)
	}
	// A second name means someone can reach the content from outside the
	// directory, or has pointed a name inside at a file elsewhere.
	if !isDir(st) && uint64(st.Nlink) > 1 {
		return fmt.Errorf("%w: %s has %d hard links", ErrUnsafeAccess, path, uint64(st.Nlink))
	}
	return nil
}

// checkAncestor is the check for every directory above the private one: a
// trusted owner and no group or world write. A sticky world-writable directory
// such as /tmp passes the second test, because there nobody can remove an entry
// they do not own, and the owner test on the next component down is what
// guarantees that entry is ours.
func checkAncestor(path string, st *unix.Stat_t) error {
	if err := ownerTrusted(st); err != nil {
		return fmt.Errorf("ancestor %s: %w", path, err)
	}
	if st.Mode&writableByOthers != 0 && st.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("%w: ancestor %s is writable by group or others", ErrUnsafeAccess, path)
	}
	return nil
}

func fstat(fd int) (*unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func lstatAt(fd int, name string) (*unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	return &st, nil
}

// openDirAt opens the directory name inside dirfd without following a link at
// name, reporting one as ErrReparsePoint.
func openDirAt(dirfd int, name string) (int, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		return fd, nil
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		if st, statErr := lstatAt(dirfd, name); statErr == nil && isLink(st) {
			return -1, fmt.Errorf("%w: %s", ErrReparsePoint, name)
		}
	}
	return -1, err
}

func components(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
}

// checkNoLinks reports whether the chain down to dir contains a link.
func checkNoLinks(dir string) error {
	fd, _, err := openChain(dir, false)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// openChain opens path as a directory by walking from / one component at a
// time with openat and O_NOFOLLOW, so the descriptor it returns is the
// directory that was checked and not whatever the path names a moment later. A
// link anywhere in the chain is refused; callers pass a path from [Canonical].
// With strict, every ancestor is
// checked with checkAncestor; Ensure passes false because it is the step that
// builds the chain. The caller owns the descriptor and the leaf's checks.
func openChain(path string, strict bool) (int, *unix.Stat_t, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	st, err := fstat(fd)
	if err != nil {
		_ = unix.Close(fd)
		return -1, nil, err
	}

	parts := components(path)
	walked := "/"
	for _, name := range parts {
		if strict {
			if err = checkAncestor(walked, st); err != nil {
				_ = unix.Close(fd)
				return -1, nil, err
			}
		}
		next, openErr := openDirAt(fd, name)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, nil, fmt.Errorf("open %s: %w", filepath.Join(walked, name), openErr)
		}
		fd = next
		if st, err = fstat(fd); err != nil {
			_ = unix.Close(fd)
			return -1, nil, err
		}
		walked = filepath.Join(walked, name)
	}
	return fd, st, nil
}

// walkTree checks everything under dirfd at any depth: no symlinks, every owner
// root or the effective user, nothing writable by group or others, no file with
// a second name. Each directory is entered through openat without following
// links.
func walkTree(dirfd int, prefix string) error {
	listing, err := unix.Openat(dirfd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(listing), prefix)
	entries, err := file.ReadDir(-1)
	_ = file.Close()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(prefix, entry.Name())
		st, statErr := lstatAt(dirfd, entry.Name())
		if statErr != nil {
			return statErr
		}
		if isLink(st) {
			return fmt.Errorf("%w: %s", ErrReparsePoint, path)
		}
		if err = checkEntry(path, st); err != nil {
			return err
		}
		if !isDir(st) {
			continue
		}
		sub, openErr := openDirAt(dirfd, entry.Name())
		if openErr != nil {
			return openErr
		}
		err = walkTree(sub, path)
		_ = unix.Close(sub)
		if err != nil {
			return err
		}
	}
	return nil
}

func ensure(path string, _ trustSet) error {
	parent := filepath.Dir(path)
	parentFD, _, err := openChain(parent, false)
	if errors.Is(err, fs.ErrNotExist) && parent != path {
		if err = ensure(parent, trustSet{}); err != nil {
			return err
		}
		parentFD, _, err = openChain(parent, false)
	}
	if err != nil {
		return err
	}
	err = unix.Mkdirat(parentFD, filepath.Base(path), dirMode)
	_ = unix.Close(parentFD)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}

	fd, st, err := openChain(path, false)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = ownerTrusted(st); err != nil {
		return fmt.Errorf("%w (%s)", err, path)
	}
	// Lock the directory down first, through the descriptor that was checked,
	// so nobody else can add entries while the tree is being judged; then walk.
	// A tree that fails is reported but stays locked: the caller gets the error
	// and the directory is no longer open to anyone else.
	if err = unix.Fchmod(fd, dirMode); err != nil {
		return err
	}
	if err = walkTree(fd, path); err != nil {
		return fmt.Errorf("refusing to trust the contents of %s: %w", path, err)
	}
	return nil
}

func verify(path string, files []string, _ trustSet) error {
	fd, st, err := openChain(path, true)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = checkEntry(path, st); err != nil {
		return err
	}
	if err = walkTree(fd, path); err != nil {
		return err
	}
	for _, rel := range files {
		var probe unix.Stat_t
		if err = unix.Fstatat(fd, filepath.ToSlash(rel), &probe, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
	}
	return nil
}

// pinDir opens and checks the directory a file operation will use, and calls
// the test hook.
func pinDir(dir string) (int, error) {
	fd, st, err := openChain(dir, true)
	if err != nil {
		return -1, err
	}
	if err = checkEntry(dir, st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if afterPin != nil {
		afterPin()
	}
	return fd, nil
}

func writeFile(path string, data []byte, _ trustSet) error {
	dir, base := filepath.Split(path)
	if err := plainName(base); err != nil {
		return err
	}
	fd, err := pinDir(filepath.Clean(dir))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	suffix := make([]byte, 8)
	if _, err = rand.Read(suffix); err != nil {
		return err
	}
	tmp := "." + base + ".tmp-" + hex.EncodeToString(suffix)

	tmpFD, err := unix.Openat(fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, fileMode)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(tmpFD), tmp)
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = unix.Renameat(fd, tmp, fd, base)
	}
	if err != nil {
		_ = unix.Unlinkat(fd, tmp, 0)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func openFile(path string, flag int, _ trustSet) (*os.File, error) {
	dir, base := filepath.Split(path)
	if err := plainName(base); err != nil {
		return nil, err
	}
	dirfd, err := pinDir(filepath.Clean(dir))
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirfd)

	// Truncation waits until the link count has been checked: O_TRUNC on a
	// file with a second name would empty the other name's content too.
	truncate := flag&os.O_TRUNC != 0
	fd, err := unix.Openat(dirfd, base, flag&^os.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, fileMode)
	if errors.Is(err, unix.ELOOP) {
		return nil, fmt.Errorf("%w: %s", ErrReparsePoint, path)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	st, err := fstat(fd)
	if err == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || uint64(st.Nlink) != 1) {
		err = fmt.Errorf("%w: %s is not a regular file with exactly one link", ErrUnsafeAccess, path)
	}
	if err == nil && truncate {
		err = file.Truncate(0)
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
