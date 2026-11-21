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

const maxLinkHops = 40

func canonical(path string, _ trustSet) (string, error) {
	for range maxLinkHops {
		resolved, next, err := canonicalOnce(path)
		if err != nil {
			return "", err
		}
		if next == "" {
			return resolved, nil
		}
		path = next
	}
	return "", fmt.Errorf("%w: too many levels of links in %s", ErrReparsePoint, path)
}

// canonicalOnce walks path from / without following anything. It returns the
// resolved path, or, when it meets a link it may follow, the path to restart
// from with the link's target spliced in.
func canonicalOnce(path string) (resolved, next string, err error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = unix.Close(fd) }()
	st, err := fstat(fd)
	if err != nil {
		return "", "", err
	}

	parts := components(path)
	current := "/"
	for i, name := range parts {
		if err = checkAncestor(current, st); err != nil {
			return "", "", err
		}
		// The directory's ACL decides who can retarget a link in it just as
		// much as its mode does.
		if err = checkACL(fd, current, true, true); err != nil {
			return "", "", err
		}
		entry, statErr := lstatAt(fd, name)
		switch {
		case errors.Is(statErr, unix.ENOENT):
			return filepath.Join(append([]string{current}, parts[i:]...)...), "", nil
		case statErr != nil:
			return "", "", statErr
		case isLink(entry):
			// Only the owner matters for a symlink: its own permission bits are
			// ignored and nobody can retarget one without write access to the
			// directory holding it, which checkAncestor above has just ruled
			// out (owner, mode and ACL).
			if entry.Uid != 0 {
				return "", "", fmt.Errorf("%w: %s is a link not owned by root", ErrReparsePoint, filepath.Join(current, name))
			}
			target, readErr := readlinkAt(fd, name)
			if readErr != nil {
				return "", "", readErr
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(current, target)
			}
			return "", filepath.Join(append([]string{target}, parts[i+1:]...)...), nil
		case !isDir(entry) && i < len(parts)-1:
			return "", "", fmt.Errorf("securedir: %s is not a directory", filepath.Join(current, name))
		case !isDir(entry):
			return filepath.Join(current, name), "", nil
		}
		child, openErr := openDirAt(fd, name)
		if openErr != nil {
			return "", "", openErr
		}
		_ = unix.Close(fd)
		fd = child
		if st, err = fstat(fd); err != nil {
			return "", "", err
		}
		current = filepath.Join(current, name)
	}
	return current, "", nil
}

func readlinkAt(dirfd int, name string) (string, error) {
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
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
		// The ACL is checked even when the ancestor policy is not (Ensure): an
		// ACL grant is the one thing that lets a user act on a directory whose
		// mode looks closed.
		if strict {
			err = checkAncestor(walked, st)
		}
		if err == nil {
			err = checkACL(fd, walked, true, true)
		}
		if err != nil {
			_ = unix.Close(fd)
			return -1, nil, err
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
		if st.Mode&unix.S_IFMT == unix.S_IFREG {
			if err = checkFileAt(dirfd, entry.Name(), path); err != nil {
				return err
			}
			continue
		}
		if !isDir(st) {
			// A FIFO, socket or device in a private directory is never
			// something a privileged caller should open.
			return fmt.Errorf("%w: %s is not a regular file or directory", ErrUnsafeAccess, path)
		}
		if err = checkEntry(path, st); err != nil {
			return err
		}
		sub, openErr := openDirAt(dirfd, entry.Name())
		if openErr != nil {
			return openErr
		}
		err = checkACL(sub, path, false, true)
		if err == nil {
			err = walkTree(sub, path)
		}
		_ = unix.Close(sub)
		if err != nil {
			return err
		}
	}
	return nil
}

// checkOpenFile is the one decision about a regular file, used for the files
// Verify walks and for the file OpenFile has opened: a trusted owner, nothing
// writable by group or others, no second name, and no ACL grant to an untrusted
// principal. It runs on the open descriptor, so it describes the file that will
// be read.
func checkOpenFile(fd int, path string) error {
	st, err := fstat(fd)
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafeAccess, path)
	}
	if err = checkEntry(path, st); err != nil {
		return err
	}
	return checkACL(fd, path, false, false)
}

// checkFileAt opens a regular file without following a link and applies
// checkOpenFile to it.
func checkFileAt(dirfd int, name, path string) error {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s to check it: %w", path, err)
	}
	defer unix.Close(fd)
	return checkOpenFile(fd, path)
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
	// An ACL survives chmod and can grant a user write access to a 0700
	// directory, so it goes first. After that, lock the directory down, through the descriptor that was checked,
	// so nobody else can add entries while the tree is being judged; then walk.
	// A tree that fails is reported but stays locked: the caller gets the error
	// and the directory is no longer open to anyone else.
	if err = stripACL(fd); err != nil {
		return err
	}
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
	if err = checkACL(fd, path, false, true); err != nil {
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
	if err = checkEntry(dir, st); err == nil {
		err = checkACL(fd, dir, false, true)
	}
	if err != nil {
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
	// O_NONBLOCK keeps a planted FIFO from blocking the open forever before
	// the type check can reject it; it is cleared again once the file is known
	// to be a regular one, unless the caller asked for it.
	truncate := flag&os.O_TRUNC != 0
	fd, err := unix.Openat(dirfd, base, flag&^os.O_TRUNC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, fileMode)
	if errors.Is(err, unix.ELOOP) {
		return nil, fmt.Errorf("%w: %s", ErrReparsePoint, path)
	}
	if errors.Is(err, unix.ENXIO) {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafeAccess, path)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	err = checkOpenFile(fd, path)
	if err == nil && flag&unix.O_NONBLOCK == 0 {
		err = clearNonblock(fd)
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

func clearNonblock(fd int) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	return err
}
