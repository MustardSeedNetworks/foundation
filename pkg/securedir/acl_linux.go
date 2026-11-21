// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package securedir

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// POSIX ACLs are the system.posix_acl_access and system.posix_acl_default
// extended attributes. They are read and removed through the held descriptor;
// acl_parse.go reads the bytes.

func readXattr(fd int, name string) ([]byte, error) {
	buf := make([]byte, 4096)
	n, err := unix.Fgetxattr(fd, name, buf)
	if err != nil {
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return buf[:n], nil
}

// checkACL refuses a POSIX ACL entry that grants write to a named user or
// group other than root and the effective user. A default ACL is checked on
// directories because new entries would inherit it. An ancestor with the
// sticky bit is exempt: there nobody can remove what they do not own.
func checkACL(fd int, path string, ancestor, isDir bool) error {
	if ancestor {
		if st, err := fstat(fd); err == nil && st.Mode&unix.S_ISVTX != 0 {
			return nil
		}
	}
	names := []string{"system.posix_acl_access"}
	if isDir {
		names = append(names, "system.posix_acl_default")
	}
	for _, name := range names {
		blob, err := readXattr(fd, name)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err = posixACLUnsafe(blob, trustedUIDs()); err != nil {
			return fmt.Errorf("%s: %s: %w", path, name, err)
		}
	}
	return nil
}

// stripACL removes both POSIX ACLs; an object without one is already as wanted.
func stripACL(fd int) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		if err := unix.Fremovexattr(fd, name); err != nil && !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			return fmt.Errorf("remove %s: %w", name, err)
		}
	}
	return nil
}
