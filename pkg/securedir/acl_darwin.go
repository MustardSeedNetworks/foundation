// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package securedir

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// System call numbers from xnu's syscalls.master. x/sys/unix still defines them
// but marks them deprecated in favour of libSystem wrappers, which cannot be
// reached without cgo; the numbers themselves are the stable kernel ABI.
const (
	sysFgetattrlist   = 228
	sysFchmodExtended = 283
)

// This file talks to the kernel with raw system calls (fgetattrlist and
// fchmod_extended), not libc's acl_get_fd_np / acl_set_fd_np, so foundation
// stays free of cgo here. The extended ACL comes back as the same kauth_filesec
// blob libc would parse; acl_parse.go reads it.

// readACL returns the extended ACL of the open file, or nil when there is none
// or the filesystem has no ACLs.
func readACL(fd int) ([]byte, error) {
	list := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	buf := make([]byte, 64<<10)
	_, _, errno := unix.Syscall6(sysFgetattrlist, uintptr(fd), uintptr(unsafe.Pointer(&list)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 {
		if errors.Is(errno, unix.ENOTSUP) || errors.Is(errno, unix.EINVAL) {
			return nil, nil
		}
		return nil, fmt.Errorf("read ACL: %w", errno)
	}
	// The reply is a length word and an attrreference (offset relative to its
	// own position, then length); an object without an ACL reports length 0.
	if binary.LittleEndian.Uint32(buf) < 12 {
		return nil, nil
	}
	offset := int(binary.LittleEndian.Uint32(buf[4:]))
	length := int(binary.LittleEndian.Uint32(buf[8:]))
	if length == 0 {
		return nil, nil
	}
	if offset < 0 || 4+offset+length > len(buf) {
		return nil, fmt.Errorf("%w: malformed ACL reply", ErrUnsafeAccess)
	}
	return buf[4+offset : 4+offset+length], nil
}

// checkACL refuses an extended ACL entry that lets an untrusted principal
// modify the object (or, for an ancestor, delete or re-permission what is
// below it).
func checkACL(fd int, path string, ancestor, _ bool) error {
	blob, err := readACL(fd)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	mask := uint32(aclModify)
	if ancestor {
		mask = aclRemove
	}
	if err = filesecACLUnsafe(blob, mask, trustedUIDs()); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// stripACL removes the whole extended ACL, as fchmodx_np does with
// _FILESEC_REMOVE_ACL: fchmod_extended with the "remove" sentinel (1) for the
// security argument and "none" for owner and group.
func stripACL(fd int) error {
	const none = ^uint32(0) - 100 // KAUTH_UID_NONE and KAUTH_GID_NONE
	_, _, errno := unix.Syscall6(sysFchmodExtended, uintptr(fd), uintptr(none), uintptr(none), dirMode, 1, 0)
	if errno != 0 {
		return fmt.Errorf("remove ACL: %w", errno)
	}
	return nil
}
