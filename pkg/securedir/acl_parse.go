// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package securedir

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

// Extended ACLs sit beside the mode bits and can grant a user write access to
// a directory whose mode says 0700. The parsers here read the two on-disk forms
// from a byte slice, with no cgo and no OS calls, so they run (and are tested)
// on every unix; the platform files only fetch the bytes.

// kauth_filesec as macOS returns it from getattrlist(ATTR_CMN_EXTENDED_SECURITY):
// signature, owner GUID, group GUID, then a kauth_acl (entry count, flags, entries
// of GUID + flags + rights).
const (
	filesecSignature = 0x012cc16d
	filesecNoACL     = 0xffffffff // entry count meaning "no ACL"
	filesecHeader    = 4 + 16 + 16
	filesecEntryLen  = 16 + 4 + 4

	aceKindMask   = 0xf
	aceKindPermit = 1
	aceKindDeny   = 2
	aceKindAudit  = 3
	aceKindAlarm  = 4
	aclWriteData  = 1 << 2 // add_file
	aclDelete     = 1 << 4
	aclAppend     = 1 << 5 // add_subdirectory
	aclDeleteKid  = 1 << 6
	aclWriteAttr  = 1 << 8
	aclWriteXattr = 1 << 10
	aclWriteSec   = 1 << 12
	aclChown      = 1 << 13
	aclGenericAll = 1 << 21
	aclGenericWr  = 1 << 23

	// Concrete rights each generic right stands for. macOS defines the generic
	// write set to include DELETE, DELETE_CHILD and WRITE_SECURITY, so a generic
	// write grant is a grant to remove and re-permission, not only to create.
	aclAllRights          = 0x3ffe // READ_DATA (bit 1) through TAKE_OWNERSHIP (bit 13)
	aclGenericWriteRights = aclWriteData | aclAppend | aclDelete | aclDeleteKid |
		aclWriteAttr | aclWriteXattr | aclWriteSec

	// aclModify is everything that lets a principal change an object or its
	// permissions; aclRemove is what an ancestor must not grant: removing or
	// renaming what is below it, or changing its own ACL to be able to.
	aclModify = aclWriteData | aclDelete | aclAppend | aclDeleteKid | aclWriteAttr |
		aclWriteXattr | aclWriteSec | aclChown
	aclRemove = aclDelete | aclDeleteKid | aclWriteSec | aclChown
)

// normalizeRights replaces the generic bits with the concrete rights they
// stand for, so the masks only have to name concrete rights.
func normalizeRights(rights uint32) uint32 {
	if rights&aclGenericAll != 0 {
		rights |= aclAllRights
	}
	if rights&aclGenericWr != 0 {
		rights |= aclGenericWriteRights
	}
	return rights
}

// userGUID is the GUID macOS derives for a local user: a fixed 12-byte prefix
// and the uid. Directory-service accounts have other GUIDs and so are never
// trusted here.
func userGUID(uid uint32) [16]byte {
	guid := [16]byte{0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa}
	binary.BigEndian.PutUint32(guid[12:], uid)
	return guid
}

// filesecACLUnsafe fails when an allow entry grants a bit of mask to anyone
// other than the trusted users. Deny, audit and alarm entries grant nothing; an
// entry kind this code does not know is an error.
func filesecACLUnsafe(blob []byte, mask uint32, trustedUIDs []uint32) error {
	if len(blob) == 0 {
		return nil
	}
	if len(blob) < filesecHeader+8 || binary.LittleEndian.Uint32(blob) != filesecSignature {
		return fmt.Errorf("%w: unreadable extended ACL", ErrUnsafeAccess)
	}
	count := binary.LittleEndian.Uint32(blob[filesecHeader:])
	if count == filesecNoACL || count == 0 {
		return nil
	}
	entries := blob[filesecHeader+8:]
	if uint64(len(entries)) < uint64(count)*filesecEntryLen {
		return fmt.Errorf("%w: truncated extended ACL", ErrUnsafeAccess)
	}

	trusted := make(map[[16]byte]struct{}, len(trustedUIDs))
	for _, uid := range trustedUIDs {
		trusted[userGUID(uid)] = struct{}{}
	}
	for i := range int(count) {
		entry := entries[i*filesecEntryLen:]
		var who [16]byte
		copy(who[:], entry[:16])
		kind := binary.LittleEndian.Uint32(entry[16:]) & aceKindMask
		rights := normalizeRights(binary.LittleEndian.Uint32(entry[20:]))
		switch kind {
		case aceKindDeny, aceKindAudit, aceKindAlarm:
			continue
		case aceKindPermit:
		default:
			return fmt.Errorf("%w: extended ACL entry of unknown kind %d", ErrUnsafeAccess, kind)
		}
		if _, ok := trusted[who]; !ok && rights&mask != 0 {
			return fmt.Errorf("%w: extended ACL grants %#x to %x", ErrUnsafeAccess, rights&mask, who)
		}
	}
	return nil
}

// POSIX ACL xattr (Linux system.posix_acl_access / system.posix_acl_default):
// a version word, then 8-byte entries of tag, permissions and id.
const (
	posixACLVersion = 2
	posixTagUser    = 0x02
	posixTagGroup   = 0x08
	posixPermWrite  = 0x02
)

var errPOSIXACL = errors.New("unreadable POSIX ACL")

// posixACLUnsafe fails when a named user other than the trusted ones, or any
// named group, is granted write. The mask is deliberately not applied: an entry
// that is masked off today is a grant after the next chmod or setfacl.
func posixACLUnsafe(blob []byte, trustedUIDs []uint32) error {
	if len(blob) == 0 {
		return nil
	}
	if len(blob) < 4 || (len(blob)-4)%8 != 0 || binary.LittleEndian.Uint32(blob) != posixACLVersion {
		return fmt.Errorf("%w: %w", ErrUnsafeAccess, errPOSIXACL)
	}
	for entry := blob[4:]; len(entry) > 0; entry = entry[8:] {
		tag := binary.LittleEndian.Uint16(entry)
		perm := binary.LittleEndian.Uint16(entry[2:])
		id := binary.LittleEndian.Uint32(entry[4:])
		if perm&posixPermWrite == 0 {
			continue
		}
		switch tag {
		case posixTagGroup:
			return fmt.Errorf("%w: POSIX ACL grants write to group %d", ErrUnsafeAccess, id)
		case posixTagUser:
			if !uidIn(trustedUIDs, id) {
				return fmt.Errorf("%w: POSIX ACL grants write to user %d", ErrUnsafeAccess, id)
			}
		}
	}
	return nil
}

func uidIn(uids []uint32, uid uint32) bool {
	for _, u := range uids {
		if u == uid {
			return true
		}
	}
	return false
}

// trustedUIDs are the users whose access an ACL entry may grant: root and the
// effective user, the same set that may own a private directory.
func trustedUIDs() []uint32 {
	return []uint32{0, uint32(os.Geteuid() & 0x7fffffff)}
}
