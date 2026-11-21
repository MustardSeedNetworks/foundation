// SPDX-License-Identifier: BUSL-1.1

package securedir

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The decision logic lives here, away from any operating system, so the whole
// table of what is and is not acceptable runs on every platform. The Windows
// glue only has to turn a real descriptor into a [descriptor].

// ACE types from winnt.h. x/sys/windows defines only the first two.
const (
	aceAccessAllowed               = 0x00
	aceAccessDenied                = 0x01
	aceAccessAllowedObject         = 0x05
	aceAccessDeniedObject          = 0x06
	aceAccessAllowedCallback       = 0x09
	aceAccessDeniedCallback        = 0x0a
	aceAccessAllowedCallbackObject = 0x0b
	aceAccessDeniedCallbackObject  = 0x0c
)

// ACE flag bits.
const aceInheritOnly = 0x08

// Access mask bits.
const (
	maskAddFile      = 0x00000002 // FILE_WRITE_DATA / FILE_ADD_FILE
	maskAddSubdir    = 0x00000004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	maskWriteEA      = 0x00000010
	maskDeleteChild  = 0x00000040
	maskWriteAttrs   = 0x00000100
	maskDelete       = 0x00010000
	maskWriteDAC     = 0x00040000
	maskWriteOwner   = 0x00080000
	maskGenericWrite = 0x40000000
	maskGenericAll   = 0x10000000

	// Concrete rights the generic bits stand for (FILE_ALL_ACCESS and
	// FILE_GENERIC_WRITE). Inherit-only ACEs are stored with generic bits
	// unmapped, so they are expanded before the masks are applied. Generic write
	// is create and attribute rights only on Windows, with no DELETE or
	// DELETE_CHILD, which is why it passes the parent check and not this one.
	rightsGenericAll   = 0x001f01ff
	rightsGenericWrite = 0x00120116

	// maskModify is everything that lets a principal change the object, its
	// contents or its permissions.
	maskModify = maskAddFile | maskAddSubdir | maskWriteEA | maskDeleteChild |
		maskWriteAttrs | maskDelete | maskWriteDAC | maskWriteOwner

	// maskParentRemove is what a parent must not grant: the ability to delete
	// or rename the directory under it, or to change the parent's own ACL to
	// obtain that. Creating new entries is deliberately absent; see Verify.
	maskParentRemove = maskDeleteChild | maskDelete | maskWriteDAC | maskWriteOwner
)

// ace is one entry of a DACL, reduced to what the decision needs. sid is empty
// for a type this package cannot locate a SID in.
type ace struct {
	typ   byte
	flags byte
	mask  uint32
	sid   string
}

// descriptor is the part of a security descriptor the policy reads. hasDACL is
// false for a NULL DACL, which grants everyone everything.
type descriptor struct {
	owner   string
	hasDACL bool
	aces    []ace
}

type aceClass int

const (
	aceUnknown aceClass = iota
	aceGrant
	aceDeny
)

func classify(typ byte) aceClass {
	switch typ {
	case aceAccessAllowed, aceAccessAllowedObject, aceAccessAllowedCallback, aceAccessAllowedCallbackObject:
		return aceGrant
	case aceAccessDenied, aceAccessDeniedObject, aceAccessDeniedCallback, aceAccessDeniedCallbackObject:
		return aceDeny
	default:
		return aceUnknown
	}
}

// checkOwner requires the owner to be trusted. An owner can always rewrite the
// ACL, so this cannot be repaired by changing the DACL.
func (s trustSet) checkOwner(d descriptor) error {
	if d.owner == "" || !s.has(d.owner) {
		return fmt.Errorf("%w: owned by %q", ErrUntrustedOwner, d.owner)
	}
	return nil
}

// checkDACL fails when any grant covering a bit of mask goes to a principal
// outside the trusted set. Every allow-type ACE is a grant, whatever its
// layout; a deny ACE is understood but never subtracts from a grant, because
// an inheritance quirk or an ordering mistake must not be able to mask one. An
// ACE of any other type is an error rather than something to skip. With
// skipInheritOnly, ACEs that only apply to children are ignored, as they must
// be for a parent directory.
func (s trustSet) checkDACL(d descriptor, mask uint32, skipInheritOnly bool) error {
	if !d.hasDACL {
		return fmt.Errorf("%w: NULL DACL grants everyone full access", ErrUnsafeAccess)
	}
	for _, e := range d.aces {
		switch classify(e.typ) {
		case aceDeny:
			continue
		case aceUnknown:
			return fmt.Errorf("%w: unsupported ACE type %#x", ErrUnsafeAccess, e.typ)
		case aceGrant:
		}
		if skipInheritOnly && e.flags&aceInheritOnly != 0 {
			continue
		}
		if granted := normalizeMask(e.mask) & mask; granted != 0 && !s.has(e.sid) {
			return fmt.Errorf("%w: %s holds access %#x", ErrUnsafeAccess, e.sid, granted)
		}
	}
	return nil
}

// checkObject is the check for the private directory itself and for each file
// in it: trusted owner, and nobody untrusted can modify it or anything that
// will inherit from it.
func (s trustSet) checkObject(d descriptor) error {
	if err := s.checkOwner(d); err != nil {
		return err
	}
	return s.checkDACL(d, maskModify, false)
}

// checkParent is the check for the directory above the private one. Its owner
// matters as much as its DACL: an owner can rewrite the ACL, so an untrusted
// one could grant itself the right to delete the private directory later.
func (s trustSet) checkParent(d descriptor) error {
	if err := s.checkOwner(d); err != nil {
		return err
	}
	return s.checkDACL(d, maskParentRemove, true)
}

// normalizeMask replaces GENERIC_ALL and GENERIC_WRITE with the concrete rights
// they stand for.
func normalizeMask(mask uint32) uint32 {
	if mask&maskGenericAll != 0 {
		mask |= rightsGenericAll
	}
	if mask&maskGenericWrite != 0 {
		mask |= rightsGenericWrite
	}
	return mask
}

// parseACE decodes one raw ACE as returned by GetAce. Only allow and deny
// types are decoded; any other type comes back with its header fields and no
// SID so the caller can reject it.
func parseACE(raw []byte) (ace, error) {
	if len(raw) < 8 {
		return ace{}, errors.New("securedir: ACE shorter than its header")
	}
	if size := int(binary.LittleEndian.Uint16(raw[2:4])); size < len(raw) {
		raw = raw[:size]
	}
	e := ace{typ: raw[0], flags: raw[1], mask: binary.LittleEndian.Uint32(raw[4:8])}

	var sidAt int
	switch e.typ {
	case aceAccessAllowed, aceAccessDenied, aceAccessAllowedCallback, aceAccessDeniedCallback:
		sidAt = 8
	case aceAccessAllowedObject, aceAccessDeniedObject, aceAccessAllowedCallbackObject, aceAccessDeniedCallbackObject:
		const guidLen = 16
		if len(raw) < 12 {
			return ace{}, errors.New("securedir: object ACE shorter than its flags")
		}
		objectFlags := binary.LittleEndian.Uint32(raw[8:12])
		sidAt = 12
		if objectFlags&0x1 != 0 { // ACE_OBJECT_TYPE_PRESENT
			sidAt += guidLen
		}
		if objectFlags&0x2 != 0 { // ACE_INHERITED_OBJECT_TYPE_PRESENT
			sidAt += guidLen
		}
	default:
		return e, nil
	}

	sid, err := parseSID(raw[min(sidAt, len(raw)):])
	if err != nil {
		return ace{}, err
	}
	e.sid = sid
	return e, nil
}

// parseSID formats a binary SID the way ConvertSidToStringSid does.
func parseSID(b []byte) (string, error) {
	const header = 8
	if len(b) < header || b[0] != 1 {
		return "", errors.New("securedir: malformed SID")
	}
	count := int(b[1])
	if count > 15 || len(b) < header+4*count {
		return "", errors.New("securedir: malformed SID")
	}
	var authority uint64
	for _, octet := range b[2:8] {
		authority = authority<<8 | uint64(octet)
	}
	sid := fmt.Sprintf("S-1-%d", authority)
	for i := range count {
		sid += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[header+4*i:]))
	}
	return sid, nil
}
