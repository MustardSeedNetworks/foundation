// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package securedir

import (
	"encoding/binary"
	"errors"
	"testing"
)

func filesec(entries ...[]byte) []byte {
	blob := binary.LittleEndian.AppendUint32(nil, filesecMagic)
	blob = append(blob, make([]byte, 32)...) // owner and group GUIDs, unset
	blob = binary.LittleEndian.AppendUint32(blob, uint32(len(entries)&0xffff))
	blob = binary.LittleEndian.AppendUint32(blob, 0)
	for _, e := range entries {
		blob = append(blob, e...)
	}
	return blob
}

func filesecEntry(who [16]byte, kind, rights uint32) []byte {
	entry := append([]byte(nil), who[:]...)
	entry = binary.LittleEndian.AppendUint32(entry, kind)
	return binary.LittleEndian.AppendUint32(entry, rights)
}

var everyone = [16]byte{0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0, 0, 0, 0x0c}

func TestFilesecACLUnsafe(t *testing.T) {
	trusted := []uint32{0, 501}
	tests := []struct {
		name string
		blob []byte
		mask uint32
		bad  bool
	}{
		{"no ACL", nil, aclModify, false},
		{"empty ACL", filesec(), aclModify, false},
		{"no-ACL marker", append(filesec()[:filesecHeader:filesecHeader], 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0), aclModify, false},
		{"everyone may only read", filesec(filesecEntry(everyone, aceKindPermit, 1<<1)), aclModify, false},
		{"everyone add_file", filesec(filesecEntry(everyone, aceKindPermit, aclWriteData)), aclModify, true},
		{"everyone delete", filesec(filesecEntry(everyone, aceKindPermit, aclDelete)), aclModify, true},
		{"everyone add_subdirectory", filesec(filesecEntry(everyone, aceKindPermit, aclAppend)), aclModify, true},
		{"everyone delete_child", filesec(filesecEntry(everyone, aceKindPermit, aclDeleteKid)), aclModify, true},
		{"everyone writesecurity", filesec(filesecEntry(everyone, aceKindPermit, aclWriteSec)), aclModify, true},
		{"everyone chown", filesec(filesecEntry(everyone, aceKindPermit, aclChown)), aclModify, true},
		{"everyone generic write", filesec(filesecEntry(everyone, aceKindPermit, aclGenericWr)), aclModify, true},
		{"a deny does not offset a grant", filesec(filesecEntry(everyone, aceKindDeny, aclModify), filesecEntry(everyone, aceKindPermit, aclDelete)), aclModify, true},
		{"deny alone", filesec(filesecEntry(everyone, aceKindDeny, aclModify)), aclModify, false},
		{"audit grants nothing", filesec(filesecEntry(everyone, aceKindAudit, aclModify)), aclModify, false},
		{"trusted user may write", filesec(filesecEntry(userGUID(501), aceKindPermit, aclModify)), aclModify, false},
		{"root may write", filesec(filesecEntry(userGUID(0), aceKindPermit, aclModify)), aclModify, false},
		{"another user may write", filesec(filesecEntry(userGUID(502), aceKindPermit, aclWriteData)), aclModify, true},
		{"unknown entry kind", filesec(filesecEntry(everyone, 9, 0)), aclModify, true},
		{"ancestor: create is fine", filesec(filesecEntry(everyone, aceKindPermit, aclWriteData|aclAppend)), aclRemove, false},
		{"ancestor: delete_child is not", filesec(filesecEntry(everyone, aceKindPermit, aclDeleteKid)), aclRemove, true},
		{"truncated", filesec(filesecEntry(everyone, aceKindPermit, aclDelete))[:filesecHeader+8+10], aclModify, true},
		{"bad magic", append([]byte{1, 2, 3, 4}, make([]byte, 60)...), aclModify, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := filesecACLUnsafe(tc.blob, tc.mask, trusted)
			if tc.bad != (err != nil) || (err != nil && !errors.Is(err, ErrUnsafeAccess)) {
				t.Fatalf("got %v; want unsafe=%v", err, tc.bad)
			}
		})
	}
}

func posixACL(entries ...[3]uint32) []byte {
	blob := binary.LittleEndian.AppendUint32(nil, posixACLVersion)
	for _, e := range entries {
		blob = binary.LittleEndian.AppendUint16(blob, uint16(e[0]&0xffff))
		blob = binary.LittleEndian.AppendUint16(blob, uint16(e[1]&0xffff))
		blob = binary.LittleEndian.AppendUint32(blob, e[2])
	}
	return blob
}

func TestPOSIXACLUnsafe(t *testing.T) {
	const (
		userObj  = 0x01
		groupObj = 0x04
		mask     = 0x10
		other    = 0x20
		rwx      = 7
		rx       = 5
	)
	trusted := []uint32{0, 1000}
	tests := []struct {
		name string
		blob []byte
		bad  bool
	}{
		{"no ACL", nil, false},
		{"base entries only", posixACL([3]uint32{userObj, rwx, 0}, [3]uint32{groupObj, 0, 0}, [3]uint32{other, 0, 0}), false},
		{"named user reads", posixACL([3]uint32{posixTagUser, rx, 1001}, [3]uint32{mask, rwx, 0}), false},
		{"named user writes", posixACL([3]uint32{posixTagUser, rwx, 1001}), true},
		{"trusted named user writes", posixACL([3]uint32{posixTagUser, rwx, 1000}), false},
		{"root named user writes", posixACL([3]uint32{posixTagUser, rwx, 0}), false},
		{"named group writes", posixACL([3]uint32{posixTagGroup, 2, 50}), true},
		{"named group reads", posixACL([3]uint32{posixTagGroup, 4, 50}), false},
		{"masked-off write still counts", posixACL([3]uint32{posixTagUser, rwx, 1001}, [3]uint32{mask, 0, 0}), true},
		{"wrong version", append([]byte{9, 0, 0, 0}, make([]byte, 8)...), true},
		{"truncated entry", append(posixACL(), 1, 2, 3), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := posixACLUnsafe(tc.blob, trusted)
			if tc.bad != (err != nil) || (err != nil && !errors.Is(err, ErrUnsafeAccess)) {
				t.Fatalf("got %v; want unsafe=%v", err, tc.bad)
			}
		})
	}
}
