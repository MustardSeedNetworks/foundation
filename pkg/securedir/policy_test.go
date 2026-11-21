// SPDX-License-Identifier: BUSL-1.1

package securedir

import (
	"encoding/binary"
	"errors"
	"slices"
	"testing"
)

const (
	serviceAccount = "S-1-5-80-111111111-222222222-333333333-444444444-555555555"
	someUser       = "S-1-5-21-1-2-3-1001"
)

func mustTrust(t *testing.T, extras ...string) trustSet {
	t.Helper()
	set, err := newTrustSet(Options{ExtraTrustedSIDs: extras})
	if err != nil {
		t.Fatalf("newTrustSet: %v", err)
	}
	return set
}

type policyCase struct {
	name   string
	sddl   string
	extras []string
	want   error // nil, or the sentinel the check must return
}

func runCases(t *testing.T, check func(trustSet, descriptor) error, cases []policyCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := check(mustTrust(t, tc.extras...), parseSDDL(t, tc.sddl))
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("got %v; want %v", err, tc.want)
			}
		})
	}
}

// The private directory and every file in it.
func TestCheckObject(t *testing.T) {
	protected := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	runCases(t, trustSet.checkObject, []policyCase{
		{name: "created by Ensure", sddl: "O:BA" + protected},
		{name: "owned by SYSTEM", sddl: "O:SY" + protected},
		{name: "empty DACL", sddl: "O:BAD:P"},
		{name: "extra account as owner and grantee", sddl: "O:" + serviceAccount + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + serviceAccount + ")", extras: []string{serviceAccount}},
		{name: "same descriptor without the extra trusted", sddl: "O:" + serviceAccount + "D:P(A;OICI;FA;;;SY)", want: ErrUntrustedOwner},
		{name: "owner is a user", sddl: "O:" + someUser + protected, want: ErrUntrustedOwner},
		{name: "owner is Users", sddl: "O:BU" + protected, want: ErrUntrustedOwner},
		{name: "no owner", sddl: protected, want: ErrUntrustedOwner},
		{name: "Users read and execute only", sddl: "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FR;;;BU)"},
		{name: "Users full control", sddl: "O:BAD:P(A;OICI;FA;;;BU)", want: ErrUnsafeAccess},
		{name: "Everyone modify", sddl: "O:BAD:P(A;;FW;;;WD)", want: ErrUnsafeAccess},
		{name: "squatter ACE left beside trusted ones", sddl: "O:BA" + protected + "(A;OICI;FA;;;" + someUser + ")", want: ErrUnsafeAccess},
		{name: "DELETE", sddl: "O:BAD:P(A;;0x10000;;;BU)", want: ErrUnsafeAccess},
		{name: "FILE_DELETE_CHILD", sddl: "O:BAD:P(A;;0x40;;;BU)", want: ErrUnsafeAccess},
		{name: "WRITE_DAC", sddl: "O:BAD:P(A;;WD;;;BU)", want: ErrUnsafeAccess},
		{name: "WRITE_OWNER", sddl: "O:BAD:P(A;;WO;;;BU)", want: ErrUnsafeAccess},
		{name: "unmapped generic write", sddl: "O:BAD:P(A;;GW;;;BU)", want: ErrUnsafeAccess},
		{name: "inherit-only generic all still counts on the directory", sddl: "O:BAD:P(A;OICIIO;GA;;;BU)", want: ErrUnsafeAccess},
		{name: "object ACE", sddl: "O:BAD:P(OA;;FW;bf967aba-0de6-11d0-a285-00aa003049f2;;BU)", want: ErrUnsafeAccess},
		{name: "callback ACE", sddl: "O:BAD:P(XA;;FW;;;BU;(@User.Title==\"PM\"))", want: ErrUnsafeAccess},
		{name: "callback object ACE", sddl: "O:BAD:P(ZA;;FW;bf967aba-0de6-11d0-a285-00aa003049f2;;BU;(@User.Title==\"PM\"))", want: ErrUnsafeAccess},
		{name: "a deny does not cancel a different grant", sddl: "O:BAD:P(D;;FA;;;BU)(A;;FW;;;BU)", want: ErrUnsafeAccess},
		{name: "a deny alone is fine", sddl: "O:BAD:P(D;;FA;;;BU)(A;;FA;;;SY)"},
		{name: "NULL DACL", sddl: "O:BAD:NO_ACCESS_CONTROL", want: ErrUnsafeAccess},
		{name: "no DACL section", sddl: "O:BA", want: ErrUnsafeAccess},
	})
}

// ACE types the checker does not understand are an error, never skipped.
func TestCheckObjectRejectsUnknownACETypes(t *testing.T) {
	for _, typ := range []byte{0x02, 0x03, 0x04, 0x07, 0x08, 0x0d, 0x11, 0x42, 0xff} {
		d := descriptor{owner: sidSystem, hasDACL: true, aces: []ace{{typ: typ, mask: 0, sid: sidSystem}}}
		if err := mustTrust(t).checkObject(d); !errors.Is(err, ErrUnsafeAccess) {
			t.Errorf("type %#x: got %v; want ErrUnsafeAccess", typ, err)
		}
	}
}

// The directory above the private one: it must not let anyone delete or
// rename the directory, but may let users create entries (the %ProgramData%
// default).
func TestCheckParent(t *testing.T) {
	programData := "O:SYD:P(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;CI;0x6;;;BU)(A;OICIIO;GR;;;BU)"
	runCases(t, trustSet.checkParent, []policyCase{
		{name: "ProgramData defaults", sddl: programData},
		{name: "owner is Users", sddl: "O:BUD:P(A;;FA;;;SY)", want: ErrUntrustedOwner},
		{name: "owner is a user", sddl: "O:" + someUser + "D:P(A;;FA;;;SY)", want: ErrUntrustedOwner},
		{name: "owner is TrustedInstaller", sddl: "O:" + sidTrustedInstaller + "D:P(A;;FA;;;SY)"},
		{name: "extra account owns the parent", sddl: "O:" + serviceAccount + "D:P(A;;FA;;;SY)", extras: []string{serviceAccount}},
		{name: "no owner", sddl: "D:P(A;;FA;;;SY)", want: ErrUntrustedOwner},
		{name: "Users create files and subdirectories", sddl: "O:SYD:(A;;0x6;;;BU)"},
		{name: "Users delete child", sddl: "O:SYD:(A;;0x40;;;BU)", want: ErrUnsafeAccess},
		{name: "Users DELETE", sddl: "O:SYD:(A;;0x10000;;;BU)", want: ErrUnsafeAccess},
		{name: "Users WRITE_DAC", sddl: "O:SYD:(A;;WD;;;BU)", want: ErrUnsafeAccess},
		{name: "Users WRITE_OWNER", sddl: "O:SYD:(A;;WO;;;BU)", want: ErrUnsafeAccess},
		{name: "Users full control", sddl: "O:SYD:(A;;FA;;;BU)", want: ErrUnsafeAccess},
		{name: "inherit-only full control does not apply to the parent", sddl: "O:SYD:(A;OICIIO;FA;;;BU)"},
		{name: "object ACE with delete child", sddl: "O:SYD:(OA;;0x40;bf967aba-0de6-11d0-a285-00aa003049f2;;BU)", want: ErrUnsafeAccess},
		{name: "extra account may delete", sddl: "O:SYD:(A;;FA;;;" + serviceAccount + ")", extras: []string{serviceAccount}},
		{name: "TrustedInstaller", sddl: "O:SYD:(A;;FA;;;" + sidTrustedInstaller + ")"},
		{name: "NULL DACL", sddl: "O:SYD:NO_ACCESS_CONTROL", want: ErrUnsafeAccess},
	})

	t.Run("unknown ACE type", func(t *testing.T) {
		d := descriptor{owner: sidSystem, hasDACL: true, aces: []ace{{typ: 0x42}}}
		if err := mustTrust(t).checkParent(d); !errors.Is(err, ErrUnsafeAccess) {
			t.Fatalf("got %v; want ErrUnsafeAccess", err)
		}
	})
}

func TestNewTrustSetValidatesSIDs(t *testing.T) {
	for _, bad := range []string{"", "BA", "S-1-5", "S-1-5-x", "S-2-5-18", "S-1-5-18)(A;;FA;;;WD", "S-1-5--1", "S-1-5-+18", "S-1-5-99999999999"} {
		if _, err := newTrustSet(Options{ExtraTrustedSIDs: []string{bad}}); err == nil {
			t.Errorf("SID %q accepted", bad)
		}
	}

	set, err := newTrustSet(Options{ExtraTrustedSIDs: []string{" s-1-5-80-1-2 ", "S-1-5-80-1-2", sidSystem}})
	if err != nil {
		t.Fatalf("newTrustSet: %v", err)
	}
	if want := []string{"S-1-5-80-1-2"}; !slices.Equal(set.extras, want) {
		t.Errorf("extras = %v; want %v (normalised, deduplicated, built-ins dropped)", set.extras, want)
	}
}

func TestCheckFilesRequiresLocalPaths(t *testing.T) {
	for _, bad := range []string{"", "..", "../x", "a/../../x", "/etc/passwd", "."} {
		if checkFiles([]string{bad}) == nil {
			t.Errorf("file %q accepted", bad)
		}
	}
	if err := checkFiles([]string{"server.key", "keys/server.key"}); err != nil {
		t.Errorf("plain relative paths rejected: %v", err)
	}
}

func rawSID(authority byte, subs ...uint32) []byte {
	b := []byte{1, byte(len(subs) & 0xff), 0, 0, 0, 0, 0, authority}
	for _, s := range subs {
		b = binary.LittleEndian.AppendUint32(b, s)
	}
	return b
}

func rawACE(typ, flags byte, mask uint32, middle, sid []byte) []byte {
	b := []byte{typ, flags, 0, 0}
	b = binary.LittleEndian.AppendUint32(b, mask)
	b = append(b, middle...)
	b = append(b, sid...)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)&0xffff))
	return b
}

// The SID is not at the same offset in every allow type; reading it from the
// wrong place reports a stranger as trusted.
func TestParseACELocatesTheSIDInEveryAllowLayout(t *testing.T) {
	sid := rawSID(5, 32, 545)
	guid := make([]byte, 16)
	flags := func(f uint32) []byte { return binary.LittleEndian.AppendUint32(nil, f) }
	appData := []byte{0xde, 0xad, 0xbe, 0xef}

	tests := []struct {
		name string
		raw  []byte
		want ace
	}{
		{"allowed", rawACE(0x00, 0x03, 0x1f01ff, nil, sid), ace{0x00, 0x03, 0x1f01ff, "S-1-5-32-545"}},
		{"denied", rawACE(0x01, 0, 0x2, nil, sid), ace{0x01, 0, 0x2, "S-1-5-32-545"}},
		{"callback with trailing condition", append(rawACE(0x09, 0, 0x2, nil, sid), appData...), ace{0x09, 0, 0x2, "S-1-5-32-545"}},
		{"object without GUIDs", rawACE(0x05, 0, 0x2, flags(0), sid), ace{0x05, 0, 0x2, "S-1-5-32-545"}},
		{"object with object GUID", rawACE(0x05, 0, 0x2, append(flags(1), guid...), sid), ace{0x05, 0, 0x2, "S-1-5-32-545"}},
		{"object with both GUIDs", rawACE(0x05, 0, 0x2, append(append(flags(3), guid...), guid...), sid), ace{0x05, 0, 0x2, "S-1-5-32-545"}},
		{"object with inherited GUID only", rawACE(0x06, 0, 0x2, append(flags(2), guid...), sid), ace{0x06, 0, 0x2, "S-1-5-32-545"}},
		{"callback object", append(rawACE(0x0b, 0, 0x2, append(flags(1), guid...), sid), appData...), ace{0x0b, 0, 0x2, "S-1-5-32-545"}},
		{"unknown type has no SID", rawACE(0x11, 0, 0x1, nil, sid), ace{typ: 0x11, mask: 0x1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseACE(tc.raw)
			if err != nil {
				t.Fatalf("parseACE: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v; want %+v", got, tc.want)
			}
		})
	}
}

func TestParseACERejectsTruncatedInput(t *testing.T) {
	sid := rawSID(5, 32, 545)
	full := rawACE(0x05, 0, 0x2, binary.LittleEndian.AppendUint32(nil, 3), sid)
	for _, raw := range [][]byte{nil, {0, 0, 4, 0}, full[:11], full[:len(full)-4], rawACE(0x00, 0, 1, nil, sid[:6])} {
		if _, err := parseACE(raw); err == nil {
			t.Errorf("accepted %x", raw)
		}
	}
}
