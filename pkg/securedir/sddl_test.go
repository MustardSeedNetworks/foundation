// SPDX-License-Identifier: BUSL-1.1

package securedir

import (
	"strconv"
	"strings"
	"testing"
)

// parseSDDL turns the subset of SDDL the tests use into the policy model. It
// exists because the Windows parser is Windows-only and these tables must run
// everywhere; the Windows build asserts it agrees with the real one
// (TestSDDLModelMatchesWindows).
//
// Supported: O:<sid>, D: with its protection flags, or NO_ACCESS_CONTROL, and ACEs of
// type A, D, OA, OD, XA, XD, ZA, ZD and AU with OI/CI/NP/IO/ID flags, rights
// as aliases or 0x hex, and a SID or alias. A conditional expression after
// the sixth field is ignored.
func parseSDDL(t *testing.T, sddl string) descriptor {
	t.Helper()

	var d descriptor
	rest := sddl
	if after, ok := strings.CutPrefix(rest, "O:"); ok {
		i := strings.Index(after, "D:")
		if i < 0 {
			i = len(after)
		}
		d.owner = sddlSID(t, after[:i])
		rest = after[i:]
	}
	body, ok := strings.CutPrefix(rest, "D:")
	if !ok {
		return d
	}
	if strings.HasPrefix(body, "NO_ACCESS_CONTROL") {
		return d
	}
	d.hasDACL = true
	body = strings.TrimLeft(body, "PAIR") // DACL flags precede the first ACE

	for body != "" {
		if body[0] != '(' {
			t.Fatalf("sddl %q: expected ACE at %q", sddl, body)
		}
		depth, end := 0, -1
		for i, r := range body {
			switch r {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				end = i
				break
			}
		}
		if end < 0 {
			t.Fatalf("sddl %q: unbalanced parentheses", sddl)
		}
		d.aces = append(d.aces, sddlACE(t, body[1:end]))
		body = body[end+1:]
	}
	return d
}

func sddlACE(t *testing.T, s string) ace {
	t.Helper()

	f := strings.SplitN(s, ";", 7)
	if len(f) < 6 {
		t.Fatalf("ACE %q: want 6 fields", s)
	}
	types := map[string]byte{"A": 0, "D": 1, "AU": 2, "OA": 5, "OD": 6, "XA": 9, "XD": 10, "ZA": 11, "ZD": 12}
	typ, ok := types[f[0]]
	if !ok {
		t.Fatalf("ACE %q: unknown type", s)
	}
	return ace{typ: typ, flags: sddlFlags(t, f[1]), mask: sddlRights(t, f[2]), sid: sddlSID(t, f[5])}
}

func sddlFlags(t *testing.T, s string) byte {
	t.Helper()

	table := map[string]byte{"OI": 0x01, "CI": 0x02, "NP": 0x04, "IO": 0x08, "ID": 0x10}
	var flags byte
	for ; s != ""; s = s[2:] {
		bit, ok := table[s[:min(2, len(s))]]
		if !ok {
			t.Fatalf("unknown ACE flag in %q", s)
		}
		flags |= bit
	}
	return flags
}

func sddlRights(t *testing.T, s string) uint32 {
	t.Helper()

	if hex, ok := strings.CutPrefix(s, "0x"); ok {
		v, err := strconv.ParseUint(hex, 16, 32)
		if err != nil {
			t.Fatalf("rights %q: %v", s, err)
		}
		return uint32(v)
	}
	table := map[string]uint32{
		"FA": 0x1f01ff, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200a0,
		"GA": 0x10000000, "GR": 0x80000000, "GW": 0x40000000, "GX": 0x20000000,
		"SD": 0x10000, "RC": 0x20000, "WD": 0x40000, "WO": 0x80000,
	}
	var mask uint32
	for ; s != ""; s = s[2:] {
		bit, ok := table[s[:min(2, len(s))]]
		if !ok {
			t.Fatalf("unknown right in %q", s)
		}
		mask |= bit
	}
	return mask
}

func sddlSID(t *testing.T, s string) string {
	t.Helper()

	aliases := map[string]string{
		"SY": "S-1-5-18", "BA": "S-1-5-32-544", "BU": "S-1-5-32-545", "WD": "S-1-1-0",
		"AU": "S-1-5-11", "CO": "S-1-3-0", "LS": "S-1-5-19", "IU": "S-1-5-4",
	}
	if sid, ok := aliases[s]; ok {
		return sid
	}
	if !strings.HasPrefix(s, "S-1-") {
		t.Fatalf("unknown SID alias %q", s)
	}
	return s
}
