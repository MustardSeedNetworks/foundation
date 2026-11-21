// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package securedir

import (
	"fmt"
	"slices"
	"sort"
	"testing"

	"golang.org/x/sys/windows"
)

// The cross-platform policy tables run on a test-only SDDL parser. This is the
// check that the parser and the real Windows one agree on what each string
// means, so the tables describe the descriptors Windows actually produces.
func TestSDDLModelMatchesWindows(t *testing.T) {
	for _, sddl := range []string{
		"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
		"O:SYD:(A;OICIIO;GA;;;CO)(A;CI;0x6;;;BU)(A;;FR;;;WD)",
		"O:S-1-5-21-1-2-3-1001D:P(A;;FW;;;S-1-5-80-111111111-222222222-333333333-444444444-555555555)",
		"O:BAD:P(D;;FA;;;BU)(A;;FW;;;BU)",
		"O:BAD:P(OA;;FW;bf967aba-0de6-11d0-a285-00aa003049f2;;BU)",
		"O:BAD:P(OA;;FW;bf967aba-0de6-11d0-a285-00aa003049f2;bf967aba-0de6-11d0-a285-00aa003049f3;BU)",
		`O:BAD:P(XA;;FW;;;BU;(@User.Title=="PM"))`,
		`O:BAD:P(ZA;;FW;bf967aba-0de6-11d0-a285-00aa003049f2;;BU;(@User.Title=="PM"))`,
		"O:BAD:P",
		"O:BAD:NO_ACCESS_CONTROL",
	} {
		t.Run(sddl, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(sddl)
			if err != nil {
				t.Fatalf("SecurityDescriptorFromString: %v", err)
			}
			got, err := descriptorFrom(sd)
			if err != nil {
				t.Fatalf("descriptorFrom: %v", err)
			}
			want := parseSDDL(t, sddl)

			if got.owner != want.owner || got.hasDACL != want.hasDACL {
				t.Fatalf("owner/hasDACL = %q/%v; want %q/%v", got.owner, got.hasDACL, want.owner, want.hasDACL)
			}
			order := func(a []ace) []string {
				var s []string
				for _, e := range a {
					s = append(s, fmt.Sprintf("%+v", e))
				}
				sort.Strings(s)
				return s
			}
			if !slices.Equal(order(got.aces), order(want.aces)) {
				t.Fatalf("ACEs = %v; want %v", order(got.aces), order(want.aces))
			}
		})
	}
}
