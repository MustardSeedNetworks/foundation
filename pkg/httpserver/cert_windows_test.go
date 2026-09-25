// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package httpserver_test

import (
	"path/filepath"
	"sort"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/MustardSeedNetworks/foundation/pkg/httpserver"
)

// The Windows half of "the private key is owner-only". Mode bits do not exist
// here -- Stat reports 0666 for any ordinary file whatever os.WriteFile was
// passed -- so the promise is the file's DACL, and this asserts the exact set
// of trustees it grants. Exact, not "no Everyone ACE": a list of the accounts
// that must be absent is a list one can forget an entry from.
func TestEnsureCertificateWritesAnOwnerOnlyKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	if _, err := httpserver.EnsureCertificate(nil, filepath.Join(dir, "server.crt"), keyPath, httpserver.CertOptions{}); err != nil {
		t.Fatalf("EnsureCertificate: %v", err)
	}

	descriptor, infoErr := windows.GetNamedSecurityInfo(
		keyPath,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if infoErr != nil {
		t.Fatalf("read key security info: %v", infoErr)
	}

	control, _, controlErr := descriptor.Control()
	if controlErr != nil {
		t.Fatalf("read descriptor control: %v", controlErr)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("key DACL is not protected; the directory's permissions are still inherited")
	}

	got := grantedTrustees(t, descriptor)
	want := []string{"S-1-5-18", currentUserSID(t)} // SYSTEM and the account that wrote the key
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("key DACL grants %v; want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key DACL grants %v; want exactly %v", got, want)
		}
	}
}

// grantedTrustees returns the sorted SIDs the descriptor's DACL grants access
// to. Any ACE that is not a plain allow is reported as-is rather than skipped,
// so a deny or audit entry appearing here fails the comparison above instead
// of passing unnoticed.
func grantedTrustees(t *testing.T, descriptor *windows.SECURITY_DESCRIPTOR) []string {
	t.Helper()

	dacl, _, daclErr := descriptor.DACL()
	if daclErr != nil {
		t.Fatalf("read key DACL: %v", daclErr)
	}
	if dacl == nil {
		t.Fatal("key has a NULL DACL, which grants everyone full access")
	}

	var trustees []string
	for index := uint32(0); ; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			break // past the last ACE
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			trustees = append(trustees, "non-allow ACE for "+sid.String())
			continue
		}
		trustees = append(trustees, sid.String())
	}
	sort.Strings(trustees)
	return trustees
}

func currentUserSID(t *testing.T) string {
	t.Helper()

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read process token user: %v", err)
	}
	return user.User.Sid.String()
}
