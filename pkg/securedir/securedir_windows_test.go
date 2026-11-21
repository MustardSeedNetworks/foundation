// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package securedir

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"golang.org/x/sys/windows"
)

func currentUserSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read process token user: %v", err)
	}
	return user.User.Sid.String()
}

// userOpts trusts the account running the tests, which is what a developer or
// a service account would add; the runner's own account is not SYSTEM.
func userOpts(t *testing.T) Options {
	t.Helper()
	return Options{ExtraTrustedSIDs: []string{currentUserSID(t)}}
}

// setDACL replaces path's DACL with the one in sddl, protected, as an
// attacker-controlled or legacy setup would have left it.
func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse %q: %v", sddl, err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL of %q: %v", sddl, err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	if err != nil {
		t.Fatalf("set DACL on %s: %v", path, err)
	}
}

func readNamed(t *testing.T, path string) (descriptor, windows.SECURITY_DESCRIPTOR_CONTROL) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read security of %s: %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("read control of %s: %v", path, err)
	}
	d, err := descriptorFrom(sd)
	if err != nil {
		t.Fatalf("decode security of %s: %v", path, err)
	}
	return d, control
}

func grantees(d descriptor) []string {
	var sids []string
	for _, e := range d.aces {
		sids = append(sids, fmt.Sprintf("%#x:%s", e.typ, e.sid))
	}
	sort.Strings(sids)
	return sids
}

func wantGrantees(sids ...string) []string {
	var out []string
	for _, s := range sids {
		out = append(out, "0x0:"+s)
	}
	sort.Strings(out)
	return out
}

func expectErr(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got %v; want %v", got, want)
	}
}

// makeJunction creates link as a junction to target, the unprivileged way to
// plant a reparse point on Windows.
func makeJunction(t *testing.T, link, target string) {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
}

func enablePrivilege(t *testing.T, name string) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer token.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges:     [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}},
	}
	if err := windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil); err != nil {
		t.Fatalf("enable %s: %v", name, err)
	}
}

// squat leaves an existing directory owned by BUILTIN\Users, the way an
// unprivileged user who got there first would own it.
func squat(t *testing.T, path string) {
	t.Helper()
	enablePrivilege(t, "SeRestorePrivilege")
	users, err := windows.StringToSid("S-1-5-32-545")
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, users, nil, nil, nil); err != nil {
		t.Fatalf("hand %s to Users: %v", path, err)
	}
}

func TestEnsureCreatesAProtectedDirectoryAndAncestors(t *testing.T) {
	user := currentUserSID(t)
	leaf := filepath.Join(t.TempDir(), "a", "b", "data")
	if err := Ensure(leaf, userOpts(t)); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, dir := range []string{leaf, filepath.Dir(leaf)} {
		d, control := readNamed(t, dir)
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Errorf("%s: DACL is not protected", dir)
		}
		if got, want := grantees(d), wantGrantees(sidSystem, sidAdministrators, user); !slices.Equal(got, want) {
			t.Errorf("%s grants %v; want exactly %v", dir, got, want)
		}
	}
	if err := Verify(leaf, userOpts(t)); err != nil {
		t.Errorf("Verify of what Ensure made: %v", err)
	}
}

func TestEnsureReplacesTheDACLWholesale(t *testing.T) {
	user := currentUserSID(t)
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+user+")(A;OICI;FA;;;WD)(A;OICI;FA;;;BU)")

	if err := Verify(dir, userOpts(t)); !errors.Is(err, ErrUnsafeAccess) {
		t.Fatalf("Verify before = %v; want ErrUnsafeAccess", err)
	}
	if err := Ensure(dir, userOpts(t)); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	d, _ := readNamed(t, dir)
	if got, want := grantees(d), wantGrantees(sidSystem, sidAdministrators, user); !slices.Equal(got, want) {
		t.Fatalf("after Ensure the directory grants %v; want exactly %v", got, want)
	}
}

func TestSquattedDirectoryIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	squat(t, dir)

	expectErr(t, Ensure(dir, userOpts(t)), ErrUntrustedOwner)
	expectErr(t, Verify(dir, userOpts(t)), ErrUntrustedOwner)
	if d, _ := readNamed(t, dir); d.owner != "S-1-5-32-545" {
		t.Errorf("Ensure re-owned the squatted directory: owner %s", d.owner)
	}
}

func TestVerifyRefusesAnUntrustedOwnerAnywhereInTheTree(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Ensure(dir, userOpts(t)); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	squat(t, inner)

	expectErr(t, Verify(dir, userOpts(t)), ErrUntrustedOwner)
	expectErr(t, Ensure(dir, userOpts(t)), ErrUntrustedOwner)
}

func TestJunctionIsRefused(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := Ensure(real, userOpts(t)); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	makeJunction(t, link, real)

	expectErr(t, Ensure(link, userOpts(t)), ErrReparsePoint)
	expectErr(t, Verify(link, userOpts(t)), ErrReparsePoint)
	expectErr(t, WriteFile(filepath.Join(link, "f"), []byte("x"), userOpts(t)), ErrReparsePoint)
	_, err := OpenFile(filepath.Join(link, "f"), os.O_RDONLY, userOpts(t))
	expectErr(t, err, ErrReparsePoint)
	if _, statErr := os.Stat(filepath.Join(real, "f")); statErr == nil {
		t.Error("a file was written through the junction")
	}
}

func TestJunctionDeepInTheTreeIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Ensure(dir, userOpts(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	makeJunction(t, filepath.Join(dir, "a", "b", "out"), elsewhere)

	expectErr(t, Verify(dir, userOpts(t)), ErrReparsePoint)
	expectErr(t, Ensure(dir, userOpts(t)), ErrReparsePoint)
	if _, err := os.Stat(elsewhere); err != nil {
		t.Errorf("the walk followed the junction: %v", err)
	}
}

func TestVerifyMissingDirectoryFails(t *testing.T) {
	err := Verify(filepath.Join(t.TempDir(), "absent"), userOpts(t))
	expectErr(t, err, fs.ErrNotExist)
}

func TestVerifyRefusesAnUntrustedFileAtAnyDepth(t *testing.T) {
	user := currentUserSID(t)
	loose := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user + ")"
	for _, tc := range []struct{ name, sddlExtra string }{
		{"Everyone write", "(A;;FW;;;WD)"},
		{"Users delete", "(A;;0x10000;;;BU)"},
		{"Users WRITE_DAC", "(A;;WD;;;BU)"},
		{"Users WRITE_OWNER", "(A;;WO;;;BU)"},
		{"Users object ACE with write", "(OA;;FW;bf967aba-0de6-11d0-a285-00aa003049f2;;BU)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			if err := Ensure(dir, userOpts(t)); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "sub", "f")
			if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := Verify(dir, userOpts(t)); err != nil {
				t.Fatalf("Verify before tampering: %v", err)
			}

			setDACL(t, file, loose+tc.sddlExtra)
			expectErr(t, Verify(dir, userOpts(t)), ErrUnsafeAccess)
			expectErr(t, Ensure(dir, userOpts(t)), ErrUnsafeAccess)
		})
	}
}

func TestVerifyFilesMustExist(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Ensure(dir, userOpts(t)); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(filepath.Join(dir, "server.key"), []byte("k"), userOpts(t)); err != nil {
		t.Fatal(err)
	}
	opts := userOpts(t)
	opts.Files = []string{"server.key"}
	if err := Verify(dir, opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	opts.Files = []string{"server.key", "missing.key"}
	expectErr(t, Verify(dir, opts), fs.ErrNotExist)
}

func TestVerifyParentWithDeleteChildFails(t *testing.T) {
	user := currentUserSID(t)
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	base := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user + ")"
	setDACL(t, parent, base)
	dir := filepath.Join(parent, "data")
	if err := Ensure(dir, userOpts(t)); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dir, userOpts(t)); err != nil {
		t.Fatalf("Verify with a trusted-only parent: %v", err)
	}

	setDACL(t, parent, base+"(A;;0x40;;;BU)")
	expectErr(t, Verify(dir, userOpts(t)), ErrUnsafeAccess)

	setDACL(t, parent, base+"(A;;0x6;;;BU)")
	if err := Verify(dir, userOpts(t)); err != nil {
		t.Errorf("a parent that only lets Users create entries must pass: %v", err)
	}
}

// The default %ProgramData% ACL grants Users create rights; an install there
// has to survive Verify or the check is unusable on a real machine.
func TestEnsureThenVerifyUnderProgramData(t *testing.T) {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		t.Skip("ProgramData is not set")
	}
	root, err := os.OpenRoot(programData)
	if err != nil {
		t.Skipf("cannot open %s: %v", programData, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	name := fmt.Sprintf("securedir-test-%d", os.Getpid())
	dir := filepath.Join(programData, name)
	t.Cleanup(func() { _ = root.RemoveAll(name) })

	if err = Ensure(dir, userOpts(t)); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err = WriteFile(filepath.Join(dir, "f"), []byte("x"), userOpts(t)); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err = Verify(dir, userOpts(t)); err != nil {
		t.Fatalf("Verify under %s: %v", programData, err)
	}
}

func TestWriteFileIsPrivateAtomicAndLeavesNoTemp(t *testing.T) {
	user := currentUserSID(t)
	dir := filepath.Join(t.TempDir(), "data")
	if err := Ensure(dir, userOpts(t)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "server.crt")

	for _, content := range []string{"first", "second, longer than the first"} {
		if err := WriteFile(path, []byte(content), userOpts(t)); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != content {
			t.Fatalf("read back %q, %v; want %q", got, err, content)
		}
		d, control := readNamed(t, path)
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Error("file DACL is not protected")
		}
		if got, want := grantees(d), wantGrantees(sidSystem, sidAdministrators, user); !slices.Equal(got, want) {
			t.Errorf("file grants %v; want exactly %v", got, want)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("directory holds %v (%v); want only server.crt", entries, err)
	}
}

func TestOpenFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Ensure(dir, userOpts(t)); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "app.log")
	file, err := OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, userOpts(t))
	if err != nil {
		t.Fatalf("OpenFile create: %v", err)
	}
	if _, err = file.WriteString("one\n"); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	file, err = OpenFile(path, os.O_WRONLY|os.O_APPEND, userOpts(t))
	if err != nil {
		t.Fatalf("OpenFile append: %v", err)
	}
	if _, err = file.WriteString("two\n"); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if got, _ := os.ReadFile(path); string(got) != "one\ntwo\n" {
		t.Errorf("content = %q", got)
	}
	d, _ := readNamed(t, path)
	if got, want := grantees(d), wantGrantees(sidSystem, sidAdministrators, currentUserSID(t)); !slices.Equal(got, want) {
		t.Errorf("created file grants %v; want exactly %v", got, want)
	}

	if _, err = OpenFile(filepath.Join(dir, "absent"), os.O_RDONLY, userOpts(t)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v; want fs.ErrNotExist", err)
	}

	// A junction named like a file is a reparse point and must be refused.
	target := t.TempDir()
	makeJunction(t, filepath.Join(dir, "swapped"), target)
	_, err = OpenFile(filepath.Join(dir, "swapped"), os.O_RDONLY, userOpts(t))
	expectErr(t, err, ErrReparsePoint)
}
