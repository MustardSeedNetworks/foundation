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
	"strings"
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

// squatLink hands a reparse point itself, not its target, to BUILTIN\Users.
func squatLink(t *testing.T, path string) {
	t.Helper()
	enablePrivilege(t, "SeRestorePrivilege")
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_OWNER, shareNoDelete|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	users, err := windows.StringToSid("S-1-5-32-545")
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, users, nil, nil, nil); err != nil {
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

func TestVerifyRefusesAnUntrustedParentOwner(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "data")
	if err := Ensure(dir, userOpts(t)); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dir, userOpts(t)); err != nil {
		t.Fatalf("Verify before: %v", err)
	}
	squat(t, parent)
	expectErr(t, Verify(dir, userOpts(t)), ErrUntrustedOwner)
}

func TestHardLinksAreRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Ensure(dir, userOpts(t)); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "sub", "app.log")
	if err := os.MkdirAll(filepath.Dir(linked), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, linked); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	expectErr(t, Verify(dir, userOpts(t)), ErrUnsafeAccess)
	expectErr(t, Ensure(dir, userOpts(t)), ErrUnsafeAccess)
	for _, flag := range []int{os.O_RDONLY, os.O_WRONLY | os.O_TRUNC} {
		file, err := OpenFile(linked, flag, userOpts(t))
		if file != nil {
			_ = file.Close()
		}
		expectErr(t, err, ErrUnsafeAccess)
	}
	if got, _ := os.ReadFile(outside); string(got) != "precious" {
		t.Errorf("the other name's content was changed: %q", got)
	}
}

// Ensure applies the protected DACL before it reads the tree, so a tree that is
// refused is still locked down.
func TestEnsureLocksDownBeforeItWalks(t *testing.T) {
	user := currentUserSID(t)
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+user+")(A;OICI;FA;;;WD)")
	child := filepath.Join(dir, "f")
	if err := os.WriteFile(child, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL(t, child, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+user+")(A;;FW;;;WD)")

	expectErr(t, Ensure(dir, userOpts(t)), ErrUnsafeAccess)
	d, _ := readNamed(t, dir)
	if got, want := grantees(d), wantGrantees(sidSystem, sidAdministrators, user); !slices.Equal(got, want) {
		t.Fatalf("a refused take-over left the directory granting %v; want %v", got, want)
	}
}

func windowsAncestorFixture(t *testing.T) (base, grand, data string) {
	t.Helper()
	base = t.TempDir()
	grand = filepath.Join(base, "real")
	data = filepath.Join(grand, "mid", "data")
	if err := Ensure(data, userOpts(t)); err != nil {
		t.Fatal(err)
	}
	return base, grand, data
}

func allEntryPoints(t *testing.T, dir string) map[string]func() error {
	t.Helper()
	opts := userOpts(t)
	return map[string]func() error{
		"Verify":    func() error { return Verify(dir, opts) },
		"WriteFile": func() error { return WriteFile(filepath.Join(dir, "f"), []byte("x"), opts) },
		"OpenFile": func() error {
			file, err := OpenFile(filepath.Join(dir, "f"), os.O_RDONLY, opts)
			if file != nil {
				_ = file.Close()
			}
			return err
		},
	}
}

func TestAncestorTwoLevelsUpWithAnUntrustedOwnerIsRefused(t *testing.T) {
	_, grand, data := windowsAncestorFixture(t)
	for name, call := range allEntryPoints(t, data) {
		if err := call(); errors.Is(err, ErrUntrustedOwner) {
			t.Fatalf("%s refused before the ancestor was handed over: %v", name, err)
		}
	}
	squat(t, grand)
	for name, call := range allEntryPoints(t, data) {
		if err := call(); !errors.Is(err, ErrUntrustedOwner) {
			t.Errorf("%s = %v; want ErrUntrustedOwner", name, err)
		}
	}
}

func TestAncestorTwoLevelsUpWithDeleteChildIsRefused(t *testing.T) {
	user := currentUserSID(t)
	_, grand, data := windowsAncestorFixture(t)
	setDACL(t, grand, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+user+")(A;;0x40;;;BU)")
	for name, call := range allEntryPoints(t, data) {
		if err := call(); !errors.Is(err, ErrUnsafeAccess) {
			t.Errorf("%s = %v; want ErrUnsafeAccess", name, err)
		}
	}
}

func TestAncestorJunctionIsRefused(t *testing.T) {
	base, _, _ := windowsAncestorFixture(t)
	link := filepath.Join(base, "link")
	makeJunction(t, link, filepath.Join(base, "real"))
	for name, call := range allEntryPoints(t, filepath.Join(link, "mid", "data")) {
		if err := call(); !errors.Is(err, ErrReparsePoint) {
			t.Errorf("%s = %v; want ErrReparsePoint", name, err)
		}
	}
}

// After the directory is checked, something tries to move it aside and put a
// junction to an attacker's directory in its place. Either the move is refused
// because the chain is held open, or the operation lands in the directory that
// was checked; it never goes through the junction.
func TestSwapAfterTheCheckDoesNotRedirectTheOperation(t *testing.T) {
	for _, op := range []string{"WriteFile", "OpenFile"} {
		t.Run(op, func(t *testing.T) {
			base := t.TempDir()
			data := filepath.Join(base, "data")
			if err := Ensure(data, userOpts(t)); err != nil {
				t.Fatal(err)
			}
			attacker := filepath.Join(base, "attacker")
			if err := os.Mkdir(attacker, 0o700); err != nil {
				t.Fatal(err)
			}
			moved := filepath.Join(base, "moved")

			landed := data
			afterPin = func() {
				if err := os.Rename(data, moved); err != nil {
					t.Logf("the held directory could not be moved aside: %v", err)
					return
				}
				landed = moved
				makeJunction(t, data, attacker)
			}
			t.Cleanup(func() { afterPin = nil })

			var err error
			switch op {
			case "WriteFile":
				err = WriteFile(filepath.Join(data, "f"), []byte("secret"), userOpts(t))
			case "OpenFile":
				var file *os.File
				if file, err = OpenFile(filepath.Join(data, "f"), os.O_WRONLY|os.O_CREATE, userOpts(t)); err == nil {
					_, err = file.WriteString("secret")
					_ = file.Close()
				}
			}
			if err != nil {
				t.Fatalf("%s: %v", op, err)
			}
			if _, statErr := os.Stat(filepath.Join(landed, "f")); statErr != nil {
				t.Errorf("the file is not in the directory that was checked: %v", statErr)
			}
			if entries, _ := os.ReadDir(attacker); len(entries) != 0 {
				t.Errorf("the operation went through the junction: %v", entries)
			}
		})
	}
}

func TestSwapBeforeTheCallIsRefused(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "data")
	if err := Ensure(data, userOpts(t)); err != nil {
		t.Fatal(err)
	}
	if err := Verify(data, userOpts(t)); err != nil {
		t.Fatal(err)
	}
	attacker := filepath.Join(base, "attacker")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(data, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	makeJunction(t, data, attacker)

	expectErr(t, WriteFile(filepath.Join(data, "f"), []byte("x"), userOpts(t)), ErrReparsePoint)
	if entries, _ := os.ReadDir(attacker); len(entries) != 0 {
		t.Errorf("a file landed in the attacker's directory: %v", entries)
	}
}

func junctionFixture(t *testing.T) (base, real, link string) {
	t.Helper()
	var err error
	if base, err = Canonical(t.TempDir(), userOpts(t)); err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	real = filepath.Join(base, "real")
	if err = os.MkdirAll(filepath.Join(real, "mid"), 0o700); err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(base, "link")
	makeJunction(t, link, real)
	return base, real, link
}

// A junction owned by a trusted principal, in a directory that passes the
// ancestor rules, is followed, and components that do not exist yet are kept.
func TestCanonicalFollowsATrustedJunctionAndKeepsMissingComponents(t *testing.T) {
	_, real, link := junctionFixture(t)
	got, err := Canonical(filepath.Join(link, "mid", "not", "yet"), userOpts(t))
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if want := filepath.Join(real, "mid", "not", "yet"); !strings.EqualFold(got, want) {
		t.Errorf("Canonical = %s; want %s", got, want)
	}
	if err = Ensure(got, userOpts(t)); err != nil {
		t.Errorf("Ensure on the canonical path: %v", err)
	}
}

// With no ExtraTrustedSIDs the account running the tests is not trusted, so a
// junction it created is a link planted by someone untrusted.
func TestCanonicalRefusesAJunctionOwnedByAnUntrustedPrincipal(t *testing.T) {
	_, _, link := junctionFixture(t)
	squatLink(t, link)
	_, err := Canonical(filepath.Join(link, "mid"), userOpts(t))
	expectErr(t, err, ErrReparsePoint)
}

func TestCanonicalRefusesAJunctionInADirectoryOthersCanModify(t *testing.T) {
	base, _, link := junctionFixture(t)
	setDACL(t, base, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+currentUserSID(t)+")(A;;0x40;;;BU)")
	_, err := Canonical(filepath.Join(link, "mid"), userOpts(t))
	expectErr(t, err, ErrUnsafeAccess)
}

func TestEnsureDoesNotCreateThroughAJunctionedAncestor(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	makeJunction(t, link, real)

	expectErr(t, Ensure(filepath.Join(link, "data"), userOpts(t)), ErrReparsePoint)
	if _, err := os.Lstat(filepath.Join(real, "data")); err == nil {
		t.Error("a directory was created through the junction")
	}
}
