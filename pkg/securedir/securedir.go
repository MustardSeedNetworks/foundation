// SPDX-License-Identifier: BUSL-1.1

// Package securedir creates, checks and writes into private directories for
// daemons that run as a privileged account (LocalSystem or a service account
// on Windows, root on unix) and keep their state in a machine-wide location
// such as %ProgramData%.
//
// Every function fails closed: a path it cannot positively show to be private
// is an error, never a warning. The holes it exists to close are the ones that
// keep recurring in per-product copies of this code: a pre-existing directory
// squatted by an unprivileged user, an ACL edit that adds trustees without
// removing the squatter's, a directory created without any descriptor, a
// junction or symlink swapped in for the directory, a validator that skips ACE
// types it does not recognise, and a parent directory nobody looked at.
//
// A directory is private when it is owned by a trusted principal, is not a
// link, and nobody outside the trusted set can write, delete or re-ACL it.
// The trusted set on Windows is SYSTEM, BUILTIN\Administrators and
// NT SERVICE\TrustedInstaller plus Options.ExtraTrustedSIDs; on unix it is
// root and the effective user.
//
// Ensure is for the installer or first start, which holds the privilege to
// take over a directory. Verify is for service start, where the process only
// needs to know the directory is still safe to trust. WriteFile is the only
// write path, so a file never exists under a looser descriptor than the one
// it will keep.
package securedir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	// ErrUntrustedOwner means the path is owned by a principal outside the
	// trusted set. The owner can always rewrite the ACL, so no ACL can make
	// such a path private; it has to be removed and recreated.
	ErrUntrustedOwner = errors.New("securedir: owner is not trusted")

	// ErrReparsePoint means the path is a symbolic link, junction or other
	// reparse point. Following it would act on whatever it currently points at.
	ErrReparsePoint = errors.New("securedir: path is a link or reparse point")

	// ErrUnsafeAccess means a principal outside the trusted set can modify the
	// path, or its access control could not be shown to be safe: a NULL DACL,
	// or an ACE of a type this package does not understand.
	ErrUnsafeAccess = errors.New("securedir: access is not restricted to trusted principals")
)

// Options tunes what counts as trusted and what Verify checks.
type Options struct {
	// ExtraTrustedSIDs are additional principals, as SID strings such as
	// "S-1-5-80-...", that may own and have full access to the directory and
	// its files: typically the service's virtual account. Ensure and WriteFile
	// grant them full control; Verify accepts them. Windows only; validated
	// everywhere but unused on unix.
	ExtraTrustedSIDs []string

	// ExcludeAdministrators leaves BUILTIN\Administrators out of the DACL of
	// files WriteFile and OpenFile create, so only SYSTEM and ExtraTrustedSIDs
	// can read them: for a private key that the service account alone should
	// hold. Windows only; directories are unaffected.
	ExcludeAdministrators bool

	// Files are paths relative to the directory that Verify requires to exist.
	// They get no extra scrutiny, since Verify already walks everything under
	// the directory; this is the assertion that the expected files are there.
	// Ignored by Ensure, WriteFile and OpenFile.
	Files []string
}

// Well-known trusted principals.
const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
	// NT SERVICE\TrustedInstaller owns and writes much of the system tree,
	// parents of data directories included.
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// trustSet is the validated, normalised principal set derived from Options.
type trustSet struct {
	trusted map[string]struct{}
	noAdmin bool
	// extras are the caller's additions, in order, deduplicated; they are what
	// Ensure and WriteFile grant beyond SYSTEM and Administrators.
	extras []string
}

func newTrustSet(opts Options) (trustSet, error) {
	set := trustSet{trusted: map[string]struct{}{
		sidSystem:           {},
		sidAdministrators:   {},
		sidTrustedInstaller: {},
	}}
	set.noAdmin = opts.ExcludeAdministrators
	for _, raw := range opts.ExtraTrustedSIDs {
		sid := strings.ToUpper(strings.TrimSpace(raw))
		if !validSID(sid) {
			return trustSet{}, fmt.Errorf("securedir: invalid trusted SID %q", raw)
		}
		if _, dup := set.trusted[sid]; dup {
			continue
		}
		set.trusted[sid] = struct{}{}
		set.extras = append(set.extras, sid)
	}
	return set, nil
}

func (s trustSet) has(sid string) bool {
	_, ok := s.trusted[sid]
	return ok
}

// validSID accepts "S-1-<authority>-<sub>[-<sub>...]" with every component a
// decimal number. It exists so a value from configuration cannot smuggle SDDL
// syntax into the descriptor string built from it.
func validSID(s string) bool {
	rest, ok := strings.CutPrefix(s, "S-1-")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "-")
	if len(parts) < 2 || len(parts) > 16 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.ParseUint(p, 10, 32); err != nil || p == "" || p[0] == '+' {
			return false
		}
	}
	return true
}

// afterPin, when set by a test, runs once the directory has been opened and
// checked and before the file operation that uses it. It is how the tests
// swap the path for a link at the worst moment and show the operation still
// lands in the directory that was checked.
var afterPin func()

// plainName reports whether name is a single path element that can be created
// or opened inside a directory.
func plainName(name string) error {
	if !filepath.IsLocal(name) || filepath.Base(name) != name {
		return fmt.Errorf("securedir: %q is not a plain file name", name)
	}
	return nil
}

func requireAbs(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("securedir: path %q is not absolute", path)
	}
	return nil
}

// checkFiles validates Options.Files entries before any filesystem access.
func checkFiles(files []string) error {
	for _, rel := range files {
		if !filepath.IsLocal(rel) || filepath.Clean(rel) == "." {
			return fmt.Errorf("securedir: file %q is not a plain relative path inside the directory", rel)
		}
	}
	return nil
}

// Canonical returns the real absolute path for path, with every link in it
// resolved. The other functions here never follow a link: a link anywhere in
// the path they are given, at any depth, is an [ErrReparsePoint]. A product
// therefore calls Canonical once at startup and passes the result to Ensure,
// Verify, WriteFile and OpenFile.
//
// Canonical does not use the standard library's link resolver. It walks the path one component at a time
// from the root (the volume root on Windows). Every directory it passes through
// must have a trusted owner and grant nobody untrusted the right to delete,
// rename or re-ACL what is inside it (the ancestor rules of [Verify]), so the
// directory it is about to look into is one a user could not have tampered
// with. A link is followed only when the link itself is owned by root (on
// Windows SYSTEM, Administrators, TrustedInstaller or an ExtraTrustedSIDs
// entry) and the directory holding it passed that check; that is what lets the
// macOS /var and /tmp links through while a link an unprivileged user planted
// is refused with [ErrReparsePoint]. The final component is not required to
// pass the ancestor rules, since [Ensure] and [Verify] judge it. Components
// that do not exist yet are kept as written, so it can be used before Ensure
// creates them.
//
// The path must be absolute.
func Canonical(path string, opts Options) (string, error) {
	trust, err := newTrustSet(opts)
	if err != nil {
		return "", err
	}
	if err = requireAbs(path); err != nil {
		return "", err
	}
	return canonical(filepath.Clean(path), trust)
}

// Ensure makes path an existing private directory.
//
// A missing directory is created together with any missing ancestors, each
// with a complete protected descriptor set at creation, so there is no moment
// at which it exists under an inherited or default ACL. An existing directory
// is refused with [ErrReparsePoint] or [ErrUntrustedOwner] when it is a link
// or owned by someone outside the trusted set, and so is one with anything
// under it that Verify would refuse: it is not taken over and re-owned over
// content that was never trusted. Otherwise its access control is
// replaced wholesale, not merged, through a handle that was checked, so a
// squatter's entries do not survive and there is no path-based window between
// the check and the change.
//
// Ancestors that already exist are not modified; Verify is what looks at the
// parent. The path must be absolute.
func Ensure(path string, opts Options) error {
	trust, err := newTrustSet(opts)
	if err != nil {
		return err
	}
	if err := requireAbs(path); err != nil {
		return err
	}
	return ensure(filepath.Clean(path), trust)
}

// Verify reports whether path is a private directory that is safe to trust,
// and fails closed when it cannot tell: a missing directory, an owner outside
// the trusted set, a link, a NULL DACL, an ACE of an unknown type, or an
// untrusted principal holding write, delete, delete-child, change-permissions
// or take-ownership access are all errors. The parent directory is checked
// too: it must not let untrusted principals delete or rename the directory.
// Creating new entries in the parent is allowed, because a shared parent such
// as %ProgramData% grants that to every user by default and it cannot replace
// a directory that already exists. Everything under the directory, at any
// depth, is walked without following links and must be a plain file or
// directory with a trusted owner and no untrusted write, delete or
// change-permissions grant. Options.Files are then required to exist.
//
// Verify never modifies anything. The path must be absolute.
func Verify(path string, opts Options) error {
	trust, err := newTrustSet(opts)
	if err != nil {
		return err
	}
	if err := requireAbs(path); err != nil {
		return err
	}
	if err := checkFiles(opts.Files); err != nil {
		return err
	}
	return verify(filepath.Clean(path), opts.Files, trust)
}

// WriteFile atomically writes data to path, which must be a plain file name
// inside an existing directory: a temporary file is created next to it with
// owner-only access already in place, filled, flushed and renamed over the
// target. A reader sees the old content or the new, never a partial file, and
// the data is never readable by an untrusted principal, even briefly.
//
// The directory and every ancestor above it are checked the way [Verify]
// checks them, and the write goes through the handle that was checked, never
// back through the path. The path must be absolute.
func WriteFile(path string, data []byte, opts Options) error {
	trust, err := newTrustSet(opts)
	if err != nil {
		return err
	}
	if err := requireAbs(path); err != nil {
		return err
	}
	return writeFile(filepath.Clean(path), data, trust)
}

// OpenFile opens a file directly inside a private directory and refuses a
// symbolic link or reparse point at the file, with [ErrReparsePoint], rather
// than following it: O_NOFOLLOW on unix, FILE_FLAG_OPEN_REPARSE_POINT on
// Windows. Use it for log and configuration files that something less trusted
// than the service might have replaced. A file it creates is owner-only (0600,
// or a protected descriptor granting the trusted set), with the descriptor
// attached at creation. flag takes the usual os.O_* values.
//
// The directory and its ancestors are checked as in [WriteFile], and the open
// goes through the handle that was checked. The path must be absolute and name
// a file directly inside the directory.
func OpenFile(path string, flag int, opts Options) (*os.File, error) {
	trust, err := newTrustSet(opts)
	if err != nil {
		return nil, err
	}
	if err := requireAbs(path); err != nil {
		return nil, err
	}
	return openFile(filepath.Clean(path), flag, trust)
}
