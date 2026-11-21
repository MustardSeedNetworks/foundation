// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package securedir

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// object is an open handle on a directory or file together with what was read
// from it. Everything decided about the object is decided from this handle, so
// nothing can be swapped in between the check and the action.
type object struct {
	handle      windows.Handle
	desc        descriptor
	attrs       uint32
	canWriteDAC bool
}

func (o *object) close() { _ = windows.CloseHandle(o.handle) }

func (o *object) isLink() bool { return o.attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 }
func (o *object) isDir() bool  { return o.attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 }

const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

// openObject opens path without following a final link (unless follow) and
// reads its owner, DACL and attributes. With wantWriteDAC it asks for the
// right to replace the DACL, and when that is denied falls back to read-only
// access so a squatted directory still reports its owner instead of a bare
// access error; canWriteDAC says which was obtained.
func openObject(path string, follow, wantWriteDAC bool) (*object, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("securedir: path %q: %w", path, err)
	}
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS)
	if !follow {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}

	access := uint32(windows.READ_CONTROL)
	if wantWriteDAC {
		access |= windows.WRITE_DAC
	}
	canWriteDAC := wantWriteDAC
	handle, err := windows.CreateFile(name, access, shareAll, nil, windows.OPEN_EXISTING, flags, 0)
	if wantWriteDAC && errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		canWriteDAC = false
		handle, err = windows.CreateFile(name, windows.READ_CONTROL, shareAll, nil, windows.OPEN_EXISTING, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("securedir: open %s: %w", path, err)
	}

	obj := &object{handle: handle, canWriteDAC: canWriteDAC}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil {
		obj.close()
		return nil, fmt.Errorf("securedir: stat %s: %w", path, err)
	}
	obj.attrs = info.FileAttributes
	if obj.desc, err = readDescriptor(handle); err != nil {
		obj.close()
		return nil, fmt.Errorf("securedir: read security of %s: %w", path, err)
	}
	return obj, nil
}

func readDescriptor(handle windows.Handle) (descriptor, error) {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return descriptor{}, err
	}
	return descriptorFrom(sd)
}

// descriptorFrom reduces a Windows security descriptor to the policy model.
func descriptorFrom(sd *windows.SECURITY_DESCRIPTOR) (descriptor, error) {
	defer runtime.KeepAlive(sd)

	var d descriptor
	owner, _, err := sd.Owner()
	if err != nil {
		return descriptor{}, err
	}
	if owner != nil {
		d.owner = owner.String()
	}

	acl, _, err := sd.DACL()
	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND):
		return d, nil // no DACL: hasDACL stays false
	case err != nil:
		return descriptor{}, err
	case acl == nil:
		return d, nil // present but NULL: everyone has full access, hasDACL stays false
	}
	d.hasDACL = true

	for i := range uint32(acl.AceCount) {
		var entry *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &entry); err != nil {
			return descriptor{}, err
		}
		raw := unsafe.Slice((*byte)(unsafe.Pointer(entry)), entry.Header.AceSize)
		parsed, parseErr := parseACE(raw)
		if parseErr != nil {
			return descriptor{}, parseErr
		}
		d.aces = append(d.aces, parsed)
	}
	return d, nil
}

// sddl builds the protected descriptor: full control for SYSTEM,
// Administrators and the extra principals, inherited by children when
// container is set, and nothing else. The owner is left to default to the
// creating principal and is checked afterwards, because only a token holding
// Administrators as an owner group may name it explicitly.
func (s trustSet) sddl(container bool) string {
	inherit := ""
	if container {
		inherit = "OICI"
	}
	var b strings.Builder
	b.WriteString("D:P")
	for _, sid := range append([]string{sidSystem, sidAdministrators}, s.extras...) {
		fmt.Fprintf(&b, "(A;%s;FA;;;%s)", inherit, sid)
	}
	return b.String()
}

func (s trustSet) attributes(container bool) (*windows.SecurityAttributes, *windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.SecurityDescriptorFromString(s.sddl(container))
	if err != nil {
		return nil, nil, fmt.Errorf("securedir: build security descriptor: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, sd, nil
}

func ensure(path string, trust trustSet) error {
	if err := createDir(path, trust); err != nil {
		return err
	}

	obj, err := openObject(path, false, true)
	if err != nil {
		return err
	}
	defer obj.close()

	if obj.isLink() {
		return fmt.Errorf("%w: %s", ErrReparsePoint, path)
	}
	if !obj.isDir() {
		return fmt.Errorf("securedir: %s is not a directory", path)
	}
	if err = trust.checkOwner(obj.desc); err != nil {
		return fmt.Errorf("%w (%s)", err, path)
	}
	if err = walkTree(path, trust); err != nil {
		return fmt.Errorf("refusing to take over %s: %w", path, err)
	}
	if !obj.canWriteDAC {
		return fmt.Errorf("securedir: cannot replace the access control of %s: %w", path, windows.ERROR_ACCESS_DENIED)
	}

	sd, err := windows.SecurityDescriptorFromString(trust.sddl(true))
	if err != nil {
		return fmt.Errorf("securedir: build security descriptor: %w", err)
	}
	defer runtime.KeepAlive(sd)
	acl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("securedir: build DACL: %w", err)
	}
	err = windows.SetSecurityInfo(obj.handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
	if err != nil {
		return fmt.Errorf("securedir: set access control of %s: %w", path, err)
	}
	return nil
}

// createDir creates path with the protected descriptor in the same call, and
// any missing ancestors the same way. An existing path is not an error here;
// ensure inspects what is there.
func createDir(path string, trust trustSet) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("securedir: path %q: %w", path, err)
	}
	attrs, sd, err := trust.attributes(true)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(sd)

	err = windows.CreateDirectory(name, attrs)
	if errors.Is(err, windows.ERROR_PATH_NOT_FOUND) && filepath.Dir(path) != path {
		if err = createDir(filepath.Dir(path), trust); err != nil {
			return err
		}
		err = windows.CreateDirectory(name, attrs)
	}
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("securedir: create %s: %w", path, err)
	}
	return nil
}

func verify(path string, files []string, trust trustSet) error {
	dir, err := openObject(path, false, false)
	if err != nil {
		return err
	}
	defer dir.close()
	if err = checkOne(path, dir, true, trust); err != nil {
		return err
	}

	// The parent is opened following links: what matters is the directory the
	// path really lives in.
	parent, err := openObject(filepath.Dir(path), true, false)
	if err != nil {
		return err
	}
	defer parent.close()
	if err = trust.checkParent(parent.desc); err != nil {
		return fmt.Errorf("parent of %s: %w", path, err)
	}

	if err = walkTree(path, trust); err != nil {
		return err
	}
	for _, rel := range files {
		if err = verifyFile(path, rel, trust); err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
	}
	return nil
}

func checkOne(path string, obj *object, wantDir bool, trust trustSet) error {
	if obj.isLink() {
		return fmt.Errorf("%w: %s", ErrReparsePoint, path)
	}
	if obj.isDir() != wantDir {
		return fmt.Errorf("securedir: %s has the wrong type for a private directory entry", path)
	}
	if err := trust.checkObject(obj.desc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// verifyFile checks every component of rel under dir, so a subdirectory
// replaced by a junction is caught as well as the file.
func verifyFile(dir, rel string, trust trustSet) error {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i := range parts {
		name := filepath.Join(append([]string{dir}, parts[:i+1]...)...)
		obj, err := openObject(name, false, false)
		if err != nil {
			return err
		}
		err = checkOne(name, obj, i < len(parts)-1, trust)
		obj.close()
		if err != nil {
			return err
		}
	}
	return nil
}

func writeFile(path string, data []byte, trust trustSet) error {
	dir, base := filepath.Split(path)
	dir = filepath.Clean(dir)

	holder, err := openObject(dir, false, false)
	if err != nil {
		return err
	}
	defer holder.close()
	if holder.isLink() || !holder.isDir() {
		return fmt.Errorf("%w: %s is not a plain directory", ErrReparsePoint, dir)
	}

	suffix := make([]byte, 8)
	if _, err = rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+base+".tmp-"+hex.EncodeToString(suffix))

	if err = createPrivateFile(tmp, data, trust); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	if err != nil {
		removeFile(tmp)
		return fmt.Errorf("securedir: replace %s: %w", path, err)
	}
	return nil
}

// createPrivateFile creates path with the protected descriptor attached at
// creation: CREATE_NEW, because CreateFile ignores the descriptor for a file
// that already exists, and no sharing so nobody else holds it open.
func createPrivateFile(path string, data []byte, trust trustSet) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("securedir: path %q: %w", path, err)
	}
	attrs, sd, err := trust.attributes(false)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(sd)

	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, attrs,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("securedir: create %s: %w", path, err)
	}
	file := os.NewFile(uintptr(handle), path)
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		removeFile(path)
		return fmt.Errorf("securedir: write %s: %w", path, err)
	}
	return nil
}

// walkTree checks everything under dir at any depth with the same rules as the
// directory itself. Each entry is opened without following links and judged
// from its own handle; a link is reported and not entered.
func walkTree(dir string, trust trustSet) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		obj, err := openObject(path, false, false)
		if err != nil {
			return err
		}
		isDir := obj.isDir() && !obj.isLink()
		err = checkOne(path, obj, obj.isDir(), trust)
		obj.close()
		if err != nil {
			return err
		}
		if isDir {
			if err = walkTree(path, trust); err != nil {
				return err
			}
		}
	}
	return nil
}

func openFile(path string, flag int, trust trustSet) (*os.File, error) {
	dir, base := filepath.Split(path)
	dir = filepath.Clean(dir)

	holder, err := openObject(dir, false, false)
	if err != nil {
		return nil, err
	}
	defer holder.close()
	if holder.isLink() || !holder.isDir() {
		return nil, fmt.Errorf("%w: %s is not a plain directory", ErrReparsePoint, dir)
	}

	access := uint32(windows.GENERIC_READ)
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_WRONLY:
		access = windows.GENERIC_WRITE
	case os.O_RDWR:
		access = windows.GENERIC_READ | windows.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		access = access&^windows.GENERIC_WRITE | windows.FILE_APPEND_DATA
	}
	var disposition uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		disposition = windows.CREATE_NEW
	case flag&(os.O_CREATE|os.O_TRUNC) == os.O_CREATE|os.O_TRUNC:
		disposition = windows.CREATE_ALWAYS
	case flag&os.O_CREATE != 0:
		disposition = windows.OPEN_ALWAYS
	case flag&os.O_TRUNC != 0:
		disposition = windows.TRUNCATE_EXISTING
	default:
		disposition = windows.OPEN_EXISTING
	}

	name, err := windows.UTF16PtrFromString(filepath.Join(dir, base))
	if err != nil {
		return nil, fmt.Errorf("securedir: path %q: %w", path, err)
	}
	attrs, sd, err := trust.attributes(false)
	if err != nil {
		return nil, err
	}
	defer runtime.KeepAlive(sd)

	handle, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		attrs, disposition, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("securedir: open %s: %w", path, err)
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("securedir: stat %s: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("%w: %s", ErrReparsePoint, path)
	}
	return os.NewFile(uintptr(handle), path), nil
}

// removeFile is best-effort cleanup of a temporary file after a failed write;
// the error that got us here is the one worth reporting.
func removeFile(path string) {
	if name, err := windows.UTF16PtrFromString(path); err == nil {
		_ = windows.DeleteFile(name)
	}
}
