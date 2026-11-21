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
	"unicode/utf16"
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
	links       uint32
	canWriteDAC bool
}

func (o *object) close() { _ = windows.CloseHandle(o.handle) }

func (o *object) isLink() bool { return o.attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 }
func (o *object) isDir() bool  { return o.attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 }

// share modes never include FILE_SHARE_DELETE for a directory in a held chain:
// a directory with a handle open on it cannot be renamed or removed, which is
// what stops an ancestor being swapped for a junction while an operation runs.
const (
	shareNoDelete = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
	dirAccess     = windows.READ_CONTROL | windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
)

// ntOpen opens name relative to parent through NtCreateFile with
// FILE_OPEN_REPARSE_POINT, so the object itself is opened and a link is never
// followed, and nothing is resolved from a full path. The result is an NT
// status turned into the errno callers can match with errors.Is.
func ntOpen(parent windows.Handle, name string, access, share, disposition, options uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, fmt.Errorf("securedir: name %q: %w", name, err)
	}
	attrs := windows.OBJECT_ATTRIBUTES{
		RootDirectory:      parent,
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE,
		SecurityDescriptor: sd,
	}
	attrs.Length = uint32(unsafe.Sizeof(attrs))

	var (
		handle windows.Handle
		iosb   windows.IO_STATUS_BLOCK
	)
	status := windows.NtCreateFile(&handle, access|windows.SYNCHRONIZE, &attrs, &iosb, nil,
		windows.FILE_ATTRIBUTE_NORMAL, share, disposition,
		options|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	runtime.KeepAlive(objectName)
	runtime.KeepAlive(sd)
	if status != nil {
		var ntStatus windows.NTStatus
		if errors.As(status, &ntStatus) {
			return 0, ntStatus.Errno()
		}
		return 0, status
	}
	return handle, nil
}

// describe reads the attributes, link count, owner and DACL of an open handle.
func describe(handle windows.Handle) (*object, error) {
	obj := &object{handle: handle, canWriteDAC: true}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	obj.attrs = info.FileAttributes
	obj.links = info.NumberOfLinks
	var err error
	if obj.desc, err = readDescriptor(handle); err != nil {
		return nil, fmt.Errorf("read security: %w", err)
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

// chain is a directory opened by walking from the volume root, with a handle
// held on every component. leaf is the directory itself.
type chain struct {
	handles []windows.Handle
	leaf    *object
}

func (c *chain) close() {
	for _, h := range c.handles {
		_ = windows.CloseHandle(h)
	}
	if c.leaf != nil {
		c.leaf.close()
	}
}

// openChain opens path as a directory component by component from the volume
// root, each one relative to the handle for the one above and none following a
// link, and keeps every handle open until close. A reparse point anywhere in
// the chain is refused. With strict, every ancestor must also have a trusted
// owner and grant no untrusted delete or permission-change rights (see
// checkParent); Ensure passes false because it is the step that builds the
// chain. With wantWriteDAC the leaf is opened for replacing its DACL, falling
// back to read-only so an untrusted owner is still reported as such;
// canWriteDAC says which was obtained.
func openChain(path string, strict, wantWriteDAC bool, trust trustSet) (*chain, error) {
	volume := filepath.VolumeName(path)
	rootPath := volume + `\`
	rootName, err := windows.UTF16PtrFromString(rootPath)
	if err != nil {
		return nil, fmt.Errorf("securedir: path %q: %w", path, err)
	}
	root, err := windows.CreateFile(rootName, windows.READ_CONTROL|windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		shareNoDelete, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("securedir: open %s: %w", rootPath, err)
	}

	c := &chain{handles: []windows.Handle{root}}
	var parts []string
	for _, p := range strings.Split(strings.TrimPrefix(path[len(volume):], `\`), `\`) {
		if p != "" {
			parts = append(parts, p)
		}
	}

	walked := rootPath
	current := root
	for i := -1; i < len(parts); i++ {
		last := i == len(parts)-1
		if i >= 0 {
			walked = filepath.Join(walked, parts[i])
			access := uint32(dirAccess)
			if last && wantWriteDAC {
				access |= windows.WRITE_DAC
			}
			handle, openErr := ntOpen(current, parts[i], access, shareNoDelete, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
			if openErr != nil && last && wantWriteDAC && errors.Is(openErr, windows.ERROR_ACCESS_DENIED) {
				handle, openErr = ntOpen(current, parts[i], dirAccess, shareNoDelete, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
				wantWriteDAC = false
			}
			if openErr != nil {
				c.close()
				return nil, fmt.Errorf("securedir: open %s: %w", walked, openErr)
			}
			current = handle
		}

		obj, describeErr := describe(current)
		if describeErr != nil {
			if current != root || i >= 0 {
				c.handles = append(c.handles, current)
			}
			c.close()
			return nil, fmt.Errorf("securedir: %s: %w", walked, describeErr)
		}
		obj.canWriteDAC = wantWriteDAC
		if i >= 0 && obj.isLink() {
			c.handles = append(c.handles, current)
			c.close()
			return nil, fmt.Errorf("%w: %s", ErrReparsePoint, walked)
		}
		if last {
			c.leaf = obj
			if i < 0 {
				c.handles = c.handles[:0] // the root is the leaf; the object owns the handle
			}
			return c, nil
		}
		if i >= 0 {
			c.handles = append(c.handles, current)
		}
		if strict {
			if err = trust.checkParent(obj.desc); err != nil {
				c.close()
				return nil, fmt.Errorf("ancestor %s: %w", walked, err)
			}
		}
	}
	return c, nil
}

const maxLinkHops = 40

func canonical(path string, trust trustSet) (string, error) {
	for range maxLinkHops {
		resolved, link, rest, err := canonicalOnce(path, trust)
		if err != nil {
			return "", err
		}
		if link == "" {
			return resolved, nil
		}
		// The link is one we may follow, and everything above it was walked
		// without following anything; EvalSymlinks only resolves the link.
		target, err := filepath.EvalSymlinks(link)
		if err != nil {
			return "", fmt.Errorf("securedir: resolve %s: %w", link, err)
		}
		path = filepath.Join(target, rest)
	}
	return "", fmt.Errorf("%w: too many levels of links in %s", ErrReparsePoint, path)
}

// canonicalOnce walks path from the volume root with a handle on each
// directory, opening every child relative to it without following links. It
// returns the resolved path, or a link it may follow with the rest of the path
// below it.
func canonicalOnce(path string, trust trustSet) (resolved, link, rest string, err error) {
	volume := filepath.VolumeName(path)
	rootPath := volume + `\`
	rootName, err := windows.UTF16PtrFromString(rootPath)
	if err != nil {
		return "", "", "", fmt.Errorf("securedir: path %q: %w", path, err)
	}
	current, err := windows.CreateFile(rootName, windows.READ_CONTROL|windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		shareNoDelete|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", "", "", fmt.Errorf("securedir: open %s: %w", rootPath, err)
	}
	defer func() { _ = windows.CloseHandle(current) }()

	var parts []string
	for _, p := range strings.Split(strings.TrimPrefix(path[len(volume):], `\`), `\`) {
		if p != "" {
			parts = append(parts, p)
		}
	}
	walked := rootPath
	for i, name := range parts {
		holder, err := describe(current)
		if err != nil {
			return "", "", "", fmt.Errorf("securedir: %s: %w", walked, err)
		}
		if err = trust.checkParent(holder.desc); err != nil {
			return "", "", "", fmt.Errorf("ancestor %s: %w", walked, err)
		}
		handle, err := ntOpen(current, name, dirAccess, shareNoDelete|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, 0, nil)
		if errors.Is(err, os.ErrNotExist) {
			return filepath.Join(append([]string{walked}, parts[i:]...)...), "", "", nil
		}
		if err != nil {
			return "", "", "", fmt.Errorf("securedir: open %s: %w", filepath.Join(walked, name), err)
		}
		child, err := describe(handle)
		if err != nil {
			_ = windows.CloseHandle(handle)
			return "", "", "", fmt.Errorf("securedir: %s: %w", filepath.Join(walked, name), err)
		}
		switch {
		case child.isLink():
			ownerErr := trust.checkOwner(child.desc)
			_ = windows.CloseHandle(handle)
			if ownerErr != nil {
				return "", "", "", fmt.Errorf("%w: %s is a link not owned by a trusted principal", ErrReparsePoint, filepath.Join(walked, name))
			}
			return "", filepath.Join(walked, name), filepath.Join(parts[i+1:]...), nil
		case !child.isDir() && i < len(parts)-1:
			_ = windows.CloseHandle(handle)
			return "", "", "", fmt.Errorf("securedir: %s is not a directory", filepath.Join(walked, name))
		}
		_ = windows.CloseHandle(current)
		current = handle
		walked = filepath.Join(walked, name)
	}
	return walked, "", "", nil
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
	grantees := append([]string{sidSystem, sidAdministrators}, s.extras...)
	if s.noAdmin && !container {
		grantees = append([]string{sidSystem}, s.extras...)
	}
	for _, sid := range grantees {
		fmt.Fprintf(&b, "(A;%s;FA;;;%s)", inherit, sid)
	}
	return b.String()
}

func (s trustSet) descriptor(container bool) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.SecurityDescriptorFromString(s.sddl(container))
	if err != nil {
		return nil, fmt.Errorf("securedir: build security descriptor: %w", err)
	}
	return sd, nil
}

func ensure(path string, trust trustSet) error {
	if err := createDir(path, trust); err != nil {
		return err
	}

	c, err := openChain(path, false, true, trust)
	if err != nil {
		return err
	}
	defer c.close()
	obj := c.leaf

	if obj.isLink() {
		return fmt.Errorf("%w: %s", ErrReparsePoint, path)
	}
	if !obj.isDir() {
		return fmt.Errorf("securedir: %s is not a directory", path)
	}
	if err = trust.checkOwner(obj.desc); err != nil {
		return fmt.Errorf("%w (%s)", err, path)
	}
	if !obj.canWriteDAC {
		return fmt.Errorf("securedir: cannot replace the access control of %s: %w", path, windows.ERROR_ACCESS_DENIED)
	}

	sd, err := trust.descriptor(true)
	if err != nil {
		return err
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
	// Locked down first, then judged: while the tree was being read nobody
	// else could add to it. A tree that fails is reported but stays locked.
	if err = walkTree(obj.handle, path, trust); err != nil {
		return fmt.Errorf("refusing to trust the contents of %s: %w", path, err)
	}
	return nil
}

// createDir creates path with the protected descriptor in the same call,
// relative to the held handle of its parent so no link in the path is followed,
// and any missing ancestors the same way. An existing path is not an error
// here; ensure inspects what is there.
func createDir(path string, trust trustSet) error {
	parent := filepath.Dir(path)
	held, err := openChain(parent, false, false, trust)
	if errors.Is(err, os.ErrNotExist) && parent != path {
		if err = createDir(parent, trust); err != nil {
			return err
		}
		held, err = openChain(parent, false, false, trust)
	}
	if err != nil {
		return err
	}
	defer held.close()

	sd, err := trust.descriptor(true)
	if err != nil {
		return err
	}
	handle, err := ntOpen(held.leaf.handle, filepath.Base(path), windows.READ_CONTROL, shareNoDelete|windows.FILE_SHARE_DELETE,
		windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE, sd)
	if err == nil {
		return windows.CloseHandle(handle)
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil
	}
	return fmt.Errorf("securedir: create %s: %w", path, err)
}

func verify(path string, files []string, trust trustSet) error {
	c, err := openChain(path, true, false, trust)
	if err != nil {
		return err
	}
	defer c.close()
	if err = checkOne(path, c.leaf, true, trust); err != nil {
		return err
	}
	if err = walkTree(c.leaf.handle, path, trust); err != nil {
		return err
	}
	for _, rel := range files {
		if err = existsRelative(c.leaf.handle, rel); err != nil {
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
	if !wantDir && obj.links > 1 {
		return fmt.Errorf("%w: %s has %d hard links", ErrUnsafeAccess, path, obj.links)
	}
	if err := trust.checkObject(obj.desc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// existsRelative opens each component of rel below dir, without following
// links, to show it exists.
func existsRelative(dir windows.Handle, rel string) error {
	current := dir
	for _, name := range strings.Split(filepath.ToSlash(rel), "/") {
		handle, err := ntOpen(current, name, windows.READ_CONTROL, shareNoDelete|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, 0, nil)
		if current != dir {
			_ = windows.CloseHandle(current)
		}
		if err != nil {
			return err
		}
		current = handle
	}
	if current != dir {
		_ = windows.CloseHandle(current)
	}
	return nil
}

// walkTree checks everything under dir at any depth with the same rules as the
// directory itself. Names come from a listing; each entry is then opened
// relative to the handle of its directory, without following links, and judged
// from its own handle. A link is reported and not entered.
func walkTree(dir windows.Handle, path string, trust trustSet) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		handle, err := ntOpen(dir, entry.Name(), windows.READ_CONTROL|windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES,
			shareNoDelete|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, 0, nil)
		if err != nil {
			return fmt.Errorf("securedir: open %s: %w", child, err)
		}
		obj, err := describe(handle)
		if err != nil {
			_ = windows.CloseHandle(handle)
			return fmt.Errorf("securedir: %s: %w", child, err)
		}
		err = checkOne(child, obj, obj.isDir(), trust)
		if err == nil && obj.isDir() && !obj.isLink() {
			err = walkTree(handle, child, trust)
		}
		_ = windows.CloseHandle(handle)
		if err != nil {
			return err
		}
	}
	return nil
}

// pinDir opens and checks the directory a file operation will use, and calls
// the test hook.
func pinDir(dir string, trust trustSet) (*chain, error) {
	c, err := openChain(dir, true, false, trust)
	if err != nil {
		return nil, err
	}
	if err = checkOne(dir, c.leaf, true, trust); err != nil {
		c.close()
		return nil, err
	}
	if afterPin != nil {
		afterPin()
	}
	return c, nil
}

// fileRenameInformation is FILE_RENAME_INFORMATION from the WDK, which
// x/sys/windows does not define. RootDirectory makes FileName relative to a
// directory handle instead of a full path.
type fileRenameInformation struct {
	ReplaceIfExists byte
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

// renameInto renames the open file to name inside dir, replacing any existing
// file, relative to the dir handle.
func renameInto(file windows.Handle, dir windows.Handle, name string) error {
	units := utf16.Encode([]rune(name))
	size := int(unsafe.Offsetof(fileRenameInformation{}.FileName)) + 2*len(units)
	buf := make([]byte, max(size, int(unsafe.Sizeof(fileRenameInformation{}))))
	info := (*fileRenameInformation)(unsafe.Pointer(&buf[0]))
	info.ReplaceIfExists = 1
	info.RootDirectory = dir
	info.FileNameLength = uint32(2 * len(units) & 0xffff)
	copy(unsafe.Slice(&info.FileName[0], len(units)), units)

	var iosb windows.IO_STATUS_BLOCK
	status := windows.NtSetInformationFile(file, &iosb, &buf[0], uint32(len(buf)&0xffff), windows.FileRenameInformation)
	if status != nil {
		var ntStatus windows.NTStatus
		if errors.As(status, &ntStatus) {
			return ntStatus.Errno()
		}
		return status
	}
	return nil
}

func writeFile(path string, data []byte, trust trustSet) error {
	dir, base := filepath.Split(path)
	if err := plainName(base); err != nil {
		return err
	}
	c, err := pinDir(filepath.Clean(dir), trust)
	if err != nil {
		return err
	}
	defer c.close()
	dirHandle := c.leaf.handle

	suffix := make([]byte, 8)
	if _, err = rand.Read(suffix); err != nil {
		return err
	}
	tmp := "." + base + ".tmp-" + hex.EncodeToString(suffix)

	sd, err := trust.descriptor(false)
	if err != nil {
		return err
	}
	// DELETE is what renaming a file through its own handle needs; no sharing,
	// so nobody else holds it open.
	handle, err := ntOpen(dirHandle, tmp, windows.GENERIC_WRITE|windows.DELETE, 0, windows.FILE_CREATE,
		windows.FILE_NON_DIRECTORY_FILE, sd)
	if err != nil {
		return fmt.Errorf("securedir: create %s: %w", path, err)
	}
	file := os.NewFile(uintptr(handle), tmp)
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = renameInto(handle, dirHandle, base)
	}
	if err != nil {
		markForDeletion(handle)
		_ = file.Close()
		return fmt.Errorf("securedir: write %s: %w", path, err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("securedir: write %s: %w", path, err)
	}
	return nil
}

// markForDeletion removes a temporary file through its own handle when the
// handle is closed, so cleanup never goes back through a path.
func markForDeletion(handle windows.Handle) {
	disposition := uint32(1) // FILE_DISPOSITION_INFO.DeleteFile
	_ = windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo,
		(*byte)(unsafe.Pointer(&disposition)), uint32(unsafe.Sizeof(disposition)))
}

func openFile(path string, flag int, trust trustSet) (*os.File, error) {
	dir, base := filepath.Split(path)
	if err := plainName(base); err != nil {
		return nil, err
	}
	c, err := pinDir(filepath.Clean(dir), trust)
	if err != nil {
		return nil, err
	}
	defer c.close()

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
	// Truncation waits until the link count has been checked: truncating a
	// file with a second name would empty the other name's content too.
	var disposition uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		disposition = windows.FILE_CREATE
	case flag&os.O_CREATE != 0:
		disposition = windows.FILE_OPEN_IF
	default:
		disposition = windows.FILE_OPEN
	}

	sd, err := trust.descriptor(false)
	if err != nil {
		return nil, err
	}
	// FILE_READ_ATTRIBUTES is what the link-count and reparse checks below need.
	handle, err := ntOpen(c.leaf.handle, base, access|windows.FILE_READ_ATTRIBUTES, shareNoDelete, disposition, windows.FILE_NON_DIRECTORY_FILE, sd)
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
	if info.NumberOfLinks != 1 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("%w: %s does not have exactly one link", ErrUnsafeAccess, path)
	}
	file := os.NewFile(uintptr(handle), path)
	if flag&os.O_TRUNC != 0 {
		if err = file.Truncate(0); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("securedir: truncate %s: %w", path, err)
		}
	}
	return file, nil
}
