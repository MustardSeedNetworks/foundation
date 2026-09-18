// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package httpserver

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// writePrivateKey writes the key readable only by the account that created it
// and by SYSTEM.
//
// Windows ignores the mode argument [os.WriteFile] takes: a 0600 file is an
// ordinary file, and Stat reports 0666 for it. "Owner-only" is a DACL there,
// not a mode. The descriptor is therefore attached at creation rather than
// applied afterwards -- a private key must not exist, even for the width of
// one syscall, under whatever the parent directory happens to inherit.
//
// That ordering has a consequence: CreateFile ignores the security descriptor
// when the file already exists, so an existing key is removed first and the
// new one created with CREATE_NEW. If another process wins that gap the create
// fails and the key is not written, which is the safe direction to fail.
func writePrivateKey(path string, keyPEM []byte) error {
	if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return fmt.Errorf("replace private key %s: %w", path, removeErr)
	}

	attrs, attrErr := ownerOnlyAttributes()
	if attrErr != nil {
		return attrErr
	}
	pathUTF16, pathErr := windows.UTF16PtrFromString(path)
	if pathErr != nil {
		return fmt.Errorf("private key path %s: %w", path, pathErr)
	}

	handle, createErr := windows.CreateFile(
		pathUTF16,
		windows.GENERIC_WRITE,
		0,
		attrs,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if createErr != nil {
		return fmt.Errorf("create private key %s: %w", path, createErr)
	}

	file := os.NewFile(uintptr(handle), path)
	if _, writeErr := file.Write(keyPEM); writeErr != nil {
		_ = file.Close()
		return fmt.Errorf("write private key %s: %w", path, writeErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		return fmt.Errorf("write private key %s: %w", path, closeErr)
	}
	return nil
}

// ownerOnlyAttributes builds a protected DACL granting full access to the
// calling account and to SYSTEM, and to nobody else. Protected ("P") is what
// drops the permissions the parent directory would otherwise pass down.
//
// SYSTEM is present because a daemon installed as a Windows service runs as
// it; a key it cannot read is a key the service cannot start with.
func ownerOnlyAttributes() (*windows.SecurityAttributes, error) {
	user, userErr := windows.GetCurrentProcessToken().GetTokenUser()
	if userErr != nil {
		return nil, fmt.Errorf("read process token user: %w", userErr)
	}

	sddl := fmt.Sprintf("D:P(A;;FA;;;%s)(A;;FA;;;SY)", user.User.Sid.String())
	descriptor, sddlErr := windows.SecurityDescriptorFromString(sddl)
	if sddlErr != nil {
		return nil, fmt.Errorf("build private key security descriptor: %w", sddlErr)
	}

	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}, nil
}
