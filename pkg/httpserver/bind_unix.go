// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package httpserver

import (
	"errors"
	"syscall"
)

// isPortUnavailable reports whether a bind failed for a reason that makes THIS
// port unusable while leaving the next one worth trying.
//
// EADDRINUSE only. EACCES is deliberately excluded: on unix it means a
// privileged port below 1024 that needs root. The Windows sibling does include
// its EACCES equivalent, because there the same errno means a WinNAT-reserved
// port rather than a privilege problem.
func isPortUnavailable(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}
