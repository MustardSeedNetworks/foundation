// SPDX-License-Identifier: BUSL-1.1

package httpserver

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isPortUnavailable reports whether a bind failed for a reason that makes THIS
// port unusable while leaving the next one worth trying.
//
// Two Winsock errnos qualify on Windows, and the walk needs both:
//
//   - WSAEADDRINUSE — something else already holds the port. This is not the
//     value syscall.EADDRINUSE carries here: on Windows that constant is a
//     synthesised APPLICATION_ERROR with nothing mapping the Winsock errno
//     back to it, so comparing against it is always false and the walk would
//     never happen.
//
//   - WSAEACCES — the port sits inside a range reserved by WinNAT/Hyper-V.
//     Those blocks live inside the dynamic range (49152-65535) and are present
//     on any host running Hyper-V, WSL2 or Docker Desktop. Bind reports "an
//     attempt was made to access a socket in a way forbidden by its access
//     permissions", which reads like a privilege problem and is not one — the
//     port is simply spoken for. Treating it as fatal stops the walk dead.
//
// The unix sibling deliberately does NOT treat EACCES this way: there it means
// a privileged port below 1024 and genuinely needs root.
func isPortUnavailable(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEACCES)
}
