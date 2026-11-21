// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package httpserver

import (
	"os"

	"github.com/MustardSeedNetworks/foundation/pkg/securedir"
)

// keyFileMode is the private key's permission: owner-only, because a
// world-readable key on a shared dev box is a real leak. Windows has no mode
// bits; its half of the promise is the DACL in cert_windows.go.
const keyFileMode os.FileMode = 0o600

// writePrivateKey writes the key owner-only. On unix the mode argument is the
// whole story.
func writePrivateKey(path string, keyPEM []byte) error {
	return os.WriteFile(path, keyPEM, keyFileMode)
}

// certDirOptions is the directory policy as configured: unix needs nothing
// added.
func certDirOptions(opts securedir.Options) (securedir.Options, error) { return opts, nil }
