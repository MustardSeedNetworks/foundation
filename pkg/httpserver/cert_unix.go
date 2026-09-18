// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package httpserver

import "os"

// writePrivateKey writes the key owner-only. On unix the mode argument is the
// whole story.
func writePrivateKey(path string, keyPEM []byte) error {
	return os.WriteFile(path, keyPEM, keyFileMode)
}
