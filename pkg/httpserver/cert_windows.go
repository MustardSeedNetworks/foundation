// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package httpserver

import (
	"fmt"
	"slices"

	"golang.org/x/sys/windows"

	"github.com/MustardSeedNetworks/foundation/pkg/securedir"
)

// certDirOptions adds the running account to the directory's trusted set.
// The key is written for SYSTEM and this account only, and a daemon run by a developer
// rather than as a service has to be able to write into the directory it just
// secured; as SYSTEM this is a duplicate of an entry securedir always has.
func certDirOptions(opts securedir.Options) (securedir.Options, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return securedir.Options{}, fmt.Errorf("read process token user: %w", err)
	}
	opts.ExtraTrustedSIDs = append(slices.Clone(opts.ExtraTrustedSIDs), user.User.Sid.String())
	return opts, nil
}
