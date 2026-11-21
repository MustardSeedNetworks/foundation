// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package httpserver

import (
	"github.com/MustardSeedNetworks/foundation/pkg/securedir"
)

// certDirOptions is the directory policy as configured: unix needs nothing
// added.
func certDirOptions(opts securedir.Options) (securedir.Options, error) { return opts, nil }
