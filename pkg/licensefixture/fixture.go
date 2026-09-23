// Package licensefixture is a scratch-PR fixture: it imports an LGPL-3.0
// module so the License Compliance job must fail. Never merged.
package licensefixture

import "github.com/juju/errors"

// Err exists only to keep the import.
var Err = errors.New("fixture")
