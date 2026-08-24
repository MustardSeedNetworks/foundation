//go:build darwin

package corewlan

/*
#cgo CFLAGS: -fobjc-arc -Wall
#cgo LDFLAGS: -framework Foundation -framework CoreWLAN -framework CoreLocation
#include <stdlib.h>
#include "corewlan_darwin.h"
*/
import "C"

// bridge calls one of the Objective-C entry points and copies its result into
// Go memory, releasing the C allocation in every path.
func bridge(call func() *C.char) ([]byte, error) {
	out := call()
	if out == nil {
		return nil, ErrNoInterface
	}
	defer C.cw_free(out)
	return []byte(C.GoString(out)), nil
}

// Scan performs a Wi-Fi scan, including hidden networks.
//
// It returns [ErrLocationDenied] when the process lacks Location Services
// authorization, because CoreWLAN reports redacted results rather than failing.
func Scan() ([]Network, error) {
	payload, err := bridge(func() *C.char { return C.cw_scan() })
	if err != nil {
		return nil, err
	}
	return DecodeScan(payload)
}

// Current returns the currently associated network, or [ErrNotAssociated] when
// the interface is not associated.
func Current() (*Network, error) {
	payload, err := bridge(func() *C.char { return C.cw_current() })
	if err != nil {
		return nil, err
	}

	networks, err := DecodeScan(payload)
	if err != nil {
		return nil, err
	}
	if len(networks) == 0 {
		return nil, ErrNotAssociated
	}
	return &networks[0], nil
}
