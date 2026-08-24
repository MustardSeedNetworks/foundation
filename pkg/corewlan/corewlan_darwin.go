//go:build darwin

package corewlan

/*
#cgo CFLAGS: -fobjc-arc -Wall
#cgo LDFLAGS: -framework Foundation -framework CoreWLAN -framework CoreLocation
#include <stdlib.h>
#include "corewlan_darwin.h"
*/
import "C"

import (
	"errors"
	"time"
	"unsafe"
)

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

// action runs a bridge call that reports failure as an error string, and
// releases that string in every path.
func action(call func() *C.char) error {
	out := call()
	if out == nil {
		return nil
	}
	defer C.cw_free(out)
	return errors.New("corewlan: " + C.GoString(out))
}

// AuthorizationStatus reports whether this process holds Location Services
// authorization, without asking for it.
func AuthorizationStatus() Authorization {
	return Authorization(C.cw_authorization_status())
}

// RequestAuthorization asks for Location Services authorization and waits up to
// timeout for a decision.
//
// Requesting is also what registers the application with locationd, which is
// what makes it appear in System Settings. The permission cannot be offered at
// all until this has been called at least once.
//
// A background agent is prompted normally, but only if its bundle carries the
// com.apple.security.personal-information.location entitlement. Under the
// hardened runtime — which notarization requires — locationd registers the
// client and then declines to display the dialog without it, logging "Client
// has supported the hardened runtime but doesn't have the entitlement". Since
// the client is still registered, the bundle appears in System Settings and can
// be enabled by hand, so a missing entitlement looks like macOS refusing to
// prompt agents rather than a signing defect.
func RequestAuthorization(timeout time.Duration) Authorization {
	return Authorization(C.cw_request_authorization(C.double(timeout.Seconds())))
}

// Interfaces lists the host's Wi-Fi interface names.
func Interfaces() ([]string, error) {
	payload, err := bridge(func() *C.char { return C.cw_interfaces() })
	if err != nil {
		return nil, err
	}
	return DecodeNames(payload)
}

// SavedNetworks lists the names of networks the system remembers.
func SavedNetworks() ([]string, error) {
	payload, err := bridge(func() *C.char { return C.cw_saved_networks() })
	if err != nil {
		return nil, err
	}
	return DecodeNames(payload)
}

// Associate joins the named network, scanning for it first. Pass an empty
// password for an open network.
func Associate(ssid, password string) error {
	cSSID := C.CString(ssid)
	defer C.free(unsafe.Pointer(cSSID))

	var cPass *C.char
	if password != "" {
		cPass = C.CString(password)
		defer C.free(unsafe.Pointer(cPass))
	}

	return action(func() *C.char { return C.cw_associate(cSSID, cPass) })
}

// Disassociate leaves the current network without powering the radio down.
func Disassociate() error {
	return action(func() *C.char { return C.cw_disassociate() })
}

// SetPower turns the Wi-Fi radio on or off.
func SetPower(on bool) error {
	var v C.int
	if on {
		v = 1
	}
	return action(func() *C.char { return C.cw_set_power(v) })
}

// Forget removes a remembered network. Rewriting the stored configuration is an
// administrative operation and fails without the system-configuration right.
func Forget(ssid string) error {
	cSSID := C.CString(ssid)
	defer C.free(unsafe.Pointer(cSSID))

	return action(func() *C.char { return C.cw_forget(cSSID) })
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
