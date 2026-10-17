//go:build darwin

package corebluetooth

/*
#cgo CFLAGS: -fobjc-arc -Wall
#cgo LDFLAGS: -framework Foundation -framework CoreBluetooth
#include <stdlib.h>
#include "corebluetooth_darwin.h"
*/
import "C"

import "time"

// Scan listens for LE advertisements for duration and returns every peripheral
// heard, including ones that advertise no name.
//
// Creating the central manager is what asks the user for Bluetooth access, so
// the first scan from a newly installed bundle can return [ErrUnauthorized]
// while the consent dialog is still on screen.
func Scan(duration time.Duration) ([]Peripheral, error) {
	out := C.cbt_scan(C.double(duration.Seconds()))
	if out == nil {
		return nil, ErrDecode
	}
	defer C.cbt_free(out)
	return DecodeScan([]byte(C.GoString(out)))
}

// AuthorizationStatus reports whether this process may use Bluetooth, without
// asking for it.
func AuthorizationStatus() Authorization {
	return Authorization(C.cbt_authorization())
}
