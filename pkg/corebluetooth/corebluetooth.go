// Package corebluetooth binds Apple's CoreBluetooth framework for Bluetooth Low
// Energy scanning on macOS.
//
// macOS offers no other way to hear LE advertisements: there is no HCI socket,
// and system_profiler lists only paired devices. CoreBluetooth answers only a
// process holding the user's Bluetooth grant, which macOS gives per user to a
// signed application bundle after a click in the GUI session. A daemon, or a
// binary started over ssh, is refused outright with
// CBManagerStateUnauthorized. This package returns that as [ErrUnauthorized]
// rather than an empty scan, so callers can tell an operator to grant the
// permission instead of reporting a quiet room.
//
// The bundle's Info.plist must carry NSBluetoothAlwaysUsageDescription. Without
// it, macOS terminates a bundled process the moment it creates a central
// manager; there is no error to return.
//
// CoreBluetooth never exposes a peripheral's Bluetooth address. Each peripheral
// is named by an identifier UUID that is stable on this Mac and meaningless on
// any other, so callers key on [Peripheral.Identifier], not a MAC.
//
// Scan results cross the cgo boundary as JSON, as pkg/corewlan's do.
package corebluetooth

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Sentinel errors returned by this package.
var (
	// ErrUnauthorized means the process lacks the user's Bluetooth grant.
	ErrUnauthorized = errors.New("corebluetooth: Bluetooth authorization required")

	// ErrPoweredOff means the Bluetooth radio is switched off.
	ErrPoweredOff = errors.New("corebluetooth: Bluetooth is powered off")

	// ErrUnsupported means this host has no Bluetooth LE radio, or this
	// platform has no CoreBluetooth.
	ErrUnsupported = errors.New("corebluetooth: Bluetooth LE unsupported")

	// ErrNotReady means the radio did not reach a usable state in time.
	ErrNotReady = errors.New("corebluetooth: Bluetooth did not become ready")

	// ErrDecode means the CoreBluetooth bridge returned a payload we could not
	// read.
	ErrDecode = errors.New("corebluetooth: malformed scan payload")
)

// State is the central manager's radio state, mirroring CBManagerState.
type State int

// Radio states.
const (
	StateUnknown      State = 0
	StateResetting    State = 1
	StateUnsupported  State = 2
	StateUnauthorized State = 3
	StatePoweredOff   State = 4
	StatePoweredOn    State = 5
)

// Authorization reports whether this process may use Bluetooth, mirroring
// CBManagerAuthorization.
type Authorization int

// Authorization states.
const (
	AuthNotDetermined Authorization = 0
	AuthRestricted    Authorization = 1
	AuthDenied        Authorization = 2
	AuthAllowedAlways Authorization = 3
)

// String names an authorization state for logs and operator messages.
func (a Authorization) String() string {
	switch a {
	case AuthNotDetermined:
		return "not determined"
	case AuthRestricted:
		return "restricted"
	case AuthDenied:
		return "denied"
	case AuthAllowedAlways:
		return "allowed"
	default:
		return "unknown"
	}
}

// rssiUnavailable is the value CoreBluetooth reports when it has no RSSI.
const rssiUnavailable = 127

// Peripheral is one LE device heard during a scan, with every advertisement
// and scan response it sent merged into one record.
type Peripheral struct {
	// Identifier is CoreBluetooth's UUID for the peripheral on this Mac.
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	// RSSI is the last signal strength heard in dBm, or 0 when unreported.
	RSSI        int  `json:"rssi"`
	Connectable bool `json:"connectable"`
	// TxPower is the advertised transmit power in dBm, nil when not advertised.
	TxPower *int `json:"txPower"`
	// ManufacturerData is the raw manufacturer-specific field, beginning with
	// the little-endian Bluetooth SIG company identifier.
	ManufacturerData []byte   `json:"manufacturerData"`
	ServiceUUIDs     []string `json:"serviceUuids"`
}

// scanPayload is the wire format produced by the Objective-C bridge.
type scanPayload struct {
	State       State        `json:"state"`
	Peripherals []Peripheral `json:"peripherals"`
}

// DecodeScan converts a bridge payload into peripherals, mapping every radio
// state other than powered on to its error. It is exported so the decoding
// rules can be tested without a Bluetooth radio.
func DecodeScan(payload []byte) ([]Peripheral, error) {
	var p scanPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecode, err)
	}

	switch p.State {
	case StatePoweredOn:
	case StateUnauthorized:
		return nil, ErrUnauthorized
	case StatePoweredOff:
		return nil, ErrPoweredOff
	case StateUnsupported:
		return nil, ErrUnsupported
	default:
		return nil, ErrNotReady
	}

	peripherals := make([]Peripheral, 0, len(p.Peripherals))
	for _, d := range p.Peripherals {
		if d.RSSI == rssiUnavailable {
			d.RSSI = 0
		}
		peripherals = append(peripherals, d)
	}
	return peripherals, nil
}
