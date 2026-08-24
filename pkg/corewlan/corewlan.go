// Package corewlan binds Apple's CoreWLAN framework for Wi-Fi scanning on macOS.
//
// It exists because the `airport` command-line tool, which every Mustard Seed
// product previously shelled out to, was removed in macOS 26. CoreWLAN is the
// supported replacement and is not deprecated.
//
// CoreWLAN redacts SSID and BSSID unless the calling process holds Location
// Services authorization, which macOS grants per-user to a signed application
// bundle. A scan without that grant does not fail: it returns the correct number
// of networks with correct RSSI and channel, and every identifier stripped to the
// empty string. This package refuses to pass that through as a successful scan
// and returns [ErrLocationDenied] instead, so callers can tell an operator to
// grant the permission rather than silently reporting an empty airspace.
//
// Scan results cross the cgo boundary as JSON. Scans are infrequent and the
// payload is a few kilobytes, so the cost is irrelevant next to keeping the C
// surface to a single string return with one owner and one free.
package corewlan

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Band identifies the frequency band a network operates on.
type Band int

// Frequency bands reported by CoreWLAN.
const (
	BandUnknown Band = 0
	Band2GHz    Band = 2
	Band5GHz    Band = 5
	Band6GHz    Band = 6
)

// Sentinel errors returned by this package.
var (
	// ErrLocationDenied means the process lacks Location Services authorization,
	// so CoreWLAN redacted every SSID and BSSID.
	ErrLocationDenied = errors.New("corewlan: Location Services authorization required")

	// ErrUnsupported means this platform has no CoreWLAN.
	ErrUnsupported = errors.New("corewlan: only supported on macOS")

	// ErrNoInterface means the host reported no Wi-Fi interface.
	ErrNoInterface = errors.New("corewlan: no Wi-Fi interface")

	// ErrNotAssociated means the Wi-Fi interface is not joined to a network.
	ErrNotAssociated = errors.New("corewlan: not associated")

	// ErrDecode means the CoreWLAN bridge returned a payload we could not read.
	ErrDecode = errors.New("corewlan: malformed scan payload")
)

// Authorization reports whether this process may see network identifiers.
type Authorization int

// Authorization states, mirroring CLAuthorizationStatus.
const (
	AuthNotDetermined Authorization = 0
	AuthRestricted    Authorization = 1
	AuthDenied        Authorization = 2
	AuthAuthorized    Authorization = 3
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
	case AuthAuthorized:
		return "authorized"
	default:
		return "unknown"
	}
}

// Network is a single access point observed during a scan.
type Network struct {
	SSID         string `json:"ssid"`
	BSSID        string `json:"bssid"`
	RSSI         int    `json:"rssi"`  // dBm
	Noise        int    `json:"noise"` // dBm, 0 when unreported
	Channel      int    `json:"channel"`
	ChannelWidth int    `json:"width"` // MHz
	Band         Band   `json:"band"`
	PHYMode      string `json:"phyMode"`
	Security     string `json:"security"`

	// Hidden reports a network that broadcasts no SSID but was still observed.
	// It is distinct from a redacted result, which has no BSSID either.
	Hidden bool `json:"-"`
}

// SNR returns the signal-to-noise ratio in dB, or 0 when no noise floor was
// reported. CoreWLAN omits the noise floor for scanned (as opposed to
// associated) networks on some adapters.
func (n Network) SNR() int {
	if n.Noise == 0 {
		return 0
	}
	return n.RSSI - n.Noise
}

// DecodeNames converts a bridge JSON array of names into a slice. It is
// exported so the decoding rule can be tested without a Wi-Fi adapter.
func DecodeNames(payload []byte) ([]string, error) {
	var names []string
	if err := json.Unmarshal(payload, &names); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecode, err)
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}

// scanPayload is the wire format produced by the Objective-C bridge.
type scanPayload struct {
	Authorized bool      `json:"authorized"`
	Networks   []Network `json:"networks"`
}

// DecodeScan converts a bridge payload into networks, mapping a redacted scan
// onto [ErrLocationDenied]. It is exported so the decoding rules can be tested
// without a Wi-Fi adapter.
func DecodeScan(payload []byte) ([]Network, error) {
	var p scanPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecode, err)
	}

	if !p.Authorized || redacted(p.Networks) {
		return nil, ErrLocationDenied
	}

	networks := make([]Network, 0, len(p.Networks))
	for _, n := range p.Networks {
		n.Hidden = n.SSID == "" && n.BSSID != ""
		networks = append(networks, n)
	}
	return networks, nil
}

// redacted reports whether a non-empty scan carries no identifiers at all.
//
// The authorization status alone cannot be trusted. CoreWLAN redacts according
// to the calling process's own client identity, and a bundled executable
// launched directly rather than through LaunchServices is a *different* client
// from its bundle — so the manager can report the bundle's grant while the scan
// it returns is stripped. Observed on macOS 27.0: status authorized, thirteen
// networks, every SSID and BSSID empty.
//
// A real observation always carries a BSSID, so a scan that found networks and
// named none of them was redacted, whatever the status says.
func redacted(networks []Network) bool {
	if len(networks) == 0 {
		return false
	}
	for _, n := range networks {
		if n.BSSID != "" {
			return false
		}
	}
	return true
}
