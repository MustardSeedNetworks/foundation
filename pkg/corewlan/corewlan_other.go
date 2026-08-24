//go:build !darwin

package corewlan

// Scan is unavailable off macOS; callers select a platform implementation at a
// higher layer.
func Scan() ([]Network, error) { return nil, ErrUnsupported }

// Current is unavailable off macOS.
func Current() (*Network, error) { return nil, ErrUnsupported }

// Interfaces is unavailable off macOS.
func Interfaces() ([]string, error) { return nil, ErrUnsupported }

// SavedNetworks is unavailable off macOS.
func SavedNetworks() ([]string, error) { return nil, ErrUnsupported }

// Associate is unavailable off macOS.
func Associate(_, _ string) error { return ErrUnsupported }

// Disassociate is unavailable off macOS.
func Disassociate() error { return ErrUnsupported }

// SetPower is unavailable off macOS.
func SetPower(_ bool) error { return ErrUnsupported }

// Forget is unavailable off macOS.
func Forget(_ string) error { return ErrUnsupported }
