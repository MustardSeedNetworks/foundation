//go:build !darwin

package corewlan

// Scan is unavailable off macOS; callers select a platform implementation at a
// higher layer.
func Scan() ([]Network, error) { return nil, ErrUnsupported }

// Current is unavailable off macOS.
func Current() (*Network, error) { return nil, ErrUnsupported }
