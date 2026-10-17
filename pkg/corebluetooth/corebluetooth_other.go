//go:build !darwin

package corebluetooth

import "time"

// Scan is unavailable off macOS; callers select a platform implementation at a
// higher layer.
func Scan(_ time.Duration) ([]Peripheral, error) { return nil, ErrUnsupported }

// AuthorizationStatus is unavailable off macOS.
func AuthorizationStatus() Authorization { return AuthNotDetermined }
