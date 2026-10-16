// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestFingerprintCacheConcurrentAndCopySafe(t *testing.T) {
	t.Parallel()

	var cache fingerprintCache
	var calls atomic.Int32
	generate := func() (DeviceFingerprint, error) {
		call := calls.Add(1)
		return DeviceFingerprint{
			MACAddress: fmt.Sprintf("00:00:00:00:00:%02d", call),
			CPUSerial:  "cpu",
			DiskSerial: "disk",
			Hostname:   "host",
			Platform:   "test",
		}, nil
	}

	const goroutines = 64
	results := make(chan *DeviceFingerprint, goroutines)
	var workers sync.WaitGroup
	workers.Add(goroutines)
	for range goroutines {
		go func() {
			defer workers.Done()
			fp, err := cache.get(generate)
			if err != nil {
				t.Errorf("cache.get: %v", err)
			}
			results <- fp
		}()
	}
	workers.Wait()
	close(results)

	var expectedHash string
	var first *DeviceFingerprint
	for fp := range results {
		if first == nil {
			first = fp
			expectedHash = fp.Hash()
		}
		if fp.Hash() != expectedHash {
			t.Fatalf("fingerprint hash = %q, want %q", fp.Hash(), expectedHash)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("generator calls = %d, want 1", got)
	}

	first.Hostname = "mutated"
	again, err := cache.get(generate)
	if err != nil {
		t.Fatalf("cache.get: %v", err)
	}
	if again.Hostname != "host" {
		t.Fatalf("cached hostname = %q after caller mutation, want host", again.Hostname)
	}
}

// A failed probe must surface as an error, never as a stand-in identity, and
// must not stick: the next call retries and caches the real fingerprint.
func TestFingerprintCacheDoesNotKeepAFailure(t *testing.T) {
	t.Parallel()

	var cache fingerprintCache
	probeErr := errors.New("probe timed out")
	fail := true
	generate := func() (DeviceFingerprint, error) {
		if fail {
			return DeviceFingerprint{}, probeErr
		}
		return DeviceFingerprint{MACAddress: "aa", CPUSerial: "cpu", Hostname: "host", Platform: "test"}, nil
	}

	fp, err := cache.get(generate)
	if !errors.Is(err, probeErr) || fp != nil {
		t.Fatalf("cache.get = %v, %v; want nil, %v", fp, err, probeErr)
	}

	fail = false
	fp, err = cache.get(generate)
	if err != nil {
		t.Fatalf("cache.get after recovery: %v", err)
	}
	if fp.CPUSerial != "cpu" {
		t.Fatalf("CPUSerial = %q, want cpu", fp.CPUSerial)
	}

	fail = true
	if _, err := cache.get(generate); err != nil {
		t.Fatalf("cache.get after a cached success re-probed: %v", err)
	}
}

func TestParseIOPlatformUUID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		out     string
		want    string
		wantErr bool
	}{
		{
			name: "ioreg device entry",
			out: `+-o J413AP  <class IOPlatformExpertDevice, id 0x100000243, registered, matched, active, busy 0 (124 ms), retain 39>
    {
      "IOPlatformSerialNumber" = "C02XXXXXXXXX"
      "IOPlatformUUID" = "4C4C4544-0042-3510-8051-B4C04F4B4E32"
      "manufacturer" = <"Apple Inc.">
    }`,
			want: "4C4C4544-0042-3510-8051-B4C04F4B4E32",
		},
		{name: "no uuid key", out: `      "IOPlatformSerialNumber" = "C02XXXXXXXXX"`, wantErr: true},
		{name: "empty value", out: `      "IOPlatformUUID" = ""`, wantErr: true},
		{name: "empty output", out: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseIOPlatformUUID(tt.out)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseIOPlatformUUID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("parseIOPlatformUUID() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Linux identity is the machine ID alone; anything that is not one is an
// error, never a stand-in, so the activation cannot silently re-key.
func TestReadMachineID(t *testing.T) {
	t.Parallel()

	const id = "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name    string
		content *string
		want    string
		wantErr bool
	}{
		{name: "systemd file", content: new(id + "\n"), want: id},
		{name: "missing file", wantErr: true},
		{name: "empty file", content: new(""), wantErr: true},
		{name: "first boot placeholder", content: new("uninitialized\n"), wantErr: true},
		{name: "uppercase digits", content: new(strings.ToUpper(id)), wantErr: true},
		{name: "short id", content: new(id[:31]), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "machine-id")
			if tt.content != nil {
				if err := os.WriteFile(path, []byte(*tt.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := readMachineID(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("readMachineID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("readMachineID() = %q, want %q", got, tt.want)
			}
		})
	}
}
