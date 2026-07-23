// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestFingerprintCacheConcurrentAndCopySafe(t *testing.T) {
	t.Parallel()

	var cache fingerprintCache
	var calls atomic.Int32
	generate := func() DeviceFingerprint {
		call := calls.Add(1)
		return DeviceFingerprint{
			MACAddress: fmt.Sprintf("00:00:00:00:00:%02d", call),
			CPUSerial:  "cpu",
			DiskSerial: "disk",
			Hostname:   "host",
			Platform:   "test",
		}
	}

	const goroutines = 64
	results := make(chan *DeviceFingerprint, goroutines)
	var workers sync.WaitGroup
	workers.Add(goroutines)
	for range goroutines {
		go func() {
			defer workers.Done()
			results <- cache.get(generate)
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
	if got := cache.get(generate).Hostname; got != "host" {
		t.Fatalf("cached hostname = %q after caller mutation, want host", got)
	}
}
