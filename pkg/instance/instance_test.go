// SPDX-License-Identifier: BUSL-1.1

package instance_test

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/instance"
)

// A second Acquire on the same data directory must fail, and the error must
// carry the holder's PID and port so the product can name them. This is the
// row's headline acceptance: a fallback orphan that binds a neighbouring port
// and opens the same SQLite is exactly what this prevents.
func TestAcquireRejectsSecondHolderNamingPIDAndPort(t *testing.T) {
	dir := t.TempDir()

	first, acquireErr := instance.Acquire(dir)
	if acquireErr != nil {
		t.Fatalf("first Acquire: %v", acquireErr)
	}
	t.Cleanup(func() { _ = first.Release() })

	if portErr := first.SetPort(8445); portErr != nil {
		t.Fatalf("SetPort: %v", portErr)
	}

	second, secondErr := instance.Acquire(dir)
	if secondErr == nil {
		_ = second.Release()
		t.Fatal("second Acquire succeeded on a held data directory; want ErrHeld")
	}

	var held *instance.HeldError
	if !errors.As(secondErr, &held) {
		t.Fatalf("second Acquire error = %v (%T); want *instance.HeldError", secondErr, secondErr)
	}
	if held.PID != os.Getpid() {
		t.Errorf("HeldError.PID = %d; want %d", held.PID, os.Getpid())
	}
	if held.Port != 8445 {
		t.Errorf("HeldError.Port = %d; want 8445", held.Port)
	}

	msg := held.Error()
	if !strings.Contains(msg, strconv.Itoa(os.Getpid())) || !strings.Contains(msg, "8445") {
		t.Errorf("HeldError.Error() = %q; want it to name PID %d and port 8445", msg, os.Getpid())
	}
}

// Acquire runs before the listener binds, so the lock exists for a while with
// no port. The holder must still be nameable by PID, and the message must not
// claim a port it does not have.
func TestAcquireBeforePortIsKnown(t *testing.T) {
	dir := t.TempDir()

	first, acquireErr := instance.Acquire(dir)
	if acquireErr != nil {
		t.Fatalf("first Acquire: %v", acquireErr)
	}
	t.Cleanup(func() { _ = first.Release() })

	_, secondErr := instance.Acquire(dir)
	var held *instance.HeldError
	if !errors.As(secondErr, &held) {
		t.Fatalf("second Acquire error = %v; want *instance.HeldError", secondErr)
	}
	if held.PID != os.Getpid() {
		t.Errorf("HeldError.PID = %d; want %d", held.PID, os.Getpid())
	}
	if held.Port != 0 {
		t.Errorf("HeldError.Port = %d; want 0 before SetPort", held.Port)
	}
	if strings.Contains(held.Error(), "port") {
		t.Errorf("HeldError.Error() = %q; must not mention a port it does not know", held.Error())
	}
}

// Releasing must hand the directory back: a supervisor restart has to be able
// to re-acquire.
func TestReleaseAllowsReacquire(t *testing.T) {
	dir := t.TempDir()

	first, acquireErr := instance.Acquire(dir)
	if acquireErr != nil {
		t.Fatalf("first Acquire: %v", acquireErr)
	}
	if releaseErr := first.Release(); releaseErr != nil {
		t.Fatalf("Release: %v", releaseErr)
	}

	// Release must not unlink the lock file. Unlinking races a concurrent
	// open: the process that already has the old inode open would lock that,
	// the next starter would create and lock a new one, and both would believe
	// they were alone.
	if _, statErr := os.Stat(filepath.Join(dir, instance.LockFileName)); statErr != nil {
		t.Fatalf("lock file after Release: %v; Release must leave it in place", statErr)
	}

	second, secondErr := instance.Acquire(dir)
	if secondErr != nil {
		t.Fatalf("Acquire after Release: %v", secondErr)
	}
	if releaseErr := second.Release(); releaseErr != nil {
		t.Fatalf("second Release: %v", releaseErr)
	}
}

// The CLI needs to ask "is a daemon running here" without becoming the daemon.
// Probe must report the holder and must leave the lock exactly as it found it:
// held stays held, free stays free and acquirable.
func TestProbeReportsHolderWithoutTakingTheLock(t *testing.T) {
	dir := t.TempDir()

	if _, held, probeErr := instance.Probe(dir); probeErr != nil || held {
		t.Fatalf("Probe on a free directory = (held %v, err %v); want (false, nil)", held, probeErr)
	}

	first, acquireErr := instance.Acquire(dir)
	if acquireErr != nil {
		t.Fatalf("Acquire: %v", acquireErr)
	}
	t.Cleanup(func() { _ = first.Release() })
	if portErr := first.SetPort(8446); portErr != nil {
		t.Fatalf("SetPort: %v", portErr)
	}

	info, held, probeErr := instance.Probe(dir)
	if probeErr != nil {
		t.Fatalf("Probe: %v", probeErr)
	}
	if !held {
		t.Fatal("Probe reported the lock free while it was held")
	}
	if info.PID != os.Getpid() || info.Port != 8446 {
		t.Errorf("Probe info = %+v; want PID %d port 8446", info, os.Getpid())
	}

	// The probe must not have stolen the lock: the holder is still the holder.
	if _, stillHeldErr := instance.Acquire(dir); stillHeldErr == nil {
		t.Fatal("Acquire succeeded after Probe; Probe took the lock")
	}
}

// A crashed holder leaves the file behind with stale contents. That file must
// not read as a live daemon, and the directory must be acquirable again.
func TestStaleLockFileIsNotAHolder(t *testing.T) {
	dir := t.TempDir()

	first, acquireErr := instance.Acquire(dir)
	if acquireErr != nil {
		t.Fatalf("Acquire: %v", acquireErr)
	}
	if portErr := first.SetPort(8447); portErr != nil {
		t.Fatalf("SetPort: %v", portErr)
	}
	if releaseErr := first.Release(); releaseErr != nil {
		t.Fatalf("Release: %v", releaseErr)
	}

	if _, held, probeErr := instance.Probe(dir); probeErr != nil || held {
		t.Fatalf("Probe over a released lock = (held %v, err %v); want (false, nil)", held, probeErr)
	}

	second, secondErr := instance.Acquire(dir)
	if secondErr != nil {
		t.Fatalf("Acquire over a stale lock file: %v", secondErr)
	}
	_ = second.Release()
}

// The holder writes its record after taking the lock, so a second process can
// lose the race and find an empty or half-written file. It must still refuse
// to start, and must say so without inventing a PID.
func TestHolderRecordUnreadableStillRefuses(t *testing.T) {
	dir := t.TempDir()

	first, acquireErr := instance.Acquire(dir)
	if acquireErr != nil {
		t.Fatalf("Acquire: %v", acquireErr)
	}
	t.Cleanup(func() { _ = first.Release() })

	// Simulate the window between flock and the record write, and a torn
	// write, by clobbering the record underneath the live lock.
	for _, garbage := range []string{"", "not-a-record\n", "{\"pid\":"} {
		if writeErr := os.WriteFile(filepath.Join(dir, instance.LockFileName), []byte(garbage), 0o600); writeErr != nil {
			t.Fatalf("clobber record: %v", writeErr)
		}

		_, secondErr := instance.Acquire(dir)
		var held *instance.HeldError
		if !errors.As(secondErr, &held) {
			t.Fatalf("Acquire with record %q = %v; want *instance.HeldError", garbage, secondErr)
		}
		if held.PID != 0 {
			t.Errorf("record %q: HeldError.PID = %d; want 0 (unknown), not an invented PID", garbage, held.PID)
		}
		if held.Error() == "" {
			t.Errorf("record %q: HeldError.Error() is empty", garbage)
		}

		info, isHeld, probeErr := instance.Probe(dir)
		if probeErr != nil || !isHeld {
			t.Errorf("record %q: Probe = (%+v, held %v, err %v); want held with no error", garbage, info, isHeld, probeErr)
		}
	}
}

// SetPort is called once the listener is up, which may be after a probe has
// already read the record. It must be readable afterwards, and repeatable
// (the +1..+9 fallback can settle on a different port than first attempted).
func TestSetPortIsReadableAndRepeatable(t *testing.T) {
	dir := t.TempDir()

	lock, acquireErr := instance.Acquire(dir)
	if acquireErr != nil {
		t.Fatalf("Acquire: %v", acquireErr)
	}
	t.Cleanup(func() { _ = lock.Release() })

	for _, port := range []int{8445, 8446, 8452} {
		if portErr := lock.SetPort(port); portErr != nil {
			t.Fatalf("SetPort(%d): %v", port, portErr)
		}
		info, held, probeErr := instance.Probe(dir)
		if probeErr != nil || !held {
			t.Fatalf("Probe after SetPort(%d) = (held %v, err %v)", port, held, probeErr)
		}
		if info.Port != port {
			t.Errorf("Probe after SetPort(%d) read port %d", port, info.Port)
		}
	}
}

// Two different data directories are two different daemons and must not
// collide: the +1..+9 port fallback exists precisely so several products can
// run on one machine.
func TestDifferentDataDirsDoNotCollide(t *testing.T) {
	a, aErr := instance.Acquire(t.TempDir())
	if aErr != nil {
		t.Fatalf("Acquire(a): %v", aErr)
	}
	t.Cleanup(func() { _ = a.Release() })

	b, bErr := instance.Acquire(t.TempDir())
	if bErr != nil {
		t.Fatalf("Acquire(b): %v", bErr)
	}
	t.Cleanup(func() { _ = b.Release() })
}

// Acquire owns creating the data directory: products call it before anything
// else exists on a fresh install.
func TestAcquireCreatesDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")

	lock, acquireErr := instance.Acquire(dir)
	if acquireErr != nil {
		t.Fatalf("Acquire on a missing directory: %v", acquireErr)
	}
	t.Cleanup(func() { _ = lock.Release() })

	if _, statErr := os.Stat(filepath.Join(dir, instance.LockFileName)); statErr != nil {
		t.Fatalf("lock file after Acquire: %v", statErr)
	}
}

// Release must be safe to call twice: products defer it and also call it on a
// clean shutdown path.
func TestReleaseIsIdempotent(t *testing.T) {
	dir := t.TempDir()

	lock, acquireErr := instance.Acquire(dir)
	if acquireErr != nil {
		t.Fatalf("Acquire: %v", acquireErr)
	}
	if releaseErr := lock.Release(); releaseErr != nil {
		t.Fatalf("first Release: %v", releaseErr)
	}
	if releaseErr := lock.Release(); releaseErr != nil {
		t.Fatalf("second Release: %v", releaseErr)
	}
	if portErr := lock.SetPort(8445); portErr == nil {
		t.Error("SetPort after Release succeeded; want an error")
	}
}
