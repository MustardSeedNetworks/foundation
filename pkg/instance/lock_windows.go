// SPDX-License-Identifier: BUSL-1.1

package instance

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// The locked byte range sits past any record the file will ever hold. A
// Windows byte-range lock blocks other handles from *reading* the locked
// bytes, so locking offset 0 would make Probe unable to read the PID and port
// it exists to report. Nothing is ever written at this offset; it is a pure
// lock token.
const (
	lockOffsetHigh = 0x4000_0000
	lockOffsetLow  = 0
	lockLengthLow  = 1
	lockLengthHigh = 0
)

func lockRange() *windows.Overlapped {
	return &windows.Overlapped{Offset: lockOffsetLow, OffsetHigh: lockOffsetHigh}
}

func tryLock(file *os.File) (bool, error) {
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		lockLengthLow,
		lockLengthHigh,
		lockRange(),
	)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		return false, nil
	default:
		return false, err
	}
}

func unlock(file *os.File) error {
	return windows.UnlockFileEx(
		windows.Handle(file.Fd()),
		0,
		lockLengthLow,
		lockLengthHigh,
		lockRange(),
	)
}
