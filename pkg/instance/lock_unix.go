// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package instance

import (
	"errors"
	"os"
	"syscall"
)

// flock, not fcntl(F_SETLK): POSIX record locks are owned by the process, so a
// second Acquire from within one process would succeed and the whole guard
// would be untestable in-process. flock is owned by the open file description,
// so two opens conflict even in one process — which is both correct and what
// makes the tests real.
func tryLock(file *os.File) (bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.EWOULDBLOCK):
		return false, nil
	default:
		return false, err
	}
}

func unlock(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
