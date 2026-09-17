// SPDX-License-Identifier: BUSL-1.1

// Package instance provides the fleet-shared single-instance lock. A daemon
// takes it on its data directory before it binds anything; a second daemon on
// the same data directory then fails by name instead of starting.
//
// The failure mode this closes is specific. Every product walks +1..+9 when
// its canonical port is busy (seed #69), so a second daemon does not collide
// on the port — it binds a neighbour and opens the same SQLite file and the
// same config underneath the first one. A fallback orphan answering
// /__version during a seed deploy check is how that was found.
//
// The lock is keyed on the data directory, not the port, because the data is
// what must not be shared. Two products on one machine have two data
// directories and never collide.
package instance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// LockFileName is the lock file's name inside the data directory.
const LockFileName = ".instance.lock"

// recordSize fixes the on-disk record's width so SetPort never changes the
// file's length. A reader racing the write then sees the old bytes, the new
// bytes, or a mix of the two at fixed offsets — never a short read of a
// truncated file, and never trailing bytes from a longer previous record.
// JSON ignores the trailing padding.
const recordSize = 64

// Info is what the holder published about itself. Port is 0 until the holder
// has bound its listener and called SetPort; PID is 0 when the record could
// not be read (see Probe).
type Info struct {
	PID  int `json:"pid"`
	Port int `json:"port"`
}

// HeldError reports that another instance holds the data directory. PID and
// Port are 0 when they are not known — the holder writes its record just
// after taking the lock, so a second process can lose that race, and a
// truthful "unknown" beats an invented number.
type HeldError struct {
	Dir  string
	PID  int
	Port int
}

func (e *HeldError) Error() string {
	switch {
	case e.PID != 0 && e.Port != 0:
		return fmt.Sprintf("another instance is already running in %s (pid %d, port %d)", e.Dir, e.PID, e.Port)
	case e.PID != 0:
		return fmt.Sprintf("another instance is already running in %s (pid %d)", e.Dir, e.PID)
	default:
		return fmt.Sprintf("another instance is already running in %s", e.Dir)
	}
}

// Lock is a held single-instance lock. It is safe for concurrent use.
type Lock struct {
	mu       sync.Mutex
	file     *os.File
	dir      string
	released bool
}

// ErrReleased is returned by SetPort after the lock has been released.
var ErrReleased = errors.New("instance lock already released")

// Acquire takes the single-instance lock on dir, creating dir if it does not
// exist, and records this process's PID. It returns a *HeldError if another
// instance holds it.
//
// Callers take the lock before binding a listener, so the port is not known
// yet; call SetPort once it is.
func Acquire(dir string) (*Lock, error) {
	if mkdirErr := os.MkdirAll(dir, 0o700); mkdirErr != nil {
		return nil, fmt.Errorf("create data directory %s: %w", dir, mkdirErr)
	}

	path := filepath.Join(dir, LockFileName)
	file, openErr := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if openErr != nil {
		return nil, fmt.Errorf("open instance lock %s: %w", path, openErr)
	}

	locked, lockErr := tryLock(file)
	if lockErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock %s: %w", path, lockErr)
	}
	if !locked {
		info := readRecord(file)
		_ = file.Close()
		return nil, &HeldError{Dir: dir, PID: info.PID, Port: info.Port}
	}

	lock := &Lock{file: file, dir: dir}
	if writeErr := lock.write(Info{PID: os.Getpid()}); writeErr != nil {
		_ = unlock(file)
		_ = file.Close()
		return nil, writeErr
	}
	return lock, nil
}

// SetPort records the port the holder ended up listening on. The +1..+9
// fallback means that is not known at Acquire time and can settle more than
// once, so SetPort is repeatable.
func (l *Lock) SetPort(port int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return ErrReleased
	}
	return l.write(Info{PID: os.Getpid(), Port: port})
}

// Release hands the data directory back. It is idempotent.
//
// The lock file is deliberately left behind: unlinking it races a concurrent
// open, which would leave two processes holding locks on two different inodes
// and each believing it is alone. A leftover file is not a holder — see Probe.
func (l *Lock) Release() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil
	}
	l.released = true

	unlockErr := unlock(l.file)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return fmt.Errorf("unlock %s: %w", l.dir, unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close instance lock %s: %w", l.dir, closeErr)
	}
	return nil
}

// Probe reports whether an instance holds dir, and what it published about
// itself. It is what a CLI uses to decide between talking to a running daemon
// and doing the work itself.
//
// Probe never leaves the lock held: on a free directory it takes and drops it
// within the call. Testing the lock is the only way to tell a live holder from
// a file a crashed one left behind — a PID read out of the file is a guess,
// and the operating system already knows the answer.
func Probe(dir string) (Info, bool, error) {
	path := filepath.Join(dir, LockFileName)
	file, openErr := os.OpenFile(path, os.O_RDWR, 0o600)
	if openErr != nil {
		if errors.Is(openErr, os.ErrNotExist) {
			return Info{}, false, nil
		}
		return Info{}, false, fmt.Errorf("open instance lock %s: %w", path, openErr)
	}
	defer func() { _ = file.Close() }()

	locked, lockErr := tryLock(file)
	if lockErr != nil {
		return Info{}, false, fmt.Errorf("probe %s: %w", path, lockErr)
	}
	if locked {
		// The deferred Close drops it again: on both unix and Windows a lock
		// dies with the descriptor that holds it. An explicit unlock here
		// would be unreachable in effect --
		// TestProbeLeavesAFreeDirectoryAcquirableByAnotherProcess is what
		// actually holds this property, and it fails if the Close goes away.
		return Info{}, false, nil
	}
	return readRecord(file), true, nil
}

func (l *Lock) write(info Info) error {
	encoded, marshalErr := json.Marshal(info)
	if marshalErr != nil {
		return fmt.Errorf("encode instance record: %w", marshalErr)
	}
	if len(encoded) > recordSize {
		return fmt.Errorf("instance record is %d bytes, over the %d-byte record", len(encoded), recordSize)
	}

	record := make([]byte, recordSize)
	for i := range record {
		record[i] = ' '
	}
	copy(record, encoded)

	if _, writeErr := l.file.WriteAt(record, 0); writeErr != nil {
		return fmt.Errorf("write instance record in %s: %w", l.dir, writeErr)
	}
	return nil
}

// readRecord is total: an empty, short or half-written record yields a zero
// Info rather than an error. The caller already knows the lock is held; the
// record only adds a name to it.
func readRecord(file *os.File) Info {
	buf := make([]byte, recordSize)
	n, readErr := file.ReadAt(buf, 0)
	if n == 0 && readErr != nil {
		return Info{}
	}
	var info Info
	if unmarshalErr := json.Unmarshal(buf[:n], &info); unmarshalErr != nil {
		return Info{}
	}
	return info
}
