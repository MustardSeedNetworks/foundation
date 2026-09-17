# ADR 0002 — Single-instance lock keyed on the data directory

**Status:** Accepted
**Date:** 2026-09-17

## Context

Every product ships one daemon, and every product walks `+1..+9` when its
canonical port is busy (seed #69). Those two facts combine badly: starting a
second daemon does not fail on the port, it binds a neighbour — and then two
processes own the same SQLite file, the same config and the same recovery
state. A fallback orphan answering `/__version` during a seed deploy check is
how this was found.

No product had any guard. The 2026-09-17 daemon/API architecture analysis
rowed it as `F-9` for all four products at once, which makes it foundation's
problem rather than four near-identical implementations.

## Decision

`pkg/instance` provides the lock. Four choices are worth recording, because
each has a plausible-looking alternative that is wrong.

**Keyed on the data directory, not the port.** The port is not the thing that
must not be shared; the data is. Two products on one machine have two data
directories and must not collide, which a port-keyed or machine-global lock
(a named mutex, an abstract socket) gets wrong.

**`flock`, not `fcntl` record locks.** POSIX `F_SETLK` locks are owned by the
*process*, so a second acquisition from inside one process succeeds. That
would make the guard untestable in-process and would silently permit a
product that opened its data directory twice. `flock` is owned by the open
file description, so two opens conflict even in one process — correct, and
testable. On Windows `LockFileEx` behaves the same way across handles.

**The Windows lock sits at a high byte offset, not offset 0.** A Windows
byte-range lock blocks other handles from *reading* the locked bytes. Locking
the record itself would make the probe unable to read the PID and port it
exists to report.

**`Release` never unlinks the lock file.** Unlinking races a concurrent open:
the racing process holds the old inode, the next starter creates and locks a
new one, and both believe they are alone. A leftover file is not a holder —
whether the lock is held is a question for the operating system, not for a
PID parsed out of a file.

Two further consequences fall out of the daemon's own startup order. The lock
is taken *before* the listener binds, so the port is not known yet: `Acquire`
records the PID and `SetPort` adds the port once the fallback has settled,
and it is repeatable. And because a second process can lose the race against
that record write, the reader is total — an empty or half-written record
yields PID 0, and the error says "another instance is already running" without
inventing a number.

## Consequences

- Products call `Acquire(dataDir)` before anything else and `SetPort` after
  binding. Mapping `*HeldError` onto an exit code stays per-product: niac's
  `--once` exits 2 with "daemon running, use `niac simulation start`", while a
  daemon start exits 1.
- `Probe` lets a CLI ask whether a daemon is running without becoming one. It
  never leaves the lock held; on a free directory it holds it for the duration
  of the call, which is the only way to tell a live holder from a file a
  crashed one left behind.
- The module takes its first external dependency, `golang.org/x/sys`, because
  `LockFileEx` is not in stdlib `syscall` on Windows.
- CI gains a Windows job. The `LockFileEx` path is behind the `_windows.go`
  filename suffix, so the Linux and macOS jobs only ever built `flock` — the
  same reasoning that added the macOS job for `pkg/corewlan`.
