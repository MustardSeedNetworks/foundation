# ADR 0003 — Supervised workers with a per-worker restart policy

**Status:** Accepted
**Date:** 2026-09-17

## Context

Every product runs long-lived background goroutines: stem's reflector
executor, dataplane and SSE hub; seed's outbox, reporting, initial scan and
Wi-Fi capture; trellis's readiness and scan loops. The 2026-09-17
daemon/API architecture analysis found stem and trellis have **no** `recover()`
in production code at all, and seed and niac recover in some workers and not
others.

That matters because every systemd unit is `Restart=on-failure`. An
unrecovered panic in one background goroutine takes the whole process down,
and systemd restarts a fresh daemon with every in-flight test run, scan and
stream lost — for a fault that was confined to one worker. The operator's
evidence is a stack trace in the journal and a restart count.

Four near-identical supervisors in four repos is the alternative, which is why
the row (`F-10`) landed here.

## Decision

`pkg/supervise` provides one `Group`. Four choices are worth recording,
because each has a plausible-looking alternative that is wrong.

**The recover lives in the worker's own goroutine.** A panic cannot be
recovered from another goroutine, so a supervisor that wraps only its own loop
recovers nothing. `runOnce` defers the recover immediately around the call to
the worker's function.

**The policy is a count, not a strategy interface.** `Policy` is a named
`int`: `Fatal` is zero and `RestartN(n)` is n. An interface with two
implementations would be indirection with no second axis behind it, and no
consumer has asked for backoff, jitter or a restart window. A count is also
what the acceptance is written in ("restarted n times and then fails the
daemon"). Restarts are not delayed: a worker that fails instantly n times
fails the daemon in a few microseconds rather than sleeping through a backoff
the operator then has to wait out.

**A panic and a returned error are the same failure.** Both consume one
restart. Distinguishing them would mean a worker could dodge its policy by
panicking. A worker returning `nil` is *finished*, not failed, and is never
restarted — that is what makes a one-shot worker (seed's initial scan)
expressible without a second worker kind.

**Shutdown is ordered, in reverse registration order, and the caller owns the
deadline.** Registration order is dependency order: a worker registered after
another may read from it, so it stops first. Cancelling every worker at once
is the obvious alternative and gets that backwards. Consequently the worker
contexts hang off the run context's *values* but not its cancellation
(`context.WithoutCancel`); a cancelled run context reaches the workers through
the same ordered stop, not all at once. `Stop(ctx)` returns
`ctx.Err()` naming the worker still running when the deadline passes, because
a worker that ignores its context cannot be killed in Go and pretending
otherwise would hang shutdown forever.

**The operator gets one line; the stack is a debug field.** The error that
stops the group is logged once at error level, with `err.Error()` rather than
the error value, so the line does not depend on the product's handler
rendering an error through `Error()`. `PanicError.Stack` is captured and
logged at debug level only. `PanicError.Error()` is one line and never
contains the stack.

## Consequences

The three product rows this unblocks (seed `D-SEED-28` slice 2, stem
`D-STEM-19`, trellis `D-TRL-6`) register their existing goroutines with a
policy each and delete nothing else; the supervisor does not change what a
worker does, only what happens when it fails.

What this does **not** do: it is not a process supervisor and does not replace
`Restart=on-failure`. A worker whose policy is exhausted still fails the
daemon — deliberately, since a daemon with a dead dataplane is not serving.
The change is that it fails with one log line naming the worker and its
restart count, after the ordered stop has run, instead of dying mid-write.

There is no restart backoff. A worker that fails instantly and is given
`RestartN(3)` burns its three restarts immediately. If a consumer needs
delay between attempts it belongs in that worker's own loop, where the
retriable condition is known, not in a policy field every consumer would then
have to reason about.
