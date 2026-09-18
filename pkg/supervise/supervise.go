// SPDX-License-Identifier: BUSL-1.1

// Package supervise runs a daemon's long-lived goroutines under one
// supervisor: a panic becomes an error instead of killing the process, a
// failed worker is restarted as many times as its policy allows, and shutdown
// stops the workers in reverse registration order within the caller's
// deadline.
//
// The failure mode this closes is fleet-wide. stem and trellis have no
// recover() in production code at all, seed and niac recover in some workers
// and not others, and every systemd unit is Restart=on-failure — so one
// unrecovered panic in a background goroutine takes the whole daemon down and
// systemd restarts it with every in-flight run, scan and stream lost.
//
// Ordering is reverse registration order because registration order is
// dependency order: a worker registered after another may read from it, so it
// stops first.
package supervise

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
)

// Policy is how many times a failed worker is restarted before the group
// fails. A worker fails when its run function returns a non-nil error or
// panics; returning nil means the worker is finished and is never restarted.
type Policy int

// Fatal stops the group the first time the worker fails.
const Fatal Policy = 0

// RestartN restarts a failed worker n times, then fails the group. A negative
// n behaves as Fatal.
func RestartN(n int) Policy { return Policy(n) }

// PanicError reports a worker that panicked. Error is one line and never
// carries the stack; Stack is a field so the supervisor can log it at debug
// level without putting a stack trace in front of an operator.
type PanicError struct {
	Worker string
	Value  any
	Stack  []byte
}

func (e *PanicError) Error() string {
	return fmt.Sprintf("worker %q panicked: %v", e.Worker, e.Value)
}

type worker struct {
	name   string
	policy Policy
	run    func(context.Context) error

	cancel context.CancelFunc
	exited chan struct{}
}

// Group is a set of named workers under one supervisor. The zero value is not
// usable; call New.
type Group struct {
	log *slog.Logger

	mu        sync.Mutex
	workers   []*worker
	started   bool
	failure   error
	allExited chan struct{}
}

// New returns an empty group logging through log, or through slog.Default when
// log is nil.
func New(log *slog.Logger) *Group {
	if log == nil {
		log = slog.Default()
	}
	return &Group{log: log, allExited: make(chan struct{})}
}

// Add registers a worker. Workers start in registration order and stop in
// reverse. Add panics if the group has already started: a worker registered
// after Start would have no place in that order.
func (g *Group) Add(name string, policy Policy, run func(context.Context) error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.started {
		panic("supervise: Add after Start")
	}
	g.workers = append(g.workers, &worker{
		name:   name,
		policy: policy,
		run:    run,
		exited: make(chan struct{}),
	})
}

// Start launches every registered worker and returns immediately. Cancelling
// ctx triggers the same ordered stop as Stop, unbounded: a worker that ignores
// its context is waited for. Call Stop to bound that wait.
func (g *Group) Start(ctx context.Context) {
	g.mu.Lock()
	if g.started {
		g.mu.Unlock()
		panic("supervise: Start called twice")
	}
	g.started = true
	workers := g.workers
	g.mu.Unlock()

	// Worker contexts hang off ctx's values but not its cancellation: a
	// cancelled ctx must reach the workers through the ordered stop below,
	// not all at once.
	base := context.WithoutCancel(ctx)

	for _, w := range workers {
		wctx, cancel := context.WithCancel(base)
		w.cancel = cancel
		go g.supervise(wctx, w)
	}

	go func() {
		for _, w := range workers {
			<-w.exited
		}
		close(g.allExited)
	}()

	go func() {
		select {
		case <-ctx.Done():
			_ = g.Stop(context.WithoutCancel(ctx))
		case <-g.allExited:
		}
	}()
}

// Wait blocks until every worker has returned and reports the failure that
// stopped the group, or nil when the workers finished or the group was
// stopped on request.
func (g *Group) Wait() error {
	<-g.allExited
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failure
}

// Stop cancels the workers in reverse registration order, waiting for each to
// return before cancelling the next. If ctx expires first, Stop returns an
// error naming the worker still running. Stop is safe to call concurrently and
// more than once.
func (g *Group) Stop(ctx context.Context) error {
	g.mu.Lock()
	workers := g.workers
	started := g.started
	g.mu.Unlock()

	if !started {
		return nil
	}

	for i := len(workers) - 1; i >= 0; i-- {
		w := workers[i]
		w.cancel()
		select {
		case <-w.exited:
		case <-ctx.Done():
			return fmt.Errorf("stopping worker %q: %w", w.name, ctx.Err())
		}
	}
	return nil
}

// supervise runs one worker until it finishes, until its policy is exhausted,
// or until the group stops.
func (g *Group) supervise(ctx context.Context, w *worker) {
	defer close(w.exited)

	for attempt := 0; ; attempt++ {
		err := runOnce(ctx, w)
		if err == nil {
			return
		}
		// A failure while the group is stopping is the stop, not a fault.
		if ctx.Err() != nil {
			return
		}
		if attempt < int(w.policy) {
			g.log.Warn("supervised worker failed, restarting",
				"worker", w.name,
				"error", err.Error(),
				"restart", attempt+1,
				"restarts_allowed", int(w.policy))
			continue
		}
		g.fail(w, err)
		return
	}
}

// runOnce calls the worker's run function with its panic recovered into an
// error. The recover has to live in the worker's own goroutine: a panic in one
// goroutine cannot be recovered from another.
func runOnce(ctx context.Context, w *worker) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = &PanicError{Worker: w.name, Value: v, Stack: debug.Stack()}
		}
	}()
	return w.run(ctx)
}

// fail records the failure that stops the group, logs the single line the
// operator sees, and stops the remaining workers.
func (g *Group) fail(w *worker, err error) {
	g.mu.Lock()
	first := g.failure == nil
	if first {
		g.failure = err
	}
	g.mu.Unlock()

	if !first {
		return
	}

	// err.Error(), not err: slog's own handlers render an error value
	// through Error(), but a handler that marshals the value instead would
	// put PanicError.Stack in this line as a base64 field. The one-line
	// promise should not depend on which handler the product installed.
	g.log.Error("supervised worker failed, stopping",
		"worker", w.name,
		"error", err.Error(),
		"restarts_allowed", int(w.policy))

	var panicErr *PanicError
	if errors.As(err, &panicErr) {
		g.log.Debug("supervised worker panic stack",
			"worker", w.name,
			"stack", string(panicErr.Stack))
	}

	// Not inline: Stop waits for every worker to exit, and this one has not.
	go func() { _ = g.Stop(context.Background()) }()
}
