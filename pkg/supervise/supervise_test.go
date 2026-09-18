// SPDX-License-Identifier: BUSL-1.1

package supervise_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MustardSeedNetworks/foundation/pkg/supervise"
)

// newTestLogger returns a logger writing JSON into buf, and buf. Debug is
// enabled so a test can prove what does and does not appear at each level.
func newTestLogger() (*slog.Logger, *lockedBuffer) {
	buf := &lockedBuffer{}
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// lockedBuffer is a bytes.Buffer safe for the supervisor's goroutines to write
// while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// linesAtLevel returns the log lines whose "level" field is level.
func (b *lockedBuffer) linesAtLevel(level string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if line != "" && strings.Contains(line, `"level":"`+level+`"`) {
			out = append(out, line)
		}
	}
	return out
}

func TestPanicIsRestartedNTimesThenFailsTheGroup(t *testing.T) {
	t.Parallel()

	log, buf := newTestLogger()
	g := supervise.New(log)

	var runs atomic.Int32
	g.Add("dataplane", supervise.RestartN(2), func(context.Context) error {
		runs.Add(1)
		panic("frame writer exploded")
	})

	g.Start(t.Context())
	err := g.Wait()

	if got := runs.Load(); got != 3 {
		t.Errorf("run count = %d, want 3 (initial run plus two restarts)", got)
	}

	var panicErr *supervise.PanicError
	if !errors.As(err, &panicErr) {
		t.Fatalf("Wait() = %v, want a *PanicError", err)
	}
	if panicErr.Worker != "dataplane" {
		t.Errorf("PanicError.Worker = %q, want %q", panicErr.Worker, "dataplane")
	}
	if len(panicErr.Stack) == 0 {
		t.Error("PanicError.Stack is empty; the stack must be captured for debug logging")
	}
	if strings.Contains(panicErr.Error(), "\n") {
		t.Errorf("PanicError.Error() = %q, want one line", panicErr.Error())
	}

	// The operator sees exactly one error line, and no stack trace above debug.
	if errLines := buf.linesAtLevel("ERROR"); len(errLines) != 1 {
		t.Errorf("error log lines = %d, want exactly 1:\n%s", len(errLines), buf.String())
	}
	for _, level := range []string{"ERROR", "WARN", "INFO"} {
		for _, line := range buf.linesAtLevel(level) {
			if strings.Contains(line, "goroutine ") || strings.Contains(line, "runtime/") {
				t.Errorf("%s line carries a stack trace: %s", level, line)
			}
		}
	}

	// The stack is still available to whoever is debugging.
	debugLines := buf.linesAtLevel("DEBUG")
	if len(debugLines) != 1 || !strings.Contains(debugLines[0], "goroutine ") {
		t.Errorf("want one debug line carrying the stack, got %v", debugLines)
	}
}

func TestFatalPolicyDoesNotRestart(t *testing.T) {
	t.Parallel()

	log, _ := newTestLogger()
	g := supervise.New(log)

	var runs atomic.Int32
	wantErr := errors.New("reflector socket closed")
	g.Add("reflector", supervise.Fatal, func(context.Context) error {
		runs.Add(1)
		return wantErr
	})

	g.Start(t.Context())
	if err := g.Wait(); !errors.Is(err, wantErr) {
		t.Errorf("Wait() = %v, want %v", err, wantErr)
	}
	if got := runs.Load(); got != 1 {
		t.Errorf("run count = %d, want 1; Fatal never restarts", got)
	}
}

func TestWorkerReturningNilIsFinishedNotRestarted(t *testing.T) {
	t.Parallel()

	log, _ := newTestLogger()
	g := supervise.New(log)

	var runs atomic.Int32
	g.Add("initial-scan", supervise.RestartN(3), func(context.Context) error {
		runs.Add(1)
		return nil
	})

	g.Start(t.Context())
	if err := g.Wait(); err != nil {
		t.Errorf("Wait() = %v, want nil when every worker finished", err)
	}
	if got := runs.Load(); got != 1 {
		t.Errorf("run count = %d, want 1; a nil return means finished", got)
	}
}

func TestRestartCountsErrorsAndPanicsTogether(t *testing.T) {
	t.Parallel()

	log, _ := newTestLogger()
	g := supervise.New(log)

	var runs atomic.Int32
	g.Add("sse-hub", supervise.RestartN(2), func(context.Context) error {
		if runs.Add(1)%2 == 0 {
			panic("hub wedged")
		}
		return errors.New("hub closed")
	})

	g.Start(t.Context())
	if err := g.Wait(); err == nil {
		t.Fatal("Wait() = nil, want the failure that exhausted the policy")
	}
	if got := runs.Load(); got != 3 {
		t.Errorf("run count = %d, want 3; a panic and an error both count as a failure", got)
	}
}

// stopRecorder records the order in which workers observed their context being
// cancelled.
type stopRecorder struct {
	mu    sync.Mutex
	order []string
}

func (r *stopRecorder) worker(name string) func(context.Context) error {
	return func(ctx context.Context) error {
		<-ctx.Done()
		r.mu.Lock()
		r.order = append(r.order, name)
		r.mu.Unlock()
		return nil
	}
}

func (r *stopRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.order...)
}

func TestStopIsOrderedInReverseRegistration(t *testing.T) {
	t.Parallel()

	log, _ := newTestLogger()
	g := supervise.New(log)
	rec := &stopRecorder{}

	for _, name := range []string{"outbox", "reporting", "capture"} {
		g.Add(name, supervise.Fatal, rec.worker(name))
	}

	g.Start(t.Context())

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := g.Stop(ctx); err != nil {
		t.Fatalf("Stop() = %v, want nil", err)
	}

	want := []string{"capture", "reporting", "outbox"}
	got := rec.recorded()
	if len(got) != len(want) {
		t.Fatalf("stop order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stop order = %v, want %v", got, want)
		}
	}

	if err := g.Wait(); err != nil {
		t.Errorf("Wait() = %v, want nil after a requested stop", err)
	}
}

func TestStopReturnsTheDeadlineNamingTheStuckWorker(t *testing.T) {
	t.Parallel()

	log, _ := newTestLogger()
	g := supervise.New(log)

	release := make(chan struct{})

	g.Add("outbox", supervise.Fatal, func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	})
	// A worker that ignores its context cannot be killed; Stop must give up.
	g.Add("wedged", supervise.Fatal, func(context.Context) error {
		<-release
		return nil
	})

	g.Start(t.Context())

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := g.Stop(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop() = %v, want a context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "wedged") {
		t.Errorf("Stop() error = %q, want it to name the worker still running", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Stop() took %s, want it bounded by the caller's deadline", elapsed)
	}

	// Release the wedged worker and let the group finish, so the test leaves
	// no goroutine behind and Stop is shown to succeed once it can.
	close(release)
	stopCtx, stopCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer stopCancel()
	if err := g.Stop(stopCtx); err != nil {
		t.Errorf("second Stop() = %v, want nil once the worker returns", err)
	}
	if err := g.Wait(); err != nil {
		t.Errorf("Wait() = %v, want nil after a requested stop", err)
	}
}

func TestCancellingStartContextStopsTheGroupInOrder(t *testing.T) {
	t.Parallel()

	log, _ := newTestLogger()
	g := supervise.New(log)
	rec := &stopRecorder{}

	for _, name := range []string{"outbox", "reporting"} {
		g.Add(name, supervise.Fatal, rec.worker(name))
	}

	ctx, cancel := context.WithCancel(t.Context())
	g.Start(ctx)
	cancel()

	if err := g.Wait(); err != nil {
		t.Errorf("Wait() = %v, want nil after the run context was cancelled", err)
	}

	want := []string{"reporting", "outbox"}
	got := rec.recorded()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("stop order = %v, want %v", got, want)
	}
}

func TestAFailedWorkerStopsTheRestOfTheGroup(t *testing.T) {
	t.Parallel()

	log, _ := newTestLogger()
	g := supervise.New(log)
	rec := &stopRecorder{}

	g.Add("outbox", supervise.Fatal, rec.worker("outbox"))
	g.Add("dataplane", supervise.Fatal, func(context.Context) error {
		return errors.New("dataplane died")
	})

	g.Start(t.Context())
	if err := g.Wait(); err == nil {
		t.Fatal("Wait() = nil, want the dataplane failure")
	}
	if got := rec.recorded(); len(got) != 1 || got[0] != "outbox" {
		t.Errorf("stopped workers = %v, want the surviving worker to have been stopped", got)
	}
}

func TestNilLoggerUsesTheDefault(t *testing.T) {
	t.Parallel()

	g := supervise.New(nil)
	g.Add("noop", supervise.Fatal, func(context.Context) error { return nil })
	g.Start(t.Context())
	if err := g.Wait(); err != nil {
		t.Errorf("Wait() = %v, want nil", err)
	}
}
