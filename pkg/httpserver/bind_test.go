// SPDX-License-Identifier: BUSL-1.1

package httpserver_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/httpserver"
)

// port extracts the numeric port from a bound listener.
func port(t *testing.T, ln net.Listener) int {
	t.Helper()
	_, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", ln.Addr(), err)
	}
	n, convErr := strconv.Atoi(p)
	if convErr != nil {
		t.Fatalf("Atoi(%q): %v", p, convErr)
	}
	return n
}

// The canonical port is free: Bind takes it and reports it, and the walk never
// runs. Every product documents one port (seed 8443 .. trellis 8446) and an
// operator reading the log line must see that number when nothing is in the way.
func TestBindTakesTheCanonicalPortWhenItIsFree(t *testing.T) {
	probe := listenLoopback(t)
	want := port(t, probe)
	if closeErr := probe.Close(); closeErr != nil {
		t.Fatalf("probe close: %v", closeErr)
	}

	ln, err := httpserver.Bind(context.Background(), nil, net.JoinHostPort("127.0.0.1", strconv.Itoa(want)))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	if got := port(t, ln); got != want {
		t.Errorf("bound port = %d; want the canonical %d", got, want)
	}
}

// The canonical port is held: the walk steps over it. This is seed #69 — a
// developer with something squatting on 8445 still gets a daemon, on the next
// port, without the documented default changing.
func TestBindWalksPastAHeldPort(t *testing.T) {
	held := listenLoopback(t)
	t.Cleanup(func() { _ = held.Close() })
	canonical := port(t, held)

	ln, err := httpserver.Bind(context.Background(), nil, net.JoinHostPort("127.0.0.1", strconv.Itoa(canonical)))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	got := port(t, ln)
	if got == canonical {
		t.Fatalf("bound the held port %d", got)
	}
	if got <= canonical || got > canonical+httpserver.MaxPortOffset {
		t.Errorf("bound port = %d; want inside (%d, %d]", got, canonical, canonical+httpserver.MaxPortOffset)
	}
}

// Every port in the window is held: Bind fails, and the message names the
// window rather than the last errno, so the operator knows ten ports were tried.
func TestBindFailsWhenTheWholeWindowIsHeld(t *testing.T) {
	first := listenLoopback(t)
	t.Cleanup(func() { _ = first.Close() })
	canonical := port(t, first)

	for offset := 1; offset <= httpserver.MaxPortOffset; offset++ {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(canonical+offset))
		var lc net.ListenConfig
		ln, err := lc.Listen(t.Context(), "tcp", addr)
		if err != nil {
			t.Skipf("could not hold the whole window (%s already busy): %v", addr, err)
		}
		t.Cleanup(func() { _ = ln.Close() })
	}

	ln, err := httpserver.Bind(context.Background(), nil, net.JoinHostPort("127.0.0.1", strconv.Itoa(canonical)))
	if err == nil {
		_ = ln.Close()
		t.Fatal("Bind succeeded with the whole window held")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(httpserver.MaxPortOffset)) {
		t.Errorf("error %q does not name the +1..+%d window", err, httpserver.MaxPortOffset)
	}
}

// Port 0 means "let the OS pick", and the caller gets an ephemeral port.
//
// What this cannot reach is the other half of the port-0 guard: the walk it
// prevents only runs if binding port 0 *fails*, which happens when the host
// is out of ephemeral ports and cannot be produced from a test. The guard
// stays because that walk would hand a caller who asked for any port the
// privileged ports 1..9 instead — a mutation that removes it therefore
// survives this suite, and is recorded rather than hidden.
func TestBindPortZeroAsksTheOSAndDoesNotWalk(t *testing.T) {
	ln, err := httpserver.Bind(context.Background(), nil, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	if got := port(t, ln); got == 0 || got <= httpserver.MaxPortOffset {
		t.Errorf("bound port = %d; want an OS-assigned ephemeral port", got)
	}
}

// A bind failure that is not "this port is taken" is fatal immediately. On
// unix EACCES means a privileged port that needs root: walking 80 -> 89 turns
// one clear "permission denied" into "tried ten ports and gave up".
func TestBindReturnsAMalformedAddressWithoutWalking(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "127.0.0.1:not-a-port", ""} {
		t.Run(addr, func(t *testing.T) {
			ln, err := httpserver.Bind(context.Background(), nil, addr)
			if err == nil {
				_ = ln.Close()
				t.Fatalf("Bind(%q) succeeded", addr)
			}
			if !strings.Contains(err.Error(), addr) && addr != "" {
				t.Errorf("error %q does not name the address %q", err, addr)
			}
		})
	}
}

// A cancelled context stops the walk rather than probing ten ports.
func TestBindHonoursACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ln, err := httpserver.Bind(ctx, nil, "127.0.0.1:0")
	if err == nil {
		_ = ln.Close()
		t.Fatal("Bind succeeded with a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v; want context.Canceled", err)
	}
}
