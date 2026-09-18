// SPDX-License-Identifier: BUSL-1.1

// Package httpserver is the fleet's one HTTPS listener: canonical-port
// fallback, the TLS configuration and self-signed default every product was
// rebuilding, and the same-port plaintext redirect that keeps a browser typing
// `host:8443` from a connection refused.
//
// Before this package each product carried its own copy — seed, stem and niac
// in `internal/api/server_port_fallback*.go`, trellis in
// `cmd/trellisd/portfallback.go` — and the copies had silently diverged. The
// Windows predicate is the sharpest example: niac learned (its #1682) that
// WinNAT reserves blocks inside the dynamic range and reports WSAEACCES, so
// the walk must step over those ports; seed, stem and trellis never learned
// it and still fail the start. This package carries the superset, so adopting
// it fixes that for the other three rather than preserving it.
package httpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
)

// MaxPortOffset is the highest offset above the canonical port that [Bind]
// probes: ports are requested..requested+MaxPortOffset.
//
// The four canonical ports are nine apart by design (seed 8443, stem 8444,
// niac 8445, trellis 8446), so these windows overlap: on a machine running
// several products a fallback can land on a sibling's port and the sibling
// then walks too. That is why the bound address is returned and logged rather
// than assumed.
const MaxPortOffset = 9

// Bind opens a TCP listener on addr ("host:port"). If the port is in use it
// walks port+1..port+MaxPortOffset and returns the first listener that binds,
// logging a WARN naming both ports when logger is non-nil.
//
// A bind failure that does not make this particular port unusable is returned
// immediately: the caller must treat it as fatal. On unix that includes
// EACCES, which means a privileged port below 1024 needing root — walking
// 80..89 would turn one clear "permission denied" into "tried ten ports and
// gave up". On Windows the same errno means a WinNAT-reserved port and is
// walked; see the platform files.
//
// Port 0 means "let the OS pick" and never walks: probing 0 then 1..9 would
// hand a caller that asked for an ephemeral port a privileged one instead.
//
// Use [BindExact] when the address came from an operator rather than from the
// product's default.
func Bind(ctx context.Context, logger *slog.Logger, addr string) (net.Listener, error) {
	return bind(ctx, logger, addr, true)
}

// BindExact opens a TCP listener on addr and fails if that exact port is
// taken. An operator who names a port is asking for that port; silently
// serving a neighbouring one hides the collision instead of reporting it.
// trellis already drew this line for `TRELLIS_ADDR` — this is that rule,
// shared.
func BindExact(ctx context.Context, logger *slog.Logger, addr string) (net.Listener, error) {
	return bind(ctx, logger, addr, false)
}

func bind(ctx context.Context, logger *slog.Logger, addr string, walk bool) (net.Listener, error) {
	host, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, fmt.Errorf("parse listen address %q: %w", addr, splitErr)
	}
	port, parseErr := strconv.Atoi(portStr)
	if parseErr != nil {
		return nil, fmt.Errorf("parse port %q from %q: %w", portStr, addr, parseErr)
	}

	// net.ListenConfig.Listen does not consult the context for a TCP listen —
	// there is nothing to block on — so a cancelled context would otherwise
	// bind ten ports in a row. Checking it here makes the parameter mean what
	// its presence in the signature claims.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("bind %s: %w", addr, ctxErr)
	}

	var lc net.ListenConfig

	if port == 0 || !walk {
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("bind %s: %w", addr, err)
		}
		return ln, nil
	}

	for offset := 0; offset <= MaxPortOffset; offset++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("bind %s and +1..+%d: %w", addr, MaxPortOffset, ctxErr)
		}
		actual := port + offset
		candidate := net.JoinHostPort(host, strconv.Itoa(actual))
		ln, err := lc.Listen(ctx, "tcp", candidate)
		if err == nil {
			if offset > 0 && logger != nil {
				logger.WarnContext(ctx,
					"requested port is in use, bound fallback port instead",
					"requested", port,
					"bound", actual,
				)
			}
			return ln, nil
		}
		if !isPortUnavailable(err) {
			return nil, fmt.Errorf("bind %s: %w", candidate, err)
		}
	}
	return nil, fmt.Errorf(
		"bind %s and +1..+%d: every port is in use or reserved",
		addr, MaxPortOffset,
	)
}
