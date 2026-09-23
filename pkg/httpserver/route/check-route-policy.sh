#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# check-route-policy.sh — every route goes through the shared registrar.
#
# github.com/MustardSeedNetworks/foundation/pkg/httpserver/route owns the
# ServeMux and composes each route's policy (limiter, auth, method gate, CSRF,
# feature, scope, body cap) in one order. A product that builds its own mux, or
# registers on net/http's default one, has a route that skipped that
# composition: the way stem shipped POST /api/v1/reflector/config without
# authentication (#398).
#
# Run it from the product's root, against the product's own pinned copy:
#
#   bash "$(go list -f '{{.Dir}}' github.com/MustardSeedNetworks/foundation/pkg/httpserver/route)/check-route-policy.sh" [dir ...]
#
# (The module cache does not keep the executable bit, hence `bash`.) Each dir
# defaults to internal/api and is searched recursively. Test files are exempt:
# a test may build a mux to exercise a handler in isolation.
set -euo pipefail

if [[ $# -eq 0 ]]; then
	set -- internal/api
fi

violations=$(grep -rnE --include='*.go' --exclude='*_test.go' \
	'http\.NewServeMux\(|\.HandleFunc\(|\.Handle\(' "$@" || true)

if [[ -n "$violations" ]]; then
	echo "❌ Route-policy gate: register every route through route.Registrar"
	echo "   (Register / RegisterAll), not a ServeMux of your own or net/http's"
	echo "   default one. A direct registration skips the canonical policy"
	echo "   composition. Declare a route.Route instead."
	echo ""
	echo "$violations"
	exit 1
fi

echo "✓ Route-policy gate: all routes go through the registrar ($*)."
