// SPDX-License-Identifier: BUSL-1.1

package route_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCheckRoutePolicyScript runs the shipped gate against fixture trees: a
// product whose routes all go through the registrar passes, and one that
// builds its own mux or uses the default one fails naming the line.
func TestCheckRoutePolicyScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the gate is a bash script; products run it on their Linux CI")
	}
	tests := []struct {
		dir      string
		wantFail bool
		wantLine string
	}{
		{dir: "clean", wantLine: "all routes go through the registrar"},
		{dir: "direct", wantFail: true, wantLine: "server.go:4:"},
		{dir: "direct", wantFail: true, wantLine: "server.go:5:"},
		{dir: "defaultmux", wantFail: true, wantLine: "metrics.go:3:"},
	}
	for _, tt := range tests {
		t.Run(tt.dir+tt.wantLine, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "bash", "check-route-policy.sh", filepath.Join("testdata", "policy", tt.dir))
			out, err := cmd.CombinedOutput()
			if failed := err != nil; failed != tt.wantFail {
				t.Fatalf("failed = %v, want %v; output:\n%s", failed, tt.wantFail, out)
			}
			if !strings.Contains(string(out), tt.wantLine) {
				t.Errorf("output does not name %q:\n%s", tt.wantLine, out)
			}
		})
	}
}
