// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withTestCost enables the cheap profile for one test and restores the
// production default afterwards.
func withTestCost(t *testing.T) {
	t.Helper()
	UseTestCost()
	t.Cleanup(func() { testCost.Store(false) })
}

func TestTestCostRoundTrip(t *testing.T) {
	withTestCost(t)
	record, err := Hash("cheap test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(record, testPrefix) {
		t.Fatalf("Hash did not use the test profile: %s", record)
	}
	for candidate, want := range map[string]bool{"cheap test passphrase": true, "other passphrase": false} {
		matched, err := Verify(record, candidate)
		if err != nil || matched != want {
			t.Fatalf("Verify(%q): matched=%v err=%v", candidate, matched, err)
		}
	}
}

func TestTestCostRecordRejectedWhenDisabled(t *testing.T) {
	withTestCost(t)
	cheap, err := Hash("cheap test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	testCost.Store(false)
	if matched, err := Verify(cheap, "cheap test passphrase"); matched || !errors.Is(err, ErrRecord) {
		t.Fatalf("accepted a test-cost record in production mode: matched=%v err=%v", matched, err)
	}
	full, err := Hash("full cost passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(full, prefix) {
		t.Fatalf("production Hash did not use the full profile: %s", full)
	}
}

func TestFullRecordStillVerifiesInTestMode(t *testing.T) {
	full, err := Hash("full cost passphrase")
	if err != nil {
		t.Fatal(err)
	}
	withTestCost(t)
	if matched, err := Verify(full, "full cost passphrase"); err != nil || !matched {
		t.Fatalf("matched=%v err=%v", matched, err)
	}
}

// TestUseTestCostPanicsOutsideGoTest builds a stand-alone binary, where
// testing.Testing is false, and requires UseTestCost to panic there.
func TestUseTestCostPanicsOutsideGoTest(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	program := `package main

import "github.com/MustardSeedNetworks/foundation/pkg/password"

func main() { password.UseTestCost() }
`
	if err := os.WriteFile(src, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "helper"+exeSuffix())
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, src)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}
	out, err := exec.CommandContext(ctx, bin).CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || !strings.Contains(string(out), "only available under go test") {
		t.Fatalf("helper did not panic: err=%v\n%s", err, out)
	}
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
