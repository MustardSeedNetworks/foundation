// SPDX-License-Identifier: BUSL-1.1

package instance_test

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/instance"
)

// holderEnv makes this test binary act as the holder process instead of
// running the suite. flock conflicts between two open file descriptions even
// inside one process, which is what makes the rest of the suite real — but the
// row's acceptance is about a second *daemon*, and only a second process can
// show that the PID reported belongs to someone else.
const (
	holderEnv     = "FOUNDATION_INSTANCE_TEST_HOLDER_DIR"
	holderPortEnv = "FOUNDATION_INSTANCE_TEST_HOLDER_PORT"
)

func TestMain(m *testing.M) {
	dir := os.Getenv(holderEnv)
	if dir == "" {
		os.Exit(m.Run())
	}
	os.Exit(runHolder(dir))
}

// runHolder takes the lock, announces its PID on stdout, and holds it until
// its stdin is closed — so the parent controls exactly when it lets go.
func runHolder(dir string) int {
	port, _ := strconv.Atoi(os.Getenv(holderPortEnv))

	lock, acquireErr := instance.Acquire(dir)
	if acquireErr != nil {
		_, _ = io.WriteString(os.Stderr, "holder acquire: "+acquireErr.Error()+"\n")
		return 1
	}
	if port != 0 {
		if portErr := lock.SetPort(port); portErr != nil {
			_, _ = io.WriteString(os.Stderr, "holder SetPort: "+portErr.Error()+"\n")
			return 1
		}
	}

	_, _ = io.WriteString(os.Stdout, strconv.Itoa(os.Getpid())+"\n")
	_, _ = io.Copy(io.Discard, os.Stdin)

	if releaseErr := lock.Release(); releaseErr != nil {
		_, _ = io.WriteString(os.Stderr, "holder release: "+releaseErr.Error()+"\n")
		return 1
	}
	return 0
}

func TestSecondProcessIsRefusedByName(t *testing.T) {
	dir := t.TempDir()

	const holderPort = 8445
	holder := exec.CommandContext(t.Context(), os.Args[0])
	holder.Env = append(os.Environ(),
		holderEnv+"="+dir,
		holderPortEnv+"="+strconv.Itoa(holderPort),
	)
	holder.Stderr = os.Stderr

	stdin, stdinErr := holder.StdinPipe()
	if stdinErr != nil {
		t.Fatalf("holder stdin: %v", stdinErr)
	}
	stdout, stdoutErr := holder.StdoutPipe()
	if stdoutErr != nil {
		t.Fatalf("holder stdout: %v", stdoutErr)
	}
	if startErr := holder.Start(); startErr != nil {
		t.Fatalf("start holder: %v", startErr)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = stdin.Close()
			_ = holder.Wait()
		}
	})

	line, readErr := bufio.NewReader(stdout).ReadString('\n')
	if readErr != nil {
		t.Fatalf("holder never reported ready: %v", readErr)
	}
	holderPID, atoiErr := strconv.Atoi(line[:len(line)-1])
	if atoiErr != nil {
		t.Fatalf("holder PID line %q: %v", line, atoiErr)
	}
	if holderPID == os.Getpid() {
		t.Fatalf("holder PID %d is this process; the subprocess did not run", holderPID)
	}

	// This process is the second daemon. It must be refused, by the holder's
	// name, not ours.
	_, secondErr := instance.Acquire(dir)
	var held *instance.HeldError
	if !errors.As(secondErr, &held) {
		t.Fatalf("Acquire beside a live holder = %v; want *instance.HeldError", secondErr)
	}
	if held.PID != holderPID {
		t.Errorf("HeldError.PID = %d; want the holder's %d", held.PID, holderPID)
	}
	if held.Port != holderPort {
		t.Errorf("HeldError.Port = %d; want %d", held.Port, holderPort)
	}

	info, isHeld, probeErr := instance.Probe(dir)
	if probeErr != nil || !isHeld || info.PID != holderPID || info.Port != holderPort {
		t.Errorf("Probe = (%+v, held %v, err %v); want the holder's PID %d port %d",
			info, isHeld, probeErr, holderPID, holderPort)
	}

	// When the holder exits, the directory must come free — including the case
	// the products care about most: the operating system drops the lock even
	// if the process never got to call Release.
	_ = stdin.Close()
	if waitErr := holder.Wait(); waitErr != nil {
		t.Fatalf("holder exited with %v", waitErr)
	}
	stopped = true

	reacquired, reacquireErr := instance.Acquire(dir)
	if reacquireErr != nil {
		t.Fatalf("Acquire after the holder exited: %v", reacquireErr)
	}
	if releaseErr := reacquired.Release(); releaseErr != nil {
		t.Fatalf("Release: %v", releaseErr)
	}
}

// A holder that is killed without unwinding — the crash case — must not leave
// the data directory locked forever.
// Probing a free directory must leave it free for a *different* process. The
// in-process check cannot see this: Probe's descriptor is closed on return, so
// a leaked lock would be dropped before the same process looked again. Another
// process is the only observer that can tell.
func TestProbeLeavesAFreeDirectoryAcquirableByAnotherProcess(t *testing.T) {
	dir := t.TempDir()

	// Create the lock file so Probe takes the real path rather than the
	// file-does-not-exist shortcut.
	seed, seedErr := instance.Acquire(dir)
	if seedErr != nil {
		t.Fatalf("seed Acquire: %v", seedErr)
	}
	if releaseErr := seed.Release(); releaseErr != nil {
		t.Fatalf("seed Release: %v", releaseErr)
	}

	if _, held, probeErr := instance.Probe(dir); probeErr != nil || held {
		t.Fatalf("Probe = (held %v, err %v); want (false, nil)", held, probeErr)
	}

	holder := exec.CommandContext(t.Context(), os.Args[0])
	holder.Env = append(os.Environ(), holderEnv+"="+dir)
	holder.Stderr = os.Stderr
	stdin, stdinErr := holder.StdinPipe()
	if stdinErr != nil {
		t.Fatalf("holder stdin: %v", stdinErr)
	}
	stdout, stdoutErr := holder.StdoutPipe()
	if stdoutErr != nil {
		t.Fatalf("holder stdout: %v", stdoutErr)
	}
	if startErr := holder.Start(); startErr != nil {
		t.Fatalf("start holder: %v", startErr)
	}

	if _, readErr := bufio.NewReader(stdout).ReadString('\n'); readErr != nil {
		t.Fatalf("another process could not acquire after Probe; Probe kept the lock: %v", readErr)
	}
	_ = stdin.Close()
	if waitErr := holder.Wait(); waitErr != nil {
		t.Fatalf("holder exited with %v", waitErr)
	}
}

func TestKilledHolderReleasesTheLock(t *testing.T) {
	dir := t.TempDir()

	holder := exec.CommandContext(t.Context(), os.Args[0])
	holder.Env = append(os.Environ(), holderEnv+"="+dir)
	holder.Stderr = os.Stderr

	if _, stdinErr := holder.StdinPipe(); stdinErr != nil {
		t.Fatalf("holder stdin: %v", stdinErr)
	}
	stdout, stdoutErr := holder.StdoutPipe()
	if stdoutErr != nil {
		t.Fatalf("holder stdout: %v", stdoutErr)
	}
	if startErr := holder.Start(); startErr != nil {
		t.Fatalf("start holder: %v", startErr)
	}

	if _, readErr := bufio.NewReader(stdout).ReadString('\n'); readErr != nil {
		t.Fatalf("holder never reported ready: %v", readErr)
	}

	if killErr := holder.Process.Kill(); killErr != nil {
		t.Fatalf("kill holder: %v", killErr)
	}
	_ = holder.Wait()

	lock, acquireErr := instance.Acquire(dir)
	if acquireErr != nil {
		t.Fatalf("Acquire after the holder was killed: %v", acquireErr)
	}
	if releaseErr := lock.Release(); releaseErr != nil {
		t.Fatalf("Release: %v", releaseErr)
	}
}
