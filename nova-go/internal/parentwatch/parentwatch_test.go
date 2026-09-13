package parentwatch

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestWatchRejectsNonPositivePid(t *testing.T) {
	if _, err := Watch(0); err == nil {
		t.Fatal("pid 0 accepted")
	}
}

func TestWatchOwnProcessStaysOpen(t *testing.T) {
	done, err := Watch(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("own process reported as exited")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestWatchFiresWhenChildExits(t *testing.T) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping.exe", "-n", "2", "127.0.0.1")
	} else {
		cmd = exec.Command("sleep", "1")
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a child process: %v", err)
	}
	done, err := Watch(cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("watch did not fire after the child exited")
	}
	<-waitErr
}

func TestWatchUnknownPidIsGone(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("pid reuse semantics differ")
	}
	// Process ids on Windows are multiples of 4; an odd id never names a process.
	_, err := Watch(0x7FFFFFF1)
	if !errors.Is(err, ErrGone) {
		t.Fatalf("expected ErrGone, got %v", err)
	}
}
