//go:build !windows

package parentwatch

import (
	"os"
	"syscall"
	"time"
)

// Non-Windows builds are for development only; polling with signal 0 is good enough there.
func watch(pid int) (<-chan struct{}, error) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, ErrGone
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return nil, ErrGone
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := proc.Signal(syscall.Signal(0)); err != nil {
				return
			}
		}
	}()
	return done, nil
}
