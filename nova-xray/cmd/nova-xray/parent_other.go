//go:build !windows

package main

import (
	"os"
	"syscall"
)

// processAlive is the POSIX form, present so the package still builds off Windows (tests, tooling).
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
