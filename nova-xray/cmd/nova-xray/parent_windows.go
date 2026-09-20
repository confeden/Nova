//go:build windows

package main

import "golang.org/x/sys/windows"

// processAlive answers whether `pid` still names a running process.
//
// A terminated process keeps its handle openable until the last handle is closed, so an exit code
// is asked for rather than trusting OpenProcess to fail: STILL_ACTIVE (259) is the only answer that
// means alive. A pid we may not query (another user, higher integrity) is read as alive — this is a
// backstop against orphaning, and guessing "gone" there would kill a working tunnel.
func processAlive(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		return true
	}
	const stillActive = 259
	return code == stillActive
}
