//go:build windows

package parentwatch

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

func watch(pid int) (<-chan struct{}, error) {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		// OpenProcess answers ERROR_INVALID_PARAMETER for a pid that does not exist.
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil, ErrGone
		}
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	// A handle to an already exited process is still valid; the wait below returns at once.
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer windows.CloseHandle(handle)
		for {
			event, werr := windows.WaitForSingleObject(handle, windows.INFINITE)
			if werr != nil {
				// WAIT_FAILED on a valid SYNCHRONIZE handle is not expected. Treating it as
				// "parent gone" stops the helper instead of leaving an unwatched orphan.
				return
			}
			if event == windows.WAIT_OBJECT_0 || event == uint32(windows.WAIT_ABANDONED) {
				return
			}
		}
	}()
	return done, nil
}
