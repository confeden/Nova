// Package parentwatch tells a helper process when the process that started it has exited.
//
// Nova starts nova-go with `--parent-pid <its own pid>`. Without the watch a helper outlives a
// crashed or force-killed Nova and keeps holding its listen port (127.0.0.1:1370), which the next
// Nova start then reads as "a live instance is already running".
package parentwatch

import "errors"

// ErrGone reports that the watched process is not running (already exited or never existed).
var ErrGone = errors.New("parent process is not running")

// Watch returns a channel that is closed when process pid exits.
//
// It returns ErrGone when the process is not running at call time, and another error when the
// process exists but cannot be watched. pid must be positive.
func Watch(pid int) (<-chan struct{}, error) {
	if pid <= 0 {
		return nil, errors.New("parent pid must be positive")
	}
	return watch(pid)
}
