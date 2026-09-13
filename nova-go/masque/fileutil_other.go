//go:build !windows

package masque

// isTransientShareError is always false off Windows: rename(2) replaces a file other processes hold open.
func isTransientShareError(error) bool { return false }
