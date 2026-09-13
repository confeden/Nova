//go:build windows

package masque

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isTransientShareError reports a replace refused because another handle on the target lacks
// FILE_SHARE_DELETE; MoveFileEx answers that with access denied or a sharing violation.
func isTransientShareError(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
