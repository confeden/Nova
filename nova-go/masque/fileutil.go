package masque

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// writeFileAtomic writes data to path via `<path>.tmp` + fsync + rename. On Windows os.Rename is
// MoveFileEx(MOVEFILE_REPLACE_EXISTING), so readers see either the old or the new file, never a
// half-written one.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(tmp), err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", filepath.Base(tmp), err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync %s: %w", filepath.Base(tmp), err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", filepath.Base(tmp), err)
	}
	if err := renameReplacing(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	return nil
}

// Retry window of renameReplacing.
const (
	renameRetryWindow = 2 * time.Second
	renameRetryStep   = 50 * time.Millisecond
)

// renameReplacing is os.Rename that waits out a target held open by another process without
// FILE_SHARE_DELETE (CPython's open() while Nova reads the profile, an antivirus scan). Such a hold
// lasts milliseconds; giving up at once would fail an enroll whose key the server already rotated.
func renameReplacing(from, to string) error {
	deadline := time.Now().Add(renameRetryWindow)
	for {
		err := os.Rename(from, to)
		if err == nil || !isTransientShareError(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(renameRetryStep)
	}
}

// errLocked means another process holds the profile lock.
var errLocked = errors.New("another nova-go process holds the profile lock")

// profileLock is a cross-process exclusive lock on `<profile>.lock`. The lock file is never
// deleted: removing it while another process has it open would let a third process lock a fresh
// file and run concurrently.
type profileLock struct {
	f *os.File
}

func lockProfile(profilePath string) (*profileLock, error) {
	f, err := os.OpenFile(profilePath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &profileLock{f: f}, nil
}

func (l *profileLock) Unlock() {
	if l == nil || l.f == nil {
		return
	}
	_ = unlockFile(l.f)
	_ = l.f.Close()
	l.f = nil
}
