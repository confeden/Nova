//go:build windows

package masque

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// GM-6: CPython's open() (Nova reading the profile) and antivirus scanners hold files without
// FILE_SHARE_DELETE. A replace during that moment must wait it out instead of failing an enroll whose
// key the server already rotated.
func TestWriteFileAtomicWaitsOutASharingViolation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The condition is real: a plain replace fails while the handle is open.
	probe := filepath.Join(dir, "probe.tmp")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(probe, path); err == nil {
		_ = windows.CloseHandle(h)
		t.Skip("this file system replaces files held without FILE_SHARE_DELETE")
	}
	released := make(chan struct{})
	go func() {
		defer close(released)
		time.Sleep(400 * time.Millisecond)
		_ = windows.CloseHandle(h)
	}()
	started := time.Now()
	if err := writeFileAtomic(path, []byte("new")); err != nil {
		<-released
		t.Fatalf("replace gave up after %v: %v", time.Since(started), err)
	}
	<-released
	if data, _ := os.ReadFile(path); string(data) != "new" {
		t.Fatalf("profile holds %q, want the new content", data)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
}
