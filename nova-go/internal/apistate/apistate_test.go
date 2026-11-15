package apistate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s := Open(filepath.Join(t.TempDir(), "sub", "state.json"))
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestNilAndBlankStoreAreInert(t *testing.T) {
	var s *Store
	s.NoteWinner("1.2.3.4", "p")
	s.NoteProxyDead("https://relay:1")
	if _, _, ok := s.Winner(); ok {
		t.Fatal("nil store remembered a winner")
	}
	if _, dead := s.ProxyDead("https://relay:1"); dead {
		t.Fatal("nil store remembered a dead proxy")
	}
	if Open("  ") != nil {
		t.Fatal("blank path must give a nil store")
	}
}

func TestWinnerExpires(t *testing.T) {
	s, now := newTestStore(t)
	s.NoteWinner("104.16.24.84", "chrome-multisplit-681")
	ip, profile, ok := s.Winner()
	if !ok || ip != "104.16.24.84" || profile != "chrome-multisplit-681" {
		t.Fatalf("winner = %q %q %v", ip, profile, ok)
	}
	*now = now.Add(WinnerTTL + time.Minute)
	if _, _, ok := s.Winner(); ok {
		t.Fatal("winner outlived its TTL")
	}
}

func TestProxyQuarantineExpiresAndLifts(t *testing.T) {
	s, now := newTestStore(t)
	key := "https://relay.example:2053"
	s.NoteProxyDead(key)
	if left, dead := s.ProxyDead(key); !dead || left <= 0 || left > ProxyDeadTTL {
		t.Fatalf("dead=%v left=%v", dead, left)
	}
	s.NoteProxyAlive(key)
	if _, dead := s.ProxyDead(key); dead {
		t.Fatal("NoteProxyAlive did not lift the quarantine")
	}
	s.NoteProxyDead(key)
	*now = now.Add(ProxyDeadTTL + time.Second)
	if _, dead := s.ProxyDead(key); dead {
		t.Fatal("quarantine outlived its TTL")
	}
}

func TestLoopbackProxyIsNeverQuarantined(t *testing.T) {
	s, _ := newTestStore(t)
	for _, key := range []string{"http://127.0.0.1:1371", "http://localhost:1371", "http://[::1]:1371"} {
		s.NoteProxyDead(key)
		if _, dead := s.ProxyDead(key); dead {
			t.Fatalf("%s was quarantined", key)
		}
	}
}

func TestCorruptFileIsNoMemory(t *testing.T) {
	s, _ := newTestStore(t)
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Winner(); ok {
		t.Fatal("corrupt file produced a winner")
	}
	s.NoteWinner("1.1.1.1", "p") // and it is rewritten, not wedged
	if _, _, ok := s.Winner(); !ok {
		t.Fatal("store did not recover from a corrupt file")
	}
}

func TestProxyKeyDropsCredentials(t *testing.T) {
	got := ProxyKey("https://user:secret@relay.nova-app.eu:2053")
	if got != "https://relay.nova-app.eu:2053" {
		t.Fatalf("key = %q", got)
	}
	if ProxyKey("relay:80") != "http://relay:80" || ProxyKey("") != "" {
		t.Fatal("bare host or empty input mishandled")
	}
}
