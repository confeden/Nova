// Package apistate remembers, between nova-go runs, what the Cloudflare API client learned about its
// routes: the last direct (address, profile) pair that got an HTTP 200, and the remote proxies that
// would not accept a connection a moment ago.
//
// Every nova-go run is a new process, so without a file each run walks the same dead routes again:
// a dead relay costs a dial timeout per run, and the one profile that works through the local ISP's
// filter is rediscovered after a string of timeouts. The file is advisory: a missing, unreadable or
// stale file only means "no memory", never an error.
package apistate

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EnvPath names the file. Empty (or unset) turns the memory off, which is what tests and ad-hoc runs get.
const EnvPath = "NOVA_API_STATE"

const (
	// WinnerTTL is how long a remembered direct winner is trusted. A filter changes over days.
	WinnerTTL = 24 * time.Hour
	// ProxyDeadTTL is how long a remote proxy that refused a TCP/TLS connection is skipped.
	ProxyDeadTTL = 10 * time.Minute
	maxProxies   = 16
)

type fileData struct {
	Winner  *winner               `json:"winner,omitempty"`
	Proxies map[string]proxyState `json:"dead_proxies,omitempty"`
}

type winner struct {
	IP      string `json:"ip"`
	Profile string `json:"profile"`
	At      int64  `json:"at"`
}

type proxyState struct {
	Until int64 `json:"until"`
}

// Store is safe for concurrent use. A nil *Store is a valid, empty one.
type Store struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

// FromEnv opens the store named by NOVA_API_STATE.
func FromEnv() *Store {
	return Open(os.Getenv(EnvPath))
}

// Open returns a store backed by path, or nil when path is blank.
func Open(path string) *Store {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	return &Store{path: path, now: time.Now}
}

// Winner returns the remembered direct pair, if it is still fresh.
func (s *Store) Winner() (ip, profile string, ok bool) {
	if s == nil {
		return "", "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	if d.Winner == nil || d.Winner.IP == "" || d.Winner.Profile == "" {
		return "", "", false
	}
	if s.now().Sub(time.Unix(d.Winner.At, 0)) > WinnerTTL {
		return "", "", false
	}
	return d.Winner.IP, d.Winner.Profile, true
}

// NoteWinner records the direct pair that just got an HTTP 200.
func (s *Store) NoteWinner(ip, profile string) {
	if s == nil || ip == "" || profile == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	if d.Winner != nil && d.Winner.IP == ip && d.Winner.Profile == profile && s.now().Unix()-d.Winner.At < 3600 {
		return // already known and fresh: do not rewrite the file on every success
	}
	d.Winner = &winner{IP: ip, Profile: profile, At: s.now().Unix()}
	s.save(d)
}

// ProxyDead reports whether key (a credential-free "scheme://host:port") was marked dead and is
// still inside its quarantine, and how long is left.
func (s *Store) ProxyDead(key string) (time.Duration, bool) {
	if s == nil || key == "" {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.load().Proxies[key]
	if !ok {
		return 0, false
	}
	left := time.Unix(st.Until, 0).Sub(s.now())
	if left <= 0 {
		return 0, false
	}
	return left, true
}

// NoteProxyDead quarantines key for ProxyDeadTTL. Loopback proxies are never quarantined: a local
// proxy that is down refuses at once, costs nothing to ask again, and may be started any moment.
func (s *Store) NoteProxyDead(key string) {
	if s == nil || key == "" || isLoopbackKey(key) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	if d.Proxies == nil {
		d.Proxies = make(map[string]proxyState)
	}
	d.Proxies[key] = proxyState{Until: s.now().Add(ProxyDeadTTL).Unix()}
	s.save(d)
}

// NoteProxyAlive lifts the quarantine of key after it carried an answer.
func (s *Store) NoteProxyAlive(key string) {
	if s == nil || key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load()
	if _, ok := d.Proxies[key]; !ok {
		return
	}
	delete(d.Proxies, key)
	s.save(d)
}

// ProxyKey is the credential-free identity of a proxy URL, or "" when raw does not parse.
func ProxyKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}[scheme]
	}
	return scheme + "://" + net.JoinHostPort(u.Hostname(), port)
}

func isLoopbackKey(key string) bool {
	u, err := url.Parse(key)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Store) load() fileData {
	var d fileData
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return d
	}
	if json.Unmarshal(raw, &d) != nil {
		return fileData{}
	}
	return d
}

// save drops expired entries and writes atomically; a failed write is ignored (advisory file).
func (s *Store) save(d fileData) {
	now := s.now().Unix()
	for k, st := range d.Proxies {
		if st.Until <= now {
			delete(d.Proxies, k)
		}
	}
	for len(d.Proxies) > maxProxies {
		for k := range d.Proxies {
			delete(d.Proxies, k)
			break
		}
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.path), 0o755)
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) != nil {
		return
	}
	if os.Rename(tmp, s.path) != nil {
		_ = os.Remove(tmp)
	}
}
