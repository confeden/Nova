package warp

import (
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nova-pc/nova-go/internal/apistate"

	utls "github.com/refraction-networking/utls"
)

// blackhole accepts TCP and never speaks: what a filter that swallows a ClientHello looks like.
func blackhole(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return ln.Addr().String()
}

func TestDirectRaceReachesTheWorkingAddressWithoutWaitingOutTheDeadOne(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	dead := blackhole(t)
	deadIP, goodIP := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")

	slow := profileFor("stalls-3s", utls.HelloAndroid_11_OkHttp, []int{1, 255, 256}, 512)
	slow.handshakeTimeout = 3 * time.Second
	hooks := &testHooks{
		pinnedIPs: []netip.Addr{deadIP, goodIP},
		directAddr: func(ip netip.Addr) string {
			if ip == deadIP {
				return dead
			}
			return api.addr()
		},
		roots:     pki.roots,
		profiles:  []registrationProfile{slow, slow},
		hedgeStep: 40 * time.Millisecond,
	}
	started := time.Now()
	resp, err := registerForTest(t, APIOptions{Mode: ModeDirect, hooks: hooks})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("took %s: the dead address was waited out instead of raced", elapsed)
	}
	if !strings.HasPrefix(resp.Via, "direct/10.0.0.2/") {
		t.Fatalf("via = %q, want the working address", resp.Via)
	}
}

func TestDirectRaceSendsTheRequestOnce(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) {
		time.Sleep(200 * time.Millisecond) // long enough for the second handshake to finish and queue at the gate
		return 200, okDevice
	})
	p1 := profileFor("one", utls.HelloAndroid_11_OkHttp, []int{1, 255, 256}, 512)
	p2 := profileFor("two", utls.HelloChrome_Auto, []int{1, 680}, 681)
	hooks := directHooks(pki, api.addr(), p1, p2)
	hooks.hedgeStep = time.Millisecond
	if _, err := registerForTest(t, APIOptions{Mode: ModeDirect, hooks: hooks}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond) // a late second request would land here
	if got := len(api.requests()); got != 1 {
		t.Fatalf("server saw %d requests, want exactly 1 (a registration creates a device)", got)
	}
}

func TestDirectWinnerIsRememberedAndTriedFirst(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	p1 := profileFor("first", utls.HelloAndroid_11_OkHttp, []int{1, 255, 256}, 512)
	p2 := profileFor("second", utls.HelloChrome_Auto, []int{1, 680}, 681)
	store := apistate.Open(filepath.Join(t.TempDir(), "state.json"))

	if _, err := registerForTest(t, APIOptions{Mode: ModeDirect, State: store, hooks: directHooks(pki, api.addr(), p1, p2)}); err != nil {
		t.Fatal(err)
	}
	ip, profile, ok := store.Winner()
	if !ok || ip != "127.0.0.1" || profile != "first" {
		t.Fatalf("remembered = %q %q %v", ip, profile, ok)
	}

	run := &apiRun{state: store}
	_, ordered := run.rememberedFirst([]netip.Addr{loopback}, []registrationProfile{p1, p2})
	if ordered[0].label != "first" {
		t.Fatalf("order = %q", ordered[0].label)
	}
	store.NoteWinner("127.0.0.1", "second")
	_, ordered = run.rememberedFirst([]netip.Addr{loopback}, []registrationProfile{p1, p2})
	if ordered[0].label != "second" || ordered[1].label != "first" || len(ordered) != 2 {
		t.Fatalf("order = %q %q", ordered[0].label, ordered[1].label)
	}
	// A remembered pair that is no longer in the table changes nothing.
	store.NoteWinner("127.0.0.1", "gone")
	_, ordered = run.rememberedFirst([]netip.Addr{loopback}, []registrationProfile{p1, p2})
	if ordered[0].label != "first" {
		t.Fatalf("stale memory reordered the table: %q", ordered[0].label)
	}
}

func TestQuarantinedProxyIsNotDialled(t *testing.T) {
	store := apistate.Open(filepath.Join(t.TempDir(), "state.json"))
	store.NoteProxyDead("https://relay.test:2053")

	started := time.Now()
	_, err := registerForTest(t, APIOptions{
		Mode: ModeProxy, ProxyURL: "https://user:secret@relay.test:2053", State: store,
		hooks: &testHooks{},
	})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
	if !strings.Contains(err.Error(), "proxy: skipped") || !strings.Contains(err.Error(), "quarantine") {
		t.Fatalf("err = %v, want the quarantine named", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("credentials leaked into %q", err.Error())
	}
	if time.Since(started) > time.Second {
		t.Fatal("a quarantined proxy was dialled")
	}
}

func TestLoopbackProxyDownIsNotQuarantined(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens there now
	store := apistate.Open(filepath.Join(t.TempDir(), "state.json"))

	_, err = registerForTest(t, APIOptions{Mode: ModeProxy, ProxyURL: "http://" + addr, State: store, hooks: &testHooks{}})
	if !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "proxy: proxy-dial") {
		t.Fatalf("err = %v", err)
	}
	if _, dead := store.ProxyDead("http://" + addr); dead {
		t.Fatal("a local proxy that was down was quarantined; it may start any moment")
	}
}

func TestUnreachableErrorStartsWithASummary(t *testing.T) {
	failures := []routeFailure{
		{where: "direct/104.16.24.84/a", group: "direct 104.16.24.84", class: "tls-timeout"},
		{where: "direct/104.16.24.84/b", group: "direct 104.16.24.84", class: "tls-timeout"},
		{where: "direct/104.16.192.82/c", group: "direct 104.16.192.82", class: "tcp-dial"},
		{where: "direct/104.16.192.82/d", group: "direct 104.16.192.82", class: "superseded"},
		{where: "proxy/https://relay", group: "proxy", class: "proxy-dial"},
	}
	got := summarizeFailures(failures)
	want := "direct 104.16.24.84: 2xtls-timeout; direct 104.16.192.82: tcp-dial; proxy: proxy-dial"
	if got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
}

func TestFailureClass(t *testing.T) {
	cases := map[string]error{
		"tcp-dial":      errTCPDial,
		"proxy-dial":    errProxyDial,
		"proxy-refused": &ProxyError{StatusCode: 407, Status: "407"},
		"superseded":    errSuperseded,
		"tls-timeout":   errors.New("tls handshake failed: read tcp4 1.2.3.4:5->6.7.8.9:443: i/o timeout"),
		"reset":         errors.New("read: connection reset by peer"),
		"eof":           errors.New("tls handshake failed: EOF"),
		"bad-body":      errors.New("200 with unusable body: body is not a JSON object"),
		"other":         errors.New("something new"),
	}
	for want, err := range cases {
		if got := failureClass(err); got != want {
			t.Errorf("failureClass(%v) = %q, want %q", err, got, want)
		}
	}
}
