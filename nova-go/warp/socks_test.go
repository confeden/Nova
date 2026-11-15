package warp

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// fakeSocks is a SOCKS5 server (no authentication) that maps whatever it is asked for to upstream.
// mode: "" serves, "refuse" answers reply 0x05, "auth" demands a method we do not offer, "junk"
// is not SOCKS at all.
type fakeSocks struct {
	ln       net.Listener
	requests atomic.Int64
	lastHost atomic.Value
	lastPort atomic.Int64
	lastType atomic.Int64
}

func newFakeSocks(t *testing.T, upstream, mode string) *fakeSocks {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSocks{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, upstream, mode)
		}
	}()
	return s
}

func (s *fakeSocks) serve(c net.Conn, upstream, mode string) {
	defer c.Close()
	if mode == "junk" {
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	hello := make([]byte, 3)
	if _, err := io.ReadFull(c, hello); err != nil || hello[0] != 5 {
		return
	}
	if mode == "auth" {
		_, _ = c.Write([]byte{5, 0xFF})
		return
	}
	_, _ = c.Write([]byte{5, 0})
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil || head[1] != 1 {
		return
	}
	s.lastType.Store(int64(head[3]))
	host := ""
	switch head[3] {
	case 3:
		n := make([]byte, 1)
		_, _ = io.ReadFull(c, n)
		name := make([]byte, int(n[0]))
		_, _ = io.ReadFull(c, name)
		host = string(name)
	case 1:
		a := make([]byte, 4)
		_, _ = io.ReadFull(c, a)
		host = net.IP(a).String()
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(c, port); err != nil {
		return
	}
	s.requests.Add(1)
	s.lastHost.Store(host)
	s.lastPort.Store(int64(port[0])<<8 | int64(port[1]))
	if mode == "refuse" {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.Dial("tcp4", upstream)
	if err != nil {
		_, _ = c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
	_, _ = io.Copy(c, up)
}

func (s *fakeSocks) url(scheme string) string { return scheme + "://" + s.ln.Addr().String() }

func TestSocks5ProxyTierSendsTheNameToTheProxy(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	for _, scheme := range []string{"socks5", "socks5h"} {
		socks := newFakeSocks(t, api.addr(), "")
		resp, err := registerForTest(t, APIOptions{Mode: ModeProxy, ProxyURL: socks.url(scheme), hooks: &testHooks{roots: pki.roots}})
		if err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		if resp.Via != "proxy/android-okhttp" || resp.StatusCode != 200 {
			t.Fatalf("%s: via = %q status = %d", scheme, resp.Via, resp.StatusCode)
		}
		// The name is resolved by the proxy: a locally resolved address would be the filtered one.
		if host, _ := socks.lastHost.Load().(string); host != APIHost || socks.lastPort.Load() != 443 || socks.lastType.Load() != 3 {
			t.Fatalf("%s: proxy was asked for %v:%d (atyp %d), want %s:443 as a name", scheme, socks.lastHost.Load(), socks.lastPort.Load(), socks.lastType.Load(), APIHost)
		}
	}
}

func TestSocks5RefusalAndNonSocksServer(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	cases := map[string]string{"refuse": "proxy-refused", "auth": "proxy-refused", "junk": "proxy-dial"}
	for mode, class := range cases {
		socks := newFakeSocks(t, api.addr(), mode)
		_, err := registerForTest(t, APIOptions{Mode: ModeProxy, ProxyURL: socks.url("socks5"), hooks: &testHooks{roots: pki.roots}})
		if !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "proxy: "+class) {
			t.Fatalf("%s: err = %v, want summary proxy: %s", mode, err, class)
		}
	}
	if len(api.requests()) != 0 {
		t.Fatal("a refused SOCKS5 connect still reached the API")
	}
}

func TestSocks5AutoFallsBackFromDirect(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	socks := newFakeSocks(t, api.addr(), "")
	dead := blackhole(t)
	stall := profileFor("stalls", utls.HelloAndroid_11_OkHttp, []int{1, 255, 256}, 512)
	stall.handshakeTimeout = 500 * time.Millisecond
	hooks := directHooks(pki, dead, stall)
	resp, err := registerForTest(t, APIOptions{Mode: ModeAuto, ProxyURL: socks.url("socks5"), hooks: hooks})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Via, "proxy/") {
		t.Fatalf("via = %q, want the SOCKS5 proxy after the blackholed direct tier", resp.Via)
	}
}
