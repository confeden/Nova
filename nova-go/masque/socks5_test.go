package masque

import (
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeSocks5 is an unauthenticated SOCKS5 server that tunnels every CONNECT to upstream and records
// what it was asked for (the host must arrive as a name: the proxy resolves it).
type fakeSocks5 struct {
	ln       net.Listener
	lastHost atomic.Value
	atyp     atomic.Int64
}

func newFakeSocks5(t *testing.T, upstream string) *fakeSocks5 {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSocks5{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				hello := make([]byte, 2)
				if _, err := io.ReadFull(c, hello); err != nil || hello[0] != 5 {
					return
				}
				_, _ = io.ReadFull(c, make([]byte, int(hello[1])))
				_, _ = c.Write([]byte{5, 0})
				head := make([]byte, 4)
				if _, err := io.ReadFull(c, head); err != nil || head[1] != 1 {
					return
				}
				s.atyp.Store(int64(head[3]))
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
				_, _ = io.ReadFull(c, make([]byte, 2))
				s.lastHost.Store(host)
				up, err := net.Dial("tcp4", upstream)
				if err != nil {
					_, _ = c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	return s
}

func TestSocks5ProxyRouteReachesTheAPIByName(t *testing.T) {
	api := newFakeAPI(t, "", "peer")
	socks := newFakeSocks5(t, api.addr())
	for _, scheme := range []string{"socks5", "socks5h"} {
		c, err := newAPIClient(APIModeProxy, []string{scheme + "://" + socks.ln.Addr().String()}, NewLogger(io.Discard, false))
		if err != nil {
			t.Fatal(err)
		}
		c.state = nil
		c.rootCAs = api.roots
		resp, err := c.do(t.Context(), raceRequest())
		if err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Via, "proxy") {
			t.Fatalf("%s: status %d via %q", scheme, resp.StatusCode, resp.Via)
		}
		if host, _ := socks.lastHost.Load().(string); host != apiHost || socks.atyp.Load() != 3 {
			t.Fatalf("%s: proxy was asked for %v (atyp %d), want the name %s", scheme, socks.lastHost.Load(), socks.atyp.Load(), apiHost)
		}
	}
}
