package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nova-pc/nova-go/internal/apistate"
)

func raceRequest() apiRequest {
	return apiRequest{label: "device", method: http.MethodGet, path: apiRegPath + "/x", token: "secret-token-value"}
}

// stalledListener accepts TCP and never speaks: a filter that swallows the ClientHello.
func stalledListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	return ln.Addr().String()
}

func newRaceClient(t *testing.T, api *fakeAPI, deadFirstAddress bool) *APIClient {
	t.Helper()
	c, err := newAPIClient(APIModeDirect, nil, NewLogger(io.Discard, false))
	if err != nil {
		t.Fatal(err)
	}
	c.state = nil
	c.rootCAs = api.roots
	c.hedgeStep = 40 * time.Millisecond
	stalled := stalledListener(t)
	c.directDial = func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
		target := api.addr()
		if deadFirstAddress && ip == apiPinnedIPs[0] {
			target = stalled
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp4", target)
	}
	return c
}

func TestDirectRaceDoesNotWaitOutAStalledAddress(t *testing.T) {
	api := newFakeAPI(t, "", "peer")
	c := newRaceClient(t, api, true)
	started := time.Now()
	resp, err := c.do(t.Context(), raceRequest())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("took %s: the stalled address was waited out (its handshake timeout is 9 s)", elapsed)
	}
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Via, apiPinnedIPs[1].String()+"/") {
		t.Fatalf("answer = %d via %q, want the second address", resp.StatusCode, resp.Via)
	}
	if w := c.winnerLabel(); !strings.HasPrefix(w, apiPinnedIPs[1].String()+"/") {
		t.Fatalf("winner = %q", w)
	}
}

func TestDirectRaceSendsTheRequestOnce(t *testing.T) {
	api := newFakeAPI(t, "", "peer")
	c := newRaceClient(t, api, false)
	c.hedgeStep = time.Millisecond
	if _, err := c.do(t.Context(), raceRequest()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // a late second request would land here
	api.mu.Lock()
	n := len(api.requests)
	api.mu.Unlock()
	if n != 1 {
		t.Fatalf("server saw %d requests, want exactly 1 (a registration creates a device)", n)
	}
}

func TestUnreachableErrorStartsWithASummary(t *testing.T) {
	api := newFakeAPI(t, "", "peer")
	c := newRaceClient(t, api, false)
	c.directDial = func(context.Context, netip.Addr) (net.Conn, error) { return nil, errors.New("blocked") }
	c.hedgeStep = time.Millisecond
	_, err := c.do(t.Context(), raceRequest())
	if !errors.Is(err, ErrAPIUnreachable) {
		t.Fatalf("err = %v", err)
	}
	n := strconv.Itoa(len(apiProfiles()))
	want := "direct " + apiPinnedIPs[0].String() + ": " + n + "xtcp-dial; direct " + apiPinnedIPs[1].String() + ": " + n + "xtcp-dial"
	if !strings.Contains(err.Error(), ErrAPIUnreachable.Error()+": "+want) {
		t.Fatalf("err = %q, want it to lead with %q", err.Error(), want)
	}
}

func TestRoutesInterleaveAddressesAndRememberTheWinner(t *testing.T) {
	c, err := newAPIClient(APIModeDirect, nil, NewLogger(io.Discard, false))
	if err != nil {
		t.Fatal(err)
	}
	c.state = apistate.Open(filepath.Join(t.TempDir(), "state.json"))
	routes := c.routes(t.Context())
	if routes[0].profile.label != routes[1].profile.label || routes[0].ip == routes[1].ip {
		t.Fatalf("first two routes = %s, %s: want one profile on both addresses", routes[0].label(), routes[1].label())
	}
	c.state.NoteWinner(apiPinnedIPs[1].String(), "chrome-multisplit-540")
	routes = c.routes(t.Context())
	if routes[0].label() != apiPinnedIPs[1].String()+"/chrome-multisplit-540" || len(routes) != 2*len(apiProfiles()) {
		t.Fatalf("remembered route not first: %s (%d routes)", routes[0].label(), len(routes))
	}
}

func TestQuarantinedProxyIsSkippedWithoutProbing(t *testing.T) {
	c, err := newAPIClient(APIModeAuto, []string{"https://u:secret@relay.test:2053"}, NewLogger(io.Discard, false))
	if err != nil {
		t.Fatal(err)
	}
	c.state = apistate.Open(filepath.Join(t.TempDir(), "state.json"))
	c.state.NoteProxyDead("https://relay.test:2053")

	started := time.Now()
	routes := c.routes(t.Context())
	if time.Since(started) > time.Second {
		t.Fatal("a quarantined proxy was probed")
	}
	for _, r := range routes {
		if r.kind == "proxy" {
			t.Fatal("a quarantined proxy was offered")
		}
	}
	notes := c.takeSkipNotes()
	if len(notes) != 1 || notes[0].class != "skipped" || strings.Contains(notes[0].text+notes[0].label, "secret") {
		t.Fatalf("notes = %+v", notes)
	}
	// A dead remote proxy found by the probe is quarantined for the next run.
	c2, _ := newAPIClient(APIModeAuto, []string{"http://127.0.0.1:1"}, NewLogger(io.Discard, false))
	c2.state = apistate.Open(filepath.Join(t.TempDir(), "state2.json"))
	c2.routes(t.Context())
	if _, dead := c2.state.ProxyDead("http://127.0.0.1:1"); dead {
		t.Fatal("a loopback proxy must never be quarantined")
	}
}
