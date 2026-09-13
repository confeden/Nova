package masque

import (
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recordingConn struct {
	net.Conn
	writes []int
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, len(p))
	return len(p), nil
}

func TestFragmentedConnSplitPlans(t *testing.T) {
	hello := make([]byte, 1000)
	rec := &recordingConn{}
	fc := &fragmentedConn{Conn: rec, splitPlan: []int{1, 255, 256}, fragmentBytes: 512}
	if n, err := fc.Write(hello); err != nil || n != len(hello) {
		t.Fatalf("write: %d %v", n, err)
	}
	// Plan pieces, then the rest of the 512-byte window as one piece, then the tail unfragmented.
	if want := []int{1, 255, 256, 488}; !reflect.DeepEqual(rec.writes, want) {
		t.Fatalf("multisplit writes = %v, want %v", rec.writes, want)
	}
	rec.writes = nil
	if _, err := fc.Write(hello[:10]); err != nil || !reflect.DeepEqual(rec.writes, []int{10}) {
		t.Fatalf("later writes must pass through: %v", rec.writes)
	}

	rec2 := &recordingConn{}
	fc2 := &fragmentedConn{Conn: rec2, fragmentSize: 16, fragmentBytes: 40}
	if _, err := fc2.Write(hello[:100]); err != nil {
		t.Fatal(err)
	}
	if want := []int{16, 16, 8, 60}; !reflect.DeepEqual(rec2.writes, want) {
		t.Fatalf("fixed split writes = %v, want %v", rec2.writes, want)
	}
}

func TestNewAPIClientValidation(t *testing.T) {
	log := NewLogger(io.Discard, false)
	if _, err := NewAPIClient("proxy", "", log); err == nil {
		t.Fatal("proxy mode without a proxy accepted")
	}
	if _, err := NewAPIClient("auto", "socks5://127.0.0.1:1", log); err == nil {
		t.Fatal("socks5 proxy URL accepted (http.Transport would treat it differently)")
	}
	if _, err := NewAPIClient("weird", "", log); err == nil {
		t.Fatal("unknown mode accepted")
	}
	c, err := NewAPIClient("auto", "http://user:secret@127.0.0.1:1371", log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.proxyLabel(), "secret") {
		t.Fatal("proxy label leaks credentials")
	}
}

func TestAPIRouteOrder(t *testing.T) {
	log := NewLogger(io.Discard, false)
	// A closed port stands in for an Opera proxy that is not running.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := l.Addr().String()
	_ = l.Close()
	c, _ := NewAPIClient("auto", "http://"+deadAddr, log)
	routes := c.routes(t.Context())
	if len(routes) != 2*len(apiProfiles())+1 || routes[0].kind != "direct" || routes[len(routes)-1].kind != "plain" {
		t.Fatalf("auto without a reachable proxy: %d routes, first %s", len(routes), routes[0].kind)
	}
	live, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	go func() {
		for {
			conn, err := live.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	c2, _ := NewAPIClient("auto", "http://"+live.Addr().String(), log)
	if r := c2.routes(t.Context()); r[0].kind != "proxy" || r[1].ip.String() != "104.16.192.82" {
		t.Fatalf("auto with a reachable proxy starts with %s then %s", r[0].kind, r[1].label())
	}
	// The last winner is tried first.
	win := c2.routes(t.Context())[5]
	c2.winner = &win
	if r := c2.routes(t.Context()); r[0].label() != win.label() || len(r) != 2*len(apiProfiles())+2 {
		t.Fatalf("winner not first: %s (%d routes)", r[0].label(), len(r))
	}
	direct, _ := NewAPIClient("direct", "", log)
	for _, r := range direct.routes(t.Context()) {
		if r.kind != "direct" {
			t.Fatal("direct mode offers a non-direct route")
		}
	}
}

func TestStatusErrorAndTOS(t *testing.T) {
	err := statusError(&apiResponse{StatusCode: 400, Status: "400 Bad Request",
		Body: []byte(`{"result":null,"success":false,"errors":[{"code":1001,"message":"Invalid public key"}],"messages":[]}`)})
	var se *apiStatusError
	if !errors.As(err, &se) || se.API == nil || !se.API.HasErrorMessage("Invalid public key") {
		t.Fatalf("API error not parsed: %v", err)
	}
	if fe := apiFailure("enroll key", err); fe.code != ExitAPIStatus {
		t.Fatalf("status error mapped to %d", fe.code)
	}
	if fe := apiFailure("register", errors.Join(ErrAPIUnreachable, errors.New("x"))); fe.code != ExitAPIUnreachable {
		t.Fatalf("unreachable mapped to %d", fe.code)
	}
	ts := cloudflareTime(time.Date(2026, 9, 13, 10, 0, 0, 5e6, time.FixedZone("MSK", 3*3600)))
	if ts != "2026-09-13T07:00:00.005+00:00" {
		t.Fatalf("tos = %s", ts)
	}
}
