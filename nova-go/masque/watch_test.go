package masque

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func testRuntimeForWatch(stall time.Duration) *socksRuntime {
	return &socksRuntime{o: socksOptions{stallTimeout: stall}, log: NewLogger(io.Discard, false)}
}

func testSession() *session {
	return newSession(dialSpec{endpoint: netip.MustParseAddrPort("162.159.198.2:443"), transport: "h3", sni: "vk.com"}, nil)
}

func TestWatchDetectsStallWhenTxGrowsWithoutRx(t *testing.T) {
	rt := testRuntimeForWatch(2 * time.Second)
	s := testSession()
	s.rx.Store(1000)
	go func() {
		for i := 0; i < 40; i++ {
			s.tx.Add(64) // retransmissions into a dead path
			time.Sleep(100 * time.Millisecond)
		}
	}()
	started := time.Now()
	class, err := rt.watch(context.Background(), s)
	if class != ClassStall || err == nil {
		t.Fatalf("watch = %s %v, want stall", class, err)
	}
	if d := time.Since(started); d < 2*time.Second || d > 5*time.Second {
		t.Fatalf("stall reported after %v", d)
	}
}

// GM-1: an idle tunnel (no rx for longer than the stall timeout), then a burst of requests whose
// answers arrive after a normal RTT, is healthy. The stall clock must start at the first unanswered
// send, not at the last inbound packet minutes ago.
func TestWatchIdleThenAnsweredBurstIsNotStall(t *testing.T) {
	rt := testRuntimeForWatch(2 * time.Second)
	s := testSession()
	s.rx.Store(1000)
	s.tx.Store(1000)
	res := make(chan string, 1)
	go func() {
		class, _ := rt.watch(context.Background(), s)
		res <- class
	}()
	time.Sleep(3800 * time.Millisecond) // idle across three ticks
	s.tx.Add(350)                       // DNS A+AAAA to three servers
	time.Sleep(300 * time.Millisecond)
	s.rx.Add(200)
	select {
	case c := <-res:
		t.Fatalf("healthy tunnel reported as %q right after an idle period", c)
	case <-time.After(1500 * time.Millisecond):
	}
	s.fail(ClassClosed, nil)
	if c := <-res; c != ClassClosed {
		t.Fatalf("watch = %s after close, want closed", c)
	}
}

// GM-1: one-sided traffic that the tunnel still answers when asked (retransmits of flows a new
// egress drops) keeps the session; only a failed check probe makes it a stall.
func TestWatchKeepsASessionThatAnswersTheCheckProbe(t *testing.T) {
	rt := testRuntimeForWatch(2 * time.Second)
	var checks atomic.Int32
	rt.stallCheck = func(context.Context, *session) bool { return checks.Add(1) == 1 }
	s := testSession()
	s.rx.Store(1000)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				s.tx.Add(64)
			}
		}
	}()
	started := time.Now()
	class, err := rt.watch(context.Background(), s)
	if class != ClassStall || err == nil {
		t.Fatalf("watch = %s %v, want stall", class, err)
	}
	if n := checks.Load(); n != 2 {
		t.Fatalf("check probes = %d, want 2 (the first answered, the second did not)", n)
	}
	if d := time.Since(started); d < 4*time.Second {
		t.Fatalf("stall reported after %v, before the kept session could stall again", d)
	}
}

func TestWatchIgnoresIdleSessionAndReportsClose(t *testing.T) {
	rt := testRuntimeForWatch(2 * time.Second)
	s := testSession()
	go func() {
		time.Sleep(3500 * time.Millisecond) // idle longer than the stall timeout: not a stall
		s.fail(ClassClosed, errors.New("connect-ip: server closed the stream"))
	}()
	class, err := rt.watch(context.Background(), s)
	if class != ClassClosed || err == nil {
		t.Fatalf("watch = %s %v, want closed", class, err)
	}

	// A close caused by an access denial keeps that signature.
	s2 := testSession()
	s2.fail(ClassClosed, errors.New("CRYPTO_ERROR 0x131 (remote): tls: access denied"))
	if class, _ := rt.watch(context.Background(), s2); class != ClassAccessDenied {
		t.Fatalf("watch = %s, want access_denied", class)
	}
}

func TestWatchDetectsBlockedWrite(t *testing.T) {
	rt := testRuntimeForWatch(2 * time.Second)
	s := testSession()
	s.writeSince.Store(time.Now().UnixNano())
	class, err := rt.watch(context.Background(), s)
	if class != ClassStall || err == nil {
		t.Fatalf("watch = %s %v, want stall on a blocked write", class, err)
	}
}

func TestWatchStopsOnContext(t *testing.T) {
	rt := testRuntimeForWatch(2 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if class, err := rt.watch(ctx, testSession()); class != "" || err != nil {
		t.Fatalf("cancelled watch = %s %v", class, err)
	}
}
