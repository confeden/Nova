package warp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestFormatHitsSortsAndBracketsIPv6(t *testing.T) {
	hits := []Hit{
		{AddrPort: netip.MustParseAddrPort("162.159.192.1:500"), RTT: 120 * time.Millisecond},
		{AddrPort: netip.MustParseAddrPort("[2606:4700:d0::1]:2408"), RTT: 83 * time.Millisecond},
		{AddrPort: netip.MustParseAddrPort("188.114.96.7:4500"), RTT: 83*time.Millisecond + 900*time.Microsecond},
		{AddrPort: netip.MustParseAddrPort("188.114.99.2:854"), RTT: 900 * time.Microsecond},
		{AddrPort: netip.AddrPort{}, RTT: time.Millisecond},
	}
	got := FormatHits(hits)
	want := "188.114.99.2:854|1\n" +
		"[2606:4700:d0::1]:2408|83\n" +
		"188.114.96.7:4500|83\n" +
		"162.159.192.1:500|120\n"
	if got != want {
		t.Fatalf("FormatHits:\n got %q\nwant %q", got, want)
	}
	if hits[0].AddrPort.Port() != 500 {
		t.Fatal("FormatHits must not reorder the caller's slice")
	}
	if FormatHits(nil) != "" {
		t.Fatal("no hits must print nothing")
	}
}

func TestFormatHitsEqualRTTOrdersByAddress(t *testing.T) {
	hits := []Hit{
		{AddrPort: netip.MustParseAddrPort("[2606:4700:d1::5]:2408"), RTT: 50 * time.Millisecond},
		{AddrPort: netip.MustParseAddrPort("162.159.195.9:2408"), RTT: 50 * time.Millisecond},
		{AddrPort: netip.MustParseAddrPort("162.159.195.10:2408"), RTT: 50 * time.Millisecond},
	}
	want := "162.159.195.9:2408|50\n162.159.195.10:2408|50\n[2606:4700:d1::5]:2408|50\n"
	if got := FormatHits(hits); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func scanKeys() (string, string) {
	priv := make([]byte, 32)
	peer := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(200 - i)
		peer[i] = byte(i * 3)
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(peer)
}

func noRouteCheck(bool) error { return nil }

var testPrefixes = []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24"), netip.MustParsePrefix("fd00:1::/120")}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logSink) joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func TestScanStopsAtLimitAndSorts(t *testing.T) {
	priv, peer := scanKeys()
	var calls atomic.Int64
	probe := func(ctx context.Context, ip netip.Addr) (netip.AddrPort, time.Duration, error) {
		calls.Add(1)
		last := ip.As4()[3]
		if last%2 == 1 {
			return netip.AddrPort{}, 0, os.ErrDeadlineExceeded
		}
		return netip.AddrPortFrom(ip, 2408), time.Duration(10+int(last)) * time.Millisecond, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hits, stats, err := Scan(ctx, ScanOptions{
		PrivateKey: priv, PeerPublicKey: peer, IPv4: true, Limit: 7, Workers: 4, Prefixes: testPrefixes,
		probe: probe, routeCheck: noRouteCheck,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 7 || stats.Hits != 7 {
		t.Fatalf("hits = %d (stats %d), want 7", len(hits), stats.Hits)
	}
	for i, hit := range hits {
		if !hit.AddrPort.Addr().Is4() || !testPrefixes[0].Contains(hit.AddrPort.Addr()) {
			t.Fatalf("hit %v outside the requested family/prefix", hit.AddrPort)
		}
		if i > 0 && hits[i-1].RTT > hit.RTT {
			t.Fatalf("hits not sorted: %v", hits)
		}
	}
	if stats.Families != "v4" || int64(stats.Timeouts+stats.Hits) > calls.Load() {
		t.Fatalf("stats = %+v calls=%d", stats, calls.Load())
	}
}

func TestScanDropsSlowAndDeduplicates(t *testing.T) {
	priv, peer := scanKeys()
	single := []netip.Prefix{netip.MustParsePrefix("10.9.9.0/30")} // 4 addresses, reshuffled forever
	probe := func(ctx context.Context, ip netip.Addr) (netip.AddrPort, time.Duration, error) {
		time.Sleep(2 * time.Millisecond)
		switch ip.As4()[3] {
		case 0:
			return netip.AddrPortFrom(ip, 500), 3 * time.Second, nil // slower than rtt-max
		case 1:
			return netip.AddrPortFrom(ip, 500), 40 * time.Millisecond, nil
		default:
			return netip.AddrPort{}, 0, errors.New("invalid handshake response length 16 bytes")
		}
	}
	// Instant errors pause a worker for fastFailPause, so give the fake enough rounds to repeat addresses.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	started := time.Now()
	hits, stats, err := Scan(ctx, ScanOptions{
		PrivateKey: priv, PeerPublicKey: peer, IPv4: true, Limit: 50, MaxRTT: 1500 * time.Millisecond,
		Workers: 2, Prefixes: single, probe: probe, routeCheck: noRouteCheck,
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("scan ignored its deadline: %s", elapsed)
	}
	if len(hits) != 1 || hits[0].AddrPort != netip.MustParseAddrPort("10.9.9.1:500") {
		t.Fatalf("hits = %v, want only 10.9.9.1:500", hits)
	}
	if stats.TooSlow == 0 || stats.Duplicates == 0 || stats.Invalid == 0 {
		t.Fatalf("stats = %+v, want too_slow, duplicates and invalid counted", stats)
	}
}

func TestScanSwitchesOffFamilyThatFailsInstantly(t *testing.T) {
	priv, peer := scanKeys()
	var v6Calls atomic.Int64
	probe := func(ctx context.Context, ip netip.Addr) (netip.AddrPort, time.Duration, error) {
		if ip.Is6() {
			v6Calls.Add(1)
			return netip.AddrPort{}, 0, fmt.Errorf("dial: %w", syscall.Errno(10051))
		}
		time.Sleep(20 * time.Millisecond)
		return netip.AddrPortFrom(ip, 2408), 30 * time.Millisecond, nil
	}
	logs := &logSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	hits, stats, err := Scan(ctx, ScanOptions{
		PrivateKey: priv, PeerPublicKey: peer, Limit: 60, Workers: 8, Prefixes: testPrefixes,
		probe: probe, routeCheck: noRouteCheck, Logf: logs.logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Families != "v4+v6" {
		t.Fatalf("neither flag must mean both families, got %s", stats.Families)
	}
	if len(hits) != 60 {
		t.Fatalf("hits = %d, want 60", len(hits))
	}
	for _, hit := range hits {
		if hit.AddrPort.Addr().Is6() {
			t.Fatalf("v6 hit %v from a failing family", hit.AddrPort)
		}
	}
	// Either rule may fire first: instant failures, or silence while IPv4 answers.
	if !strings.Contains(logs.joined(), "IPv6 probes fail instantly") && !strings.Contains(logs.joined(), "switching IPv6 off") {
		t.Fatalf("no family switch-off logged:\n%s", logs.joined())
	}
	if stats.Unreachable == 0 {
		t.Fatalf("stats = %+v, want unreachable probes counted", stats)
	}
	// Once off, the family gets no further probes beyond those already in flight.
	if n := v6Calls.Load(); n > int64(fastFailLimit+8+8) {
		t.Fatalf("v6 probed %d times after being switched off", n)
	}
}

func TestScanSwitchesOffSilentFamilyWhileOtherAnswers(t *testing.T) {
	priv, peer := scanKeys()
	var v6Calls atomic.Int64
	probe := func(ctx context.Context, ip netip.Addr) (netip.AddrPort, time.Duration, error) {
		time.Sleep(300 * time.Millisecond) // slower than fastFailWindow: a real timeout, not a missing route
		if ip.Is6() {
			v6Calls.Add(1)
			return netip.AddrPort{}, 0, os.ErrDeadlineExceeded
		}
		return netip.AddrPortFrom(ip, 2408), 30 * time.Millisecond, nil
	}
	logs := &logSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	hits, _, err := Scan(ctx, ScanOptions{
		PrivateKey: priv, PeerPublicKey: peer, Limit: 100, Workers: 16, Prefixes: testPrefixes,
		probe: probe, routeCheck: noRouteCheck, Logf: logs.logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 100 {
		t.Fatalf("hits = %d, want 100", len(hits))
	}
	if !strings.Contains(logs.joined(), "IPv6 probes and no answer while IPv4 answers") {
		t.Fatalf("silent family not switched off:\n%s", logs.joined())
	}
	if n := v6Calls.Load(); n > int64(silentFamilyLimit+16+1) {
		t.Fatalf("v6 probed %d times", n)
	}
}

func TestScanKeepsLastFamilyEvenWhenSilent(t *testing.T) {
	priv, peer := scanKeys()
	probe := func(ctx context.Context, ip netip.Addr) (netip.AddrPort, time.Duration, error) {
		time.Sleep(260 * time.Millisecond)
		return netip.AddrPort{}, 0, os.ErrDeadlineExceeded
	}
	logs := &logSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	_, stats, err := Scan(ctx, ScanOptions{
		PrivateKey: priv, PeerPublicKey: peer, Limit: 5, Workers: 32, Prefixes: testPrefixes,
		probe: probe, routeCheck: noRouteCheck, Logf: logs.logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.joined(), "switching") {
		t.Fatalf("a family was switched off with no family answering:\n%s", logs.joined())
	}
	if time.Since(started) < 1500*time.Millisecond || stats.Timeouts == 0 {
		t.Fatalf("scan must run to its deadline when nothing answers: %s %+v", time.Since(started), stats)
	}
}

func TestScanEndsEarlyWhenEveryFamilyFailsInstantly(t *testing.T) {
	priv, peer := scanKeys()
	probe := func(ctx context.Context, ip netip.Addr) (netip.AddrPort, time.Duration, error) {
		return netip.AddrPort{}, 0, fmt.Errorf("write: %w", syscall.Errno(10065))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	started := time.Now()
	hits, stats, err := Scan(ctx, ScanOptions{
		PrivateKey: priv, PeerPublicKey: peer, Limit: 5, Workers: 16, Prefixes: testPrefixes,
		probe: probe, routeCheck: noRouteCheck,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("hits = %v", hits)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("scan kept spinning for %s with no usable family", elapsed)
	}
	if stats.Unreachable == 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestScanRouteCheckDropsFamily(t *testing.T) {
	priv, peer := scanKeys()
	routeCheck := func(v6 bool) error {
		if v6 {
			return errors.New("connect: A socket operation was attempted to an unreachable network.")
		}
		return nil
	}
	var sawV6 atomic.Bool
	probe := func(ctx context.Context, ip netip.Addr) (netip.AddrPort, time.Duration, error) {
		if ip.Is6() {
			sawV6.Store(true)
		}
		return netip.AddrPortFrom(ip, 854), 5 * time.Millisecond, nil
	}
	hits, stats, err := Scan(context.Background(), ScanOptions{
		PrivateKey: priv, PeerPublicKey: peer, IPv4: true, IPv6: true, Limit: 3, Workers: 2,
		Prefixes: testPrefixes, probe: probe, routeCheck: routeCheck,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Families != "v4" || sawV6.Load() || len(hits) != 3 {
		t.Fatalf("families=%s sawV6=%t hits=%d", stats.Families, sawV6.Load(), len(hits))
	}

	none := func(bool) error { return errors.New("no route") }
	hits, stats, err = Scan(context.Background(), ScanOptions{
		PrivateKey: priv, PeerPublicKey: peer, Limit: 3, Prefixes: testPrefixes, probe: probe, routeCheck: none,
	})
	if err != nil || len(hits) != 0 || stats.Families != "none" {
		t.Fatalf("no route at all: hits=%d families=%s err=%v", len(hits), stats.Families, err)
	}
}

func TestScanRejectsBadKeysWithoutEchoing(t *testing.T) {
	priv, peer := scanKeys()
	secret := priv[:20]
	_, _, err := Scan(context.Background(), ScanOptions{PrivateKey: secret, PeerPublicKey: peer, routeCheck: noRouteCheck})
	if !errors.Is(err, ErrUsage) || strings.Contains(err.Error(), secret) {
		t.Fatalf("bad private key: err = %v", err)
	}
	_, _, err = Scan(context.Background(), ScanOptions{PrivateKey: priv, PeerPublicKey: "nope", routeCheck: noRouteCheck})
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("bad peer key: err = %v", err)
	}
	_, _, err = Scan(context.Background(), ScanOptions{
		PrivateKey: priv, PeerPublicKey: peer, IPv6: true, routeCheck: noRouteCheck,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("family without prefixes: err = %v", err)
	}
}

func TestScanStatsClassify(t *testing.T) {
	var s ScanStats
	s.classify(fmt.Errorf("read: %w", os.ErrDeadlineExceeded))
	s.classify(fmt.Errorf("read: %w", syscall.Errno(10054)))
	s.classify(fmt.Errorf("dial: %w", syscall.Errno(10051)))
	s.classify(errors.New("invalid sender index in response"))
	s.classify(errors.New("chacha20poly1305: message authentication failed"))
	s.classify(errors.New("something else"))
	if s.Timeouts != 1 || s.Refused != 1 || s.Unreachable != 1 || s.Invalid != 2 || s.Other != 1 {
		t.Fatalf("classify = %+v", s)
	}
}
