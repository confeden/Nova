package warp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bepass-org/warp-plus/ipscanner/iterator"
	"github.com/bepass-org/warp-plus/ipscanner/statute"
	wpwarp "github.com/bepass-org/warp-plus/warp"
)

const (
	DefaultScanLimit   = 50
	DefaultScanMaxRTT  = 1500 * time.Millisecond
	DefaultScanWorkers = 16
	MaxScanWorkers     = 128

	// A probe that errors this fast never reached the wire (no route for the family); the real
	// handshake spends at least 1.6 s on cover packets before it can fail on its own.
	fastFailWindow = 250 * time.Millisecond
	fastFailPause  = 250 * time.Millisecond
	// fastFailLimit fast failures with no hit in a family switch that family off for the run.
	fastFailLimit = 24
	// silentFamilyLimit failed probes with no hit switch a family off while the other family has
	// hits: a route that exists but carries nothing (a tunnel adapter's IPv6) ends in timeouts only.
	silentFamilyLimit = 16
	progressEvery     = 10 * time.Second
)

// ScanOptions configures Scan.
type ScanOptions struct {
	PrivateKey    string // base64; the device's WireGuard private key
	PeerPublicKey string // base64; config.peers[0].public_key of the registration
	IPv4, IPv6    bool   // neither set means both
	Limit         int    // stop after this many verified hits; default DefaultScanLimit
	MaxRTT        time.Duration
	Workers       int
	Prefixes      []netip.Prefix // default warp-plus WarpPrefixes()
	Logf          Logf

	probe      func(ctx context.Context, ip netip.Addr) (netip.AddrPort, time.Duration, error)
	routeCheck func(v6 bool) error
}

// Hit is an endpoint that answered a WireGuard handshake initiation for our identity.
type Hit struct {
	AddrPort netip.AddrPort
	RTT      time.Duration
}

// ScanStats counts what the probes saw.
type ScanStats struct {
	Probes      int64
	Hits        int
	Duplicates  int
	TooSlow     int
	Timeouts    int
	Refused     int
	Unreachable int
	Invalid     int
	Other       int
	LastError   string
	Families    string
	Elapsed     time.Duration
}

type scanResult struct {
	addrPort netip.AddrPort
	rtt      time.Duration
	err      error
}

// Scan walks the WARP prefixes with warp-plus's LCG address iterator and probes each address with
// a WireGuard handshake modelled on warp-plus's ping (Noise IK with our key, mac1, cover packets
// first; a hit is a decrypted handshake response, not "something listens"; see handshake.go for
// where it departs from the fork). The stock ipscanner engine pings one address per prefix per
// run, one at a time, so its RTT queue is replaced here by Workers concurrent probes and a plain
// result set. Scan stops at Limit hits or when ctx ends and returns the hits sorted by RTT. Only
// bad options produce an error (wrapping ErrUsage).
//
// Scan does not wait for probes still in flight when it returns; the built-in probe closes its
// socket when the scan's context ends, so those goroutines finish promptly.
func Scan(ctx context.Context, opts ScanOptions) ([]Hit, ScanStats, error) {
	var stats ScanStats
	started := time.Now()
	logf := opts.Logf

	privRaw, err := DecodeKey(opts.PrivateKey)
	if err != nil {
		return nil, stats, fmt.Errorf("private key: %w", err)
	}
	peerRaw, err := DecodeKey(opts.PeerPublicKey)
	if err != nil {
		return nil, stats, fmt.Errorf("peer public key: %w", err)
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = DefaultScanLimit
	}
	maxRTT := opts.MaxRTT
	if maxRTT <= 0 {
		maxRTT = DefaultScanMaxRTT
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = DefaultScanWorkers
	}
	workers = min(workers, MaxScanWorkers)
	useV4, useV6 := opts.IPv4, opts.IPv6
	if !useV4 && !useV6 {
		useV4, useV6 = true, true
	}
	prefixes := opts.Prefixes
	if len(prefixes) == 0 {
		prefixes = wpwarp.WarpPrefixes()
	}
	routeCheck := opts.routeCheck
	if routeCheck == nil {
		routeCheck = udpRouteCheck
	}

	// A family without a route is dropped up front instead of burning probes.
	if useV4 {
		if err := routeCheck(false); err != nil {
			logf.printf("scan: IPv4 has no route (%v), skipping it", err)
			useV4 = false
		}
	}
	if useV6 {
		if err := routeCheck(true); err != nil {
			logf.printf("scan: IPv6 has no route (%v), skipping it", err)
			useV6 = false
		}
	}
	stats.Families = familiesLabel(useV4, useV6)
	if !useV4 && !useV6 {
		stats.Elapsed = time.Since(started)
		return nil, stats, nil
	}

	// The iterator reads only the family switches and the prefix list.
	scanOpts := &statute.ScannerOptions{
		UseIPv4:         useV4,
		UseIPv6:         useV6,
		CidrList:        prefixes,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		IPQueueSize:     limit,
		IPQueueTTL:      30 * time.Second,
		MaxDesirableRTT: maxRTT,
	}
	gen := iterator.NewIterator(scanOpts)
	if gen == nil {
		return nil, stats, fmt.Errorf("%w: no scan prefix matches the requested address families", ErrUsage)
	}
	probe := opts.probe
	if probe == nil {
		keys, err := newHandshakeKeys(privRaw, peerRaw)
		if err != nil {
			return nil, stats, err
		}
		probe = func(ctx context.Context, ip netip.Addr) (netip.AddrPort, time.Duration, error) {
			addrPort := netip.AddrPortFrom(ip, wpwarp.RandomWarpPort())
			rtt, err := warpHandshake(ctx, addrPort, keys, defaultHandshakeConfig)
			if err != nil {
				return netip.AddrPort{}, 0, err
			}
			return addrPort, rtt, nil
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	logf.printf("scan: families=%s prefixes=%d workers=%d limit=%d rtt_max=%s", stats.Families, len(prefixes), workers, limit, maxRTT)

	var (
		disabled    [2]atomic.Bool
		fastFails   [2]atomic.Int64
		familyFails [2]atomic.Int64
		familyHits  [2]atomic.Int64
		probes      atomic.Int64
	)
	disabled[0].Store(!useV4)
	disabled[1].Store(!useV6)

	addrs := make(chan netip.Addr)
	go func() {
		defer close(addrs)
		for ctx.Err() == nil {
			batch, err := gen.NextBatch()
			if err != nil {
				logf.printf("scan: address iterator stopped: %v", err)
				return
			}
			for _, ip := range batch {
				if disabled[familyIndex(ip)].Load() {
					continue
				}
				select {
				case addrs <- ip:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	results := make(chan scanResult, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				var ip netip.Addr
				select {
				case <-ctx.Done():
					return
				case next, ok := <-addrs:
					if !ok {
						return
					}
					ip = next
				}
				family := familyIndex(ip)
				probes.Add(1)
				t0 := time.Now()
				addrPort, rtt, err := probe(ctx, ip)
				elapsed := time.Since(t0)
				if err != nil && ctx.Err() != nil {
					return // cancelled mid-probe: not an observation
				}
				if err == nil {
					familyHits[family].Add(1)
				}
				select {
				case results <- scanResult{addrPort: addrPort, rtt: rtt, err: err}:
				case <-ctx.Done():
					return
				}
				if err == nil {
					continue
				}
				other := 1 - family
				if familyFails[family].Add(1) >= silentFamilyLimit && familyHits[family].Load() == 0 &&
					familyHits[other].Load() > 0 && !disabled[other].Load() && disabled[family].CompareAndSwap(false, true) {
					logf.printf("scan: %d %s probes and no answer while %s answers, switching %s off",
						familyFails[family].Load(), familyName(family), familyName(other), familyName(family))
				}
				if elapsed >= fastFailWindow {
					continue
				}
				if fastFails[family].Add(1) >= fastFailLimit && familyHits[family].Load() == 0 &&
					disabled[family].CompareAndSwap(false, true) {
					logf.printf("scan: %s probes fail instantly (%v), switching the family off", familyName(family), err)
					if disabled[0].Load() && disabled[1].Load() {
						cancel()
						return
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(fastFailPause):
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	best := make(map[netip.AddrPort]time.Duration)
	accept := func(res scanResult) {
		if res.err != nil {
			stats.classify(res.err)
			return
		}
		if !res.addrPort.IsValid() {
			stats.Other++
			return
		}
		if res.rtt > maxRTT {
			stats.TooSlow++
			return
		}
		if prev, seen := best[res.addrPort]; seen {
			stats.Duplicates++
			if res.rtt < prev {
				best[res.addrPort] = res.rtt
			}
			return
		}
		best[res.addrPort] = res.rtt
	}

	ticker := time.NewTicker(progressEvery)
	defer ticker.Stop()
collect:
	for len(best) < limit {
		select {
		case res, ok := <-results:
			if !ok {
				break collect
			}
			accept(res)
		case <-ticker.C:
			logf.printf("scan: progress probes=%d hits=%d", probes.Load(), len(best))
		case <-ctx.Done():
			// Results that landed before the deadline still count.
			for len(best) < limit {
				select {
				case res, ok := <-results:
					if !ok {
						break collect
					}
					accept(res)
				default:
					break collect
				}
			}
			break collect
		}
	}
	cancel()

	hits := make([]Hit, 0, len(best))
	for addrPort, rtt := range best {
		hits = append(hits, Hit{AddrPort: addrPort, RTT: rtt})
	}
	sortHits(hits)
	if len(hits) > limit {
		hits = hits[:limit]
	}
	stats.Probes = probes.Load()
	stats.Hits = len(hits)
	stats.Elapsed = time.Since(started)
	logf.printf("scan: done in %s probes=%d hits=%d duplicates=%d too_slow=%d timeouts=%d refused=%d unreachable=%d invalid=%d other=%d",
		stats.Elapsed.Round(100*time.Millisecond), stats.Probes, stats.Hits, stats.Duplicates, stats.TooSlow,
		stats.Timeouts, stats.Refused, stats.Unreachable, stats.Invalid, stats.Other)
	if stats.LastError != "" {
		logf.printf("scan: last probe error: %s", stats.LastError)
	}
	return hits, stats, nil
}

func (s *ScanStats) classify(err error) {
	s.LastError = err.Error()
	var netErr net.Error
	var errno syscall.Errno
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		s.Timeouts++
	case errors.As(err, &errno):
		switch errno {
		case 10054, 10061, syscall.ECONNRESET, syscall.ECONNREFUSED: // WSAECONNRESET, WSAECONNREFUSED
			s.Refused++
		case 10051, 10065, syscall.ENETUNREACH, syscall.EHOSTUNREACH: // WSAENETUNREACH, WSAEHOSTUNREACH
			s.Unreachable++
		default:
			s.Other++
		}
	default:
		msg := err.Error()
		switch {
		case strings.Contains(msg, "invalid handshake response"), strings.Contains(msg, "invalid response type"),
			strings.Contains(msg, "invalid sender index"), strings.Contains(msg, "unexpected payload"),
			strings.Contains(msg, "authentication failed"):
			s.Invalid++
		default:
			s.Other++
		}
	}
}

// FormatHits renders hits sorted by RTT, one "addr:port|rtt_ms" per line with IPv6 bracketed
// ("[2606:4700:d0::1]:2408|83"). An RTT under 1 ms prints as 1: a zero or negative value reads as
// "unverified" to the Android-shaped parsers.
func FormatHits(hits []Hit) string {
	sorted := slices.Clone(hits)
	sortHits(sorted)
	var sb strings.Builder
	for _, hit := range sorted {
		if !hit.AddrPort.IsValid() {
			continue
		}
		sb.WriteString(hit.AddrPort.String())
		sb.WriteByte('|')
		sb.WriteString(strconv.FormatInt(max(hit.RTT.Milliseconds(), 1), 10))
		sb.WriteByte('\n')
	}
	return sb.String()
}

func sortHits(hits []Hit) {
	slices.SortStableFunc(hits, func(a, b Hit) int {
		if a.RTT != b.RTT {
			if a.RTT < b.RTT {
				return -1
			}
			return 1
		}
		return a.AddrPort.Compare(b.AddrPort)
	})
}

func familyIndex(ip netip.Addr) int {
	if ip.Unmap().Is4() {
		return 0
	}
	return 1
}

func familyName(index int) string {
	if index == 0 {
		return "IPv4"
	}
	return "IPv6"
}

func familiesLabel(v4, v6 bool) string {
	switch {
	case v4 && v6:
		return "v4+v6"
	case v4:
		return "v4"
	case v6:
		return "v6"
	default:
		return "none"
	}
}

// udpRouteCheck connects (no packet is sent) a UDP socket to a WARP address of the family; the OS
// fails it at once when the family has no route.
func udpRouteCheck(v6 bool) error {
	network, target := "udp4", "162.159.192.1:2408"
	if v6 {
		network, target = "udp6", "[2606:4700:d0::a29f:c001]:2408"
	}
	conn, err := net.Dial(network, target)
	if err != nil {
		return err
	}
	return conn.Close()
}
