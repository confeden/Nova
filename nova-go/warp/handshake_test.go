package warp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

// fastHandshake keeps the fork's shape with short pauses so a probe takes milliseconds.
var fastHandshake = handshakeConfig{
	coverMin: 3, coverMax: 6,
	coverSizeMin: 40, coverSizeMax: 100,
	coverGapMin: time.Millisecond, coverGapMax: 3 * time.Millisecond,
	readTimeout: 2 * time.Second,
}

// fakeWARP is a WireGuard responder on a loopback UDP port that behaves like the WARP edge:
// it answers a datagram starting with 4 with 16 bytes "cf000000...", ignores other junk, and answers
// a valid initiation with a handshake response.
type fakeWARP struct {
	conn   *net.UDPConn
	static noise.DHKey

	coverReplyAll bool // answer every cover packet, not just type-4 ones
	forgeFirst    bool // send a type-2 datagram for index 28 with garbage before the real response
	silent        bool // never answer an initiation

	mu         sync.Mutex
	coverFirst []byte
	initiated  int
	mac1Bad    int
}

func newFakeWARP(t *testing.T) *fakeWARP {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeWARP{conn: conn, static: noise.DHKey{Private: priv, Public: pub}}
	t.Cleanup(func() { _ = conn.Close() })
	return f
}

func (f *fakeWARP) start() { go f.serve() }

func (f *fakeWARP) addr() netip.AddrPort {
	return f.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (f *fakeWARP) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		p := append([]byte(nil), buf[:n]...)
		if n != wgInitiationSize || binary.LittleEndian.Uint32(p[:4]) != wgMessageInitiation {
			f.mu.Lock()
			f.coverFirst = append(f.coverFirst, p[0])
			f.mu.Unlock()
			if p[0] == 4 || f.coverReplyAll {
				reply := make([]byte, 16)
				copy(reply, []byte{0xcf, 0, 0, 0})
				_, _ = rand.Read(reply[4:])
				_, _ = f.conn.WriteToUDPAddrPort(reply, from)
			}
			continue
		}
		response, ok := f.respond(p)
		if !ok || f.silent {
			continue
		}
		if f.forgeFirst {
			forged := make([]byte, wgResponseSize)
			_, _ = rand.Read(forged)
			binary.LittleEndian.PutUint32(forged[0:4], wgMessageResponse)
			binary.LittleEndian.PutUint32(forged[8:12], probeSenderIndex)
			_, _ = f.conn.WriteToUDPAddrPort(forged, from)
		}
		_, _ = f.conn.WriteToUDPAddrPort(response, from)
	}
}

// respond checks mac1 and runs the responder side of Noise IKpsk2.
func (f *fakeWARP) respond(p []byte) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.initiated++
	key := blake2s.Sum256(append([]byte("mac1----"), f.static.Public...))
	mac, _ := blake2s.New128(key[:])
	mac.Write(p[:116])
	if string(mac.Sum(nil)) != string(p[116:132]) {
		f.mac1Bad++
		return nil, false
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: wgCipherSuite, Pattern: noise.HandshakeIK, Initiator: false,
		StaticKeypair: f.static, Prologue: wgPrologue,
		PresharedKey: make([]byte, 32), PresharedKeyPlacement: 2,
	})
	if err != nil {
		return nil, false
	}
	stamp, _, _, err := hs.ReadMessage(nil, p[8:116])
	if err != nil || len(stamp) != 12 {
		return nil, false
	}
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, false
	}
	out := binary.LittleEndian.AppendUint32(nil, wgMessageResponse)
	out = binary.LittleEndian.AppendUint32(out, 0x5eed)
	out = append(out, p[4:8]...) // receiver = the initiator's sender index
	out = append(out, msg...)
	out = append(out, make([]byte, 32)...) // mac1 + mac2, not checked by the probe
	return out, len(out) == wgResponseSize
}

func (f *fakeWARP) keysFor(t *testing.T) *handshakeKeys {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	keys, err := newHandshakeKeys(priv, f.static.Public)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestHandshakeSkipsQueuedCoverReplies(t *testing.T) {
	srv := newFakeWARP(t)
	srv.coverReplyAll = true // every cover reply is queued in front of the handshake response
	srv.start()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rtt, err := warpHandshake(ctx, srv.addr(), srv.keysFor(t), fastHandshake)
	if err != nil {
		t.Fatalf("handshake failed behind queued 16-byte cover replies: %v", err)
	}
	if rtt <= 0 || rtt > fastHandshake.readTimeout {
		t.Fatalf("rtt = %s", rtt)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.initiated != 1 || srv.mac1Bad != 0 || len(srv.coverFirst) < fastHandshake.coverMin {
		t.Fatalf("initiations=%d mac1Bad=%d covers=%d", srv.initiated, srv.mac1Bad, len(srv.coverFirst))
	}
}

func TestHandshakeCoverNeverLooksLikeWireGuard(t *testing.T) {
	p := make([]byte, 40)
	seen := make(map[byte]bool)
	for range 20000 {
		if err := fillCover(p); err != nil {
			t.Fatal(err)
		}
		if p[0] >= 1 && p[0] <= 4 {
			t.Fatalf("cover packet starts with WireGuard type %d", p[0])
		}
		seen[p[0]] = true
	}
	if len(seen) < 200 || seen[0] {
		t.Fatalf("cover first byte covers %d values (zero seen: %t), want 5..255", len(seen), seen[0])
	}

	// End to end: the edge answers type-4 junk, so no cover packet may provoke a reply.
	srv := newFakeWARP(t)
	srv.start()
	cfg := fastHandshake
	cfg.coverMin, cfg.coverMax = 60, 61
	cfg.coverGapMin, cfg.coverGapMax = 0, 1
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := warpHandshake(ctx, srv.addr(), srv.keysFor(t), cfg); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, b := range srv.coverFirst {
		if b >= 1 && b <= 4 {
			t.Fatalf("cover packet on the wire starts with %d", b)
		}
	}
}

func TestHandshakeForgedResponseDoesNotHideTheRealOne(t *testing.T) {
	srv := newFakeWARP(t)
	srv.forgeFirst = true
	srv.start()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := warpHandshake(ctx, srv.addr(), srv.keysFor(t), fastHandshake); err != nil {
		t.Fatalf("a forged datagram spoiled the real response: %v", err)
	}
}

func TestHandshakeWrongPeerKeyIsNotAHit(t *testing.T) {
	srv := newFakeWARP(t)
	srv.start()
	other := newFakeWARP(t) // its public key is not the server's
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := fastHandshake
	cfg.readTimeout = 400 * time.Millisecond
	_, err := warpHandshake(ctx, srv.addr(), other.keysFor(t), cfg)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want a timeout (the server drops a bad mac1)", err)
	}
	var stats ScanStats
	stats.classify(err)
	if stats.Timeouts != 1 {
		t.Fatalf("classified as %+v", stats)
	}
}

func TestHandshakeOnlyForgedAnswerIsInvalid(t *testing.T) {
	keys := newFakeWARP(t).keysFor(t)
	// A socket that answers the initiation only with a response-shaped datagram that does not decrypt.
	raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := raw.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n == wgInitiationSize {
				forged := make([]byte, wgResponseSize)
				_, _ = rand.Read(forged)
				binary.LittleEndian.PutUint32(forged[0:4], wgMessageResponse)
				binary.LittleEndian.PutUint32(forged[8:12], probeSenderIndex)
				_, _ = raw.WriteToUDPAddrPort(forged, from)
			}
		}
	}()
	cfg := fastHandshake
	cfg.readTimeout = 400 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = warpHandshake(ctx, raw.LocalAddr().(*net.UDPAddr).AddrPort(), keys, cfg)
	if err == nil {
		t.Fatal("a forged response was accepted")
	}
	var stats ScanStats
	stats.classify(err)
	if stats.Invalid != 1 {
		t.Fatalf("err = %v classified as %+v, want invalid", err, stats)
	}
}

func TestHandshakeHonoursContext(t *testing.T) {
	srv := newFakeWARP(t)
	srv.silent = true
	srv.start()
	cfg := fastHandshake
	cfg.readTimeout = 30 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	started := time.Now()
	_, err := warpHandshake(ctx, srv.addr(), srv.keysFor(t), cfg)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("cancelled read took %s", elapsed)
	}

	// Cancelled during the cover phase.
	cfg.coverMin, cfg.coverMax = 1000, 1001
	cfg.coverGapMin, cfg.coverGapMax = 50*time.Millisecond, 51*time.Millisecond
	ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started = time.Now()
	_, err = warpHandshake(ctx, srv.addr(), srv.keysFor(t), cfg)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second {
		t.Fatalf("cover phase: err = %v after %s", err, time.Since(started))
	}
}

func TestHandshakeNoAnswerAfterJunkIsTimeout(t *testing.T) {
	srv := newFakeWARP(t)
	srv.coverReplyAll = true
	srv.silent = true
	srv.start()
	cfg := fastHandshake
	cfg.readTimeout = 400 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := warpHandshake(ctx, srv.addr(), srv.keysFor(t), cfg)
	if !errors.Is(err, os.ErrDeadlineExceeded) || !strings.Contains(err.Error(), "unrelated datagrams ignored") {
		t.Fatalf("err = %v", err)
	}
}

func TestInitiationWireFormat(t *testing.T) {
	srv := newFakeWARP(t)
	keys := srv.keysFor(t)
	in, err := newInitiation(keys, time.Unix(1757740000, 123456789))
	if err != nil {
		t.Fatal(err)
	}
	p := in.packet
	if len(p) != wgInitiationSize || binary.LittleEndian.Uint32(p[0:4]) != 1 || binary.LittleEndian.Uint32(p[4:8]) != 28 {
		t.Fatalf("header % x", p[:8])
	}
	if string(p[132:]) != string(make([]byte, 16)) {
		t.Fatal("mac2 must be zero without a cookie")
	}
	// The rebuilt state writes the same message: verify() depends on it.
	_, msg, err := in.state()
	if err != nil || string(msg) != string(p[8:116]) {
		t.Fatalf("state() is not deterministic: err=%v", err)
	}
	if _, ok := srv.respond(p); !ok {
		t.Fatal("a WireGuard responder rejected the initiation")
	}
}
