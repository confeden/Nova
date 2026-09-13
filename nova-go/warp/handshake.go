package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

// The scan's handshake probe. It is the warp-plus ipscanner ping (Noise IKpsk2 with our static
// key, mac1, sender index 28, random cover packets first) with three differences:
//
//   - A cover packet never starts with 1..4. The WARP edge answers a datagram that starts with 4
//     (a WireGuard data message for an unknown receiver) with a 16-byte "cf000000..." packet
//     (measured), and the fork then read that queued reply instead of the handshake response:
//     about one genuine endpoint in eight was reported as "invalid handshake response length 16".
//   - After the initiation the socket is read until the deadline, skipping every datagram that is
//     not a handshake response for index 28, and the Noise state is rebuilt for each candidate so a
//     forged datagram cannot spoil the check of the real one.
//   - The context is honoured: cover pauses select on it and its end closes the socket.

const (
	wgMessageInitiation = 1
	wgMessageResponse   = 2
	wgInitiationSize    = 148 // type 4 + sender 4 + noise 108 + mac1 16 + mac2 16
	wgResponseMinSize   = 60  // type 4 + sender 4 + receiver 4 + noise 48
	wgResponseSize      = 92  // ... + mac1 16 + mac2 16
	probeSenderIndex    = 28

	// wsaEMSGSIZE: Windows reports a datagram larger than the read buffer as an error.
	wsaEMSGSIZE = syscall.Errno(10040)
)

var (
	wgPrologue    = []byte("WireGuard v1 zx2c4 Jason@zx2c4.com")
	wgCipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
)

// handshakeConfig shapes one probe. Ranges are [min, max), as in the fork.
type handshakeConfig struct {
	coverMin, coverMax         int
	coverSizeMin, coverSizeMax int
	coverGapMin, coverGapMax   time.Duration
	readTimeout                time.Duration
}

// defaultHandshakeConfig matches the fork: 20..49 cover packets of 40..99 bytes, 80..149 ms apart,
// then 5 s for the response.
var defaultHandshakeConfig = handshakeConfig{
	coverMin: 20, coverMax: 50,
	coverSizeMin: 40, coverSizeMax: 100,
	coverGapMin: 80 * time.Millisecond, coverGapMax: 150 * time.Millisecond,
	readTimeout: 5 * time.Second,
}

// handshakeKeys is the identity a probe authenticates with.
type handshakeKeys struct {
	static noise.DHKey
	peer   []byte
	mac1   [32]byte // BLAKE2s-256("mac1----" || peer public key)
}

func newHandshakeKeys(privateRaw, peerRaw []byte) (*handshakeKeys, error) {
	if len(privateRaw) != 32 || len(peerRaw) != 32 {
		return nil, fmt.Errorf("%w: handshake keys must be 32 bytes", ErrUsage)
	}
	public, err := curve25519.X25519(privateRaw, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("%w: unusable private key", ErrUsage)
	}
	keys := &handshakeKeys{
		static: noise.DHKey{Private: bytes.Clone(privateRaw), Public: public},
		peer:   bytes.Clone(peerRaw),
	}
	keys.mac1 = blake2s.Sum256(append([]byte("mac1----"), peerRaw...))
	return keys, nil
}

// initiation is one handshake attempt. The ephemeral key and timestamp are fixed, so state()
// rebuilds the exact Noise state that produced the packet.
type initiation struct {
	keys      *handshakeKeys
	ephemeral [32]byte
	stamp     [12]byte // TAI64N
	packet    []byte
}

func newInitiation(keys *handshakeKeys, now time.Time) (*initiation, error) {
	in := &initiation{keys: keys}
	if _, err := rand.Read(in.ephemeral[:]); err != nil {
		return nil, err
	}
	now = now.UTC()
	binary.BigEndian.PutUint64(in.stamp[:8], uint64(4611686018427387914+now.Unix()))
	binary.BigEndian.PutUint32(in.stamp[8:], uint32(now.Nanosecond()))

	_, msg, err := in.state()
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 0, wgInitiationSize)
	packet = binary.LittleEndian.AppendUint32(packet, wgMessageInitiation)
	packet = binary.LittleEndian.AppendUint32(packet, probeSenderIndex)
	packet = append(packet, msg...)
	mac, err := blake2s.New128(keys.mac1[:])
	if err != nil {
		return nil, err
	}
	mac.Write(packet)
	packet = mac.Sum(packet)
	packet = append(packet, make([]byte, 16)...) // mac2: no cookie
	if len(packet) != wgInitiationSize {
		return nil, fmt.Errorf("initiation is %d bytes, want %d", len(packet), wgInitiationSize)
	}
	in.packet = packet
	return in, nil
}

// state returns a fresh initiator state that has written the first message, and that message.
func (in *initiation) state() (*noise.HandshakeState, []byte, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           wgCipherSuite,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		StaticKeypair:         in.keys.static,
		PeerStatic:            in.keys.peer,
		Prologue:              wgPrologue,
		PresharedKey:          make([]byte, 32),
		PresharedKeyPlacement: 2,
		Random:                bytes.NewReader(in.ephemeral[:]), // noise draws the ephemeral key from here
	})
	if err != nil {
		return nil, nil, err
	}
	msg, _, _, err := hs.WriteMessage(nil, in.stamp[:])
	if err != nil {
		return nil, nil, err
	}
	return hs, msg, nil
}

// isCandidate: shaped like a handshake response to our initiation (not yet authenticated).
func isCandidate(p []byte) bool {
	return len(p) >= wgResponseMinSize && len(p) <= wgResponseSize &&
		binary.LittleEndian.Uint32(p[0:4]) == wgMessageResponse &&
		binary.LittleEndian.Uint32(p[8:12]) == probeSenderIndex
}

// verify authenticates a candidate response: the Noise message must decrypt to an empty payload.
func (in *initiation) verify(p []byte) error {
	hs, _, err := in.state()
	if err != nil {
		return err
	}
	payload, _, _, err := hs.ReadMessage(nil, p[12:wgResponseMinSize])
	if err != nil {
		return err
	}
	if len(payload) != 0 {
		return errors.New("invalid handshake response: unexpected payload")
	}
	return nil
}

// fillCover fills p with random bytes whose first byte is outside 1..4, the WireGuard message
// types; the WARP edge answers type 4 and that answer would sit in front of the real response.
func fillCover(p []byte) error {
	if _, err := rand.Read(p); err != nil {
		return err
	}
	if len(p) > 0 {
		p[0] = byte(5 + int(p[0])%251)
	}
	return nil
}

func randomBetween(lo, hi int64) int64 {
	if hi-lo < 1 {
		return lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(hi-lo))
	if err != nil {
		return lo
	}
	return lo + n.Int64()
}

// warpHandshake sends the cover packets and the initiation to addr and returns the time from the
// initiation to the first authenticated response.
func warpHandshake(ctx context.Context, addr netip.AddrPort, keys *handshakeKeys, cfg handshakeConfig) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	in, err := newInitiation(keys, time.Now())
	if err != nil {
		return 0, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", addr.String())
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	cancelled := func(err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}

	cover := make([]byte, max(cfg.coverSizeMax, 1))
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for range randomBetween(int64(cfg.coverMin), int64(cfg.coverMax)) {
		packet := cover[:randomBetween(int64(cfg.coverSizeMin), int64(cfg.coverSizeMax))]
		if err := fillCover(packet); err != nil {
			return 0, fmt.Errorf("error generating random packet: %w", err)
		}
		if _, err := conn.Write(packet); err != nil {
			return 0, cancelled(fmt.Errorf("error sending random packet: %w", err))
		}
		timer.Reset(time.Duration(randomBetween(int64(cfg.coverGapMin), int64(cfg.coverGapMax))))
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-timer.C:
		}
	}

	if _, err := conn.Write(in.packet); err != nil {
		return 0, cancelled(err)
	}
	sent := time.Now()
	if err := conn.SetReadDeadline(sent.Add(cfg.readTimeout)); err != nil {
		return 0, cancelled(err)
	}

	buf := make([]byte, 2048)
	skipped := 0
	var authErr error
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return 0, ctxErr
			}
			if errors.Is(err, wsaEMSGSIZE) {
				skipped++ // oversized datagram: not a handshake response
				continue
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if authErr != nil {
					return 0, authErr
				}
				if skipped > 0 {
					return 0, fmt.Errorf("no handshake response (%d unrelated datagrams ignored): %w", skipped, err)
				}
			}
			return 0, err
		}
		rtt := time.Since(sent)
		response := buf[:n]
		if !isCandidate(response) {
			skipped++
			continue
		}
		if err := in.verify(response); err != nil {
			authErr = err
			continue
		}
		return rtt, nil
	}
}
