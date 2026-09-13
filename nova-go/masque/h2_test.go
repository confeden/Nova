package masque

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

// ipv4Packet builds a UDP-over-IPv4 packet with a valid header checksum.
func ipv4Packet(src, dst string, ttl byte, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[8] = ttl
	b[9] = 17
	copy(b[12:16], net.ParseIP(src).To4())
	copy(b[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(b[10:12], ipv4Checksum(b[:20]))
	binary.BigEndian.PutUint16(b[20:22], 40000)
	binary.BigEndian.PutUint16(b[22:24], 53)
	binary.BigEndian.PutUint16(b[24:26], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func headerChecksumValid(header []byte) bool {
	var sum uint32
	for i := 0; i+1 < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum) == 0xffff
}

func appendCapsule(dst []byte, capsuleType uint64, payload []byte) []byte {
	dst = quicvarint.Append(dst, capsuleType)
	dst = quicvarint.Append(dst, uint64(len(payload)))
	return append(dst, payload...)
}

// readCapsule reads one capsule (type, payload) from a stream.
func readCapsule(r io.Reader) (uint64, []byte, error) {
	br := &byteReader{r: r}
	t, err := quicvarint.Read(br)
	if err != nil {
		return 0, nil, err
	}
	n, err := quicvarint.Read(br)
	if err != nil {
		return 0, nil, err
	}
	payload := make([]byte, n)
	_, err = io.ReadFull(r, payload)
	return t, payload, err
}

type byteReader struct{ r io.Reader }

func (b *byteReader) ReadByte() (byte, error) {
	var one [1]byte
	_, err := io.ReadFull(b.r, one[:])
	return one[0], err
}

type fakeCONNECTServer struct {
	srv      *httptest.Server
	received chan []byte // capsule payloads of type DATAGRAM
	reply    []byte      // raw capsule bytes written after the 200
	headers  chan http.Header
}

// newFakeCONNECTServer is an HTTP/2 TLS server that behaves like the MASQUE TCP endpoint closely
// enough for framing: it accepts a plain CONNECT, answers 200, streams capsules both ways.
func newFakeCONNECTServer(t *testing.T, serverKey *ecdsa.PrivateKey, reply []byte) *fakeCONNECTServer {
	t.Helper()
	f := &fakeCONNECTServer{received: make(chan []byte, 8), reply: reply, headers: make(chan http.Header, 1)}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.ProtoMajor != 2 {
			http.Error(w, "want HTTP/2 CONNECT", http.StatusBadRequest)
			return
		}
		f.headers <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(f.reply); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		for {
			typ, payload, err := readCapsule(r.Body)
			if err != nil {
				return
			}
			if typ == 0 {
				f.received <- payload
			}
		}
	}))
	f.srv.EnableHTTP2 = true
	f.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{selfSigned(t, serverKey)}, PrivateKey: serverKey}},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCONNECTServer) addrPort(t *testing.T) netip.AddrPort {
	ap, err := netip.ParseAddrPort(f.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

type fakeDevice struct {
	in      chan []byte
	written chan []byte
}

func (d *fakeDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-d.in
	if !ok {
		return 0, net.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], pkt)
	return 1, nil
}

func (d *fakeDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		d.written <- append([]byte(nil), b[offset:]...)
	}
	return len(bufs), nil
}

func TestH2CapsuleFramingRoundTripWithSourceFilter(t *testing.T) {
	c, serverKey := testCryptoWithServerKey(t)
	inbound := ipv4Packet("1.1.1.1", "172.16.0.2", 57, []byte("answer"))
	var reply []byte
	reply = appendCapsule(reply, 0x2d, []byte("ignored control capsule"))
	reply = appendCapsule(reply, 0, inbound)
	fake := newFakeCONNECTServer(t, serverKey, reply)

	tlsConf, err := NewTLSConfig(c, "www.google.com", false)
	if err != nil {
		t.Fatal(err)
	}
	opts := dialOptions{connectIPTimeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	log := NewLogger(io.Discard, false)
	sess, fail := dialH2(ctx, dialSpec{endpoint: fake.addrPort(t), transport: transportH2, sni: "www.google.com"}, tlsConf, opts, log)
	if fail != nil {
		t.Fatalf("dialH2 failed: class=%s stage=%s err=%v", fail.class, fail.stage, fail.err)
	}
	defer sess.close()

	hdr := <-fake.headers
	if hdr.Get("Cf-Connect-Proto") != "cf-connect-ip" || hdr.Get("Pq-Enabled") != "false" {
		t.Fatalf("CONNECT headers = %v", hdr)
	}
	if hdr.Get("User-Agent") != "" {
		t.Fatalf("User-Agent must be empty, got %q", hdr.Get("User-Agent"))
	}

	// Server -> client: the unknown capsule is skipped and the packet arrives byte-exact.
	dev := &fakeDevice{in: make(chan []byte, 4), written: make(chan []byte, 4)}
	var rx, tx atomic.Int64
	go downlink(sess, dev, &rx, log)
	select {
	case got := <-dev.written:
		if !bytes.Equal(got, inbound) {
			t.Fatalf("inbound packet changed:\n got %x\nwant %x", got, inbound)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("inbound packet did not arrive")
	}

	// Client -> server through the uplink: foreign source and TTL<=1 are dropped, the valid
	// packet leaves with TTL-1, a recomputed checksum and no context ID inside the capsule.
	var current atomic.Pointer[session]
	current.Store(sess)
	up := &uplink{dev: dev, allowedV4: net.ParseIP("172.16.0.2").To4(), current: &current, log: log, txTotal: &tx}
	go func() { _ = up.run(2048) }()
	defer close(dev.in)
	dev.in <- ipv4Packet("192.168.0.69", "1.1.1.1", 64, []byte("lan source"))
	dev.in <- ipv4Packet("172.16.0.2", "1.1.1.1", 1, []byte("ttl one"))
	valid := ipv4Packet("172.16.0.2", "1.1.1.1", 64, []byte("query"))
	dev.in <- append([]byte(nil), valid...)

	select {
	case payload := <-fake.received:
		if len(payload) != len(valid) {
			t.Fatalf("capsule payload is %d bytes, want the bare %d-byte IP packet", len(payload), len(valid))
		}
		if payload[8] != 63 {
			t.Fatalf("TTL = %d, want 63", payload[8])
		}
		if !headerChecksumValid(payload[:20]) {
			t.Fatal("IPv4 header checksum invalid after the TTL decrement")
		}
		if !bytes.Equal(payload[12:16], net.ParseIP("172.16.0.2").To4()) || !bytes.Equal(payload[20:], valid[20:]) {
			t.Fatal("packet body or source changed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("valid packet did not reach the server")
	}
	select {
	case extra := <-fake.received:
		t.Fatalf("a filtered packet reached the server: %x", extra)
	case <-time.After(300 * time.Millisecond):
	}
	if up.droppedSrc.Load() != 1 {
		t.Fatalf("foreign-source drops = %d, want 1", up.droppedSrc.Load())
	}
	if tx.Load() != int64(len(valid)) || rx.Load() != int64(len(inbound)) {
		t.Fatalf("counters tx=%d rx=%d", tx.Load(), rx.Load())
	}
}

func TestH2DialRejectsForeignEndpointKey(t *testing.T) {
	c, _ := testCryptoWithServerKey(t)
	_, otherKey := testCryptoWithServerKey(t) // a server key that is not the pinned one
	fake := newFakeCONNECTServer(t, otherKey, nil)
	tlsConf, err := NewTLSConfig(c, "vk.com", false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, fail := dialH2(ctx, dialSpec{endpoint: fake.addrPort(t), transport: transportH2, sni: "vk.com"}, tlsConf,
		dialOptions{connectIPTimeout: 3 * time.Second}, NewLogger(io.Discard, false))
	if sess != nil {
		sess.close()
		t.Fatal("dial succeeded against a server with a foreign key")
	}
	if fail.class != ClassPubkeyMismatch || fail.stage != StageTLS {
		t.Fatalf("class=%s stage=%s err=%v, want pubkey_mismatch at tls", fail.class, fail.stage, fail.err)
	}
}

func TestShouldDropTTLAndSourceAllowed(t *testing.T) {
	v4 := net.ParseIP("172.16.0.2").To4()
	v6 := net.ParseIP("2606:4700:110:8a36::2").To16()
	if !shouldDropTTL(ipv4Packet("172.16.0.2", "1.1.1.1", 1, nil)) || !shouldDropTTL(ipv4Packet("172.16.0.2", "1.1.1.1", 0, nil)) {
		t.Fatal("IPv4 TTL<=1 not dropped")
	}
	if shouldDropTTL(ipv4Packet("172.16.0.2", "1.1.1.1", 2, nil)) {
		t.Fatal("IPv4 TTL 2 dropped")
	}
	p6 := make([]byte, 40)
	p6[0] = 0x60
	p6[7] = 1
	copy(p6[8:24], v6)
	if !shouldDropTTL(p6) {
		t.Fatal("IPv6 hop limit 1 not dropped")
	}
	p6[7] = 64
	if shouldDropTTL(p6) || !sourceAllowed(p6, v4, v6) {
		t.Fatal("valid IPv6 packet rejected")
	}
	if sourceAllowed(p6, v4, nil) {
		t.Fatal("IPv6 packet allowed with no IPv6 tunnel address")
	}
	if !sourceAllowed(ipv4Packet("172.16.0.2", "8.8.8.8", 64, nil), v4, v6) {
		t.Fatal("tunnel source rejected")
	}
	if sourceAllowed(ipv4Packet("192.168.0.69", "8.8.8.8", 64, nil), v4, v6) {
		t.Fatal("LAN source allowed")
	}
	if sourceAllowed([]byte{0x45, 0, 0}, v4, v6) || sourceAllowed(ipv4Packet("172.16.0.2", "8.8.8.8", 64, nil), nil, v6) {
		t.Fatal("short packet or missing family allowed")
	}
}
