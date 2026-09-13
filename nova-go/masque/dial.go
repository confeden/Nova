package masque

// CONNECT-IP dials. H3 is nova-core/engine/masque.go:1239-1637 (connectMasqueTunnel, SETTINGS
// wait, bounded CONNECT-IP with late close, trackedPacketConn); H2 is masque_h2.go:53-125 without
// the Android socket protector.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

const (
	connectURI         = "https://cloudflareaccess.com"
	connectIPProtocol  = "cf-connect-ip"
	transportH2        = "h2"
	transportH3        = "h3"
	settingsH3Datagram = 0x276 // SETTINGS_H3_DATAGRAM_00, still sent by the official client
)

// dialOptions are the knobs of one attempt that do not change between attempts.
type dialOptions struct {
	connectIPTimeout  time.Duration
	cidLen            int
	wrapSocket        bool
	initialPacketSize uint16
	keepAlive         time.Duration
	idleTimeout       time.Duration
}

// dialSpec is one cell of the attempt matrix.
type dialSpec struct {
	endpoint  netip.AddrPort
	transport string
	sni       string
}

func (s dialSpec) String() string {
	return s.transport + "://" + s.endpoint.String() + " sni=" + s.sni
}

// dialOutcome describes a dial that did not produce a session.
type dialOutcome struct {
	stage       string
	class       string
	err         error
	status      int
	sent, recv  int64
	handshakeMs int64
	settingsMs  int64
	connectIPMs int64
}

// trackedPacketConn hides *net.UDPConn from quic-go, which disables its recvmmsg/OOB fast path,
// and counts datagrams so "sent nothing" and "got no reply" are distinguishable (masque.go:1587-1637).
type trackedPacketConn struct {
	net.PacketConn
	sent, received    atomic.Int64
	bytesOut, bytesIn atomic.Int64
}

func (c *trackedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	c.sent.Add(1)
	c.bytesOut.Add(int64(n))
	return n, err
}

func (c *trackedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.received.Add(1)
		c.bytesIn.Add(int64(n))
	}
	return n, addr, err
}

// countingConn counts TCP reads/writes for the H2 transport's sent/recv event fields.
type countingConn struct {
	net.Conn
	writes, reads atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.writes.Add(1)
	}
	return n, err
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.reads.Add(1)
	}
	return n, err
}

func quicConfig(o dialOptions) *quic.Config {
	return &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: o.initialPacketSize,
		MaxIdleTimeout:    o.idleTimeout,
		KeepAlivePeriod:   o.keepAlive,
	}
}

// dialH3 opens QUIC -> HTTP/3 SETTINGS -> CONNECT-IP. ctx bounds the whole dial; the CONNECT-IP
// part (SETTINGS + request) additionally gets connectIPTimeout.
func dialH3(ctx context.Context, spec dialSpec, tlsConf *tls.Config, o dialOptions, log *Logger) (*session, *dialOutcome) {
	started := time.Now()
	laddr := &net.UDPAddr{IP: net.IPv4zero}
	if spec.endpoint.Addr().Is6() {
		laddr.IP = net.IPv6zero
	}
	udpConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, &dialOutcome{stage: StageDial, class: ClassQUICTimeout, err: fmt.Errorf("open UDP socket: %w", err)}
	}
	tracked := &trackedPacketConn{PacketConn: udpConn}
	var pconn net.PacketConn = tracked
	if !o.wrapSocket {
		pconn = udpConn
	}
	qt := &quic.Transport{Conn: pconn, ConnectionIDLength: o.cidLen}
	remote := net.UDPAddrFromAddrPort(spec.endpoint)
	outcome := func(stage string, err error) *dialOutcome {
		return &dialOutcome{stage: stage, class: classifyError(stage, transportH3, err), err: err,
			sent: tracked.sent.Load(), recv: tracked.received.Load()}
	}

	qconn, err := qt.Dial(ctx, remote, tlsConf, quicConfig(o))
	if err != nil {
		_ = qt.Close()
		_ = udpConn.Close()
		return nil, outcome(StageDial, err)
	}
	handshakeMs := time.Since(started).Milliseconds()
	state := qconn.ConnectionState()
	log.Debug("QUIC established", "endpoint", spec.endpoint, "alpn", state.TLS.NegotiatedProtocol,
		"datagrams", state.SupportsDatagrams.Remote, "ms", handshakeMs)

	h3 := &http3.Transport{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{settingsH3Datagram: 1},
		DisableCompression: true,
	}
	hconn := h3.NewClientConn(qconn)
	closeAll := func(msg string) {
		_ = qconn.CloseWithError(0, msg)
		_ = h3.Close()
		_ = qt.Close()
		_ = udpConn.Close()
	}

	openCtx, openCancel := context.WithTimeout(ctx, o.connectIPTimeout)
	defer openCancel()

	// SETTINGS as a separate step: silence before SETTINGS means the server took QUIC but opened no
	// HTTP/3 session; a failure after them is about the CONNECT-IP request itself.
	settingsStarted := time.Now()
	select {
	case <-hconn.ReceivedSettings():
	case <-hconn.Context().Done():
		cause := context.Cause(hconn.Context())
		closeAll("")
		oc := outcome(StageSettings, fmt.Errorf("connection closed before HTTP/3 SETTINGS: %w", cause))
		oc.handshakeMs = handshakeMs
		return nil, oc
	case <-openCtx.Done():
		closeAll("settings timeout")
		oc := outcome(StageSettings, fmt.Errorf("server accepted QUIC but sent no HTTP/3 SETTINGS within %s",
			time.Since(settingsStarted).Round(time.Millisecond)))
		oc.handshakeMs = handshakeMs
		return nil, oc
	}
	settingsMs := time.Since(settingsStarted).Milliseconds()
	if s := hconn.Settings(); s != nil {
		log.Debug("HTTP/3 SETTINGS", "endpoint", spec.endpoint, "extended_connect", s.EnableExtendedConnect,
			"datagrams", s.EnableDatagrams, "ms", settingsMs)
	}

	connectStarted := time.Now()
	type result struct {
		conn *connectip.Conn
		rsp  *http.Response
		err  error
	}
	results := make(chan result, 1)
	template := uritemplate.MustNew(connectURI)
	go func() {
		c, rsp, err := connectip.Dial(openCtx, hconn, template, connectIPProtocol, http.Header{"User-Agent": []string{""}}, true)
		results <- result{c, rsp, err}
	}()
	var res result
	select {
	case res = <-results:
	case <-openCtx.Done():
		// A late answer still arrives; close it so no unknown tunnel stays open. ReadResponse has no
		// deadline, only closing the connection releases the goroutine (masque.go:1417-1463).
		go func() {
			if late := <-results; late.conn != nil {
				_ = late.conn.Close()
			}
		}()
		closeAll("connect-ip timeout")
		oc := outcome(StageConnectIP, fmt.Errorf("%w within %s", errConnectIPNoAnswer, time.Since(connectStarted).Round(time.Millisecond)))
		oc.handshakeMs, oc.settingsMs = handshakeMs, settingsMs
		return nil, oc
	}
	connectIPMs := time.Since(connectStarted).Milliseconds()
	if res.err != nil || res.rsp == nil || res.rsp.StatusCode/100 != 2 {
		if res.conn != nil {
			_ = res.conn.Close()
		}
		closeAll("")
		err := res.err
		if err == nil {
			err = errors.New("connect-ip: no response")
		}
		oc := outcome(StageConnectIP, err)
		if res.rsp != nil {
			oc.status = res.rsp.StatusCode
		}
		oc.handshakeMs, oc.settingsMs, oc.connectIPMs = handshakeMs, settingsMs, connectIPMs
		return nil, oc
	}
	log.Debug("CONNECT-IP open", "endpoint", spec.endpoint, "status", res.rsp.StatusCode, "ms", connectIPMs)

	s := newSession(spec, res.conn)
	s.status = res.rsp.StatusCode
	s.handshakeMs, s.settingsMs, s.connectIPMs = handshakeMs, settingsMs, connectIPMs
	s.sentPackets = func() (int64, int64) { return tracked.sent.Load(), tracked.received.Load() }
	s.addCloser(func() { _ = res.conn.Close() })
	s.addCloser(func() { closeAll("") })
	go logControlCapsules(s, res.conn, log)
	return s, nil
}

// dialH2 opens TLS/TCP (ALPN h2) -> plain CONNECT with cf-connect-proto. No `:protocol`: setting it
// makes x/net refuse to send "extended connect not supported by peer" (N19).
func dialH2(ctx context.Context, spec dialSpec, tlsConf *tls.Config, o dialOptions, log *Logger) (*session, *dialOutcome) {
	started := time.Now()
	clone := tlsConf.Clone()
	clone.NextProtos = []string{"h2"} // exactly h2: with http/1.1 offered the server may pick it

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", spec.endpoint.String())
	if err != nil {
		return nil, &dialOutcome{stage: StageDial, class: classifyError(StageDial, transportH2, err), err: fmt.Errorf("tcp dial: %w", err)}
	}
	counted := &countingConn{Conn: raw}
	outcome := func(stage string, err error) *dialOutcome {
		return &dialOutcome{stage: stage, class: classifyError(stage, transportH2, err), err: err,
			sent: counted.writes.Load(), recv: counted.reads.Load()}
	}
	tlsConn := tls.Client(counted, clone)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, outcome(StageTLS, fmt.Errorf("tls handshake: %w", err))
	}
	// No ALPN check: the MASQUE TCP endpoint answers without selecting a protocol (measured on
	// 162.159.198.2:443, 2026-09-13) and still speaks HTTP/2; Android never checked it either.
	handshakeMs := time.Since(started).Milliseconds()
	log.Debug("TLS/TCP established", "endpoint", spec.endpoint, "alpn", tlsConn.ConnectionState().NegotiatedProtocol, "ms", handshakeMs)

	// Pings detect a dead TCP path while the tunnel is idle; without them only the OS would notice.
	t2 := &http2.Transport{ReadIdleTimeout: 15 * time.Second, PingTimeout: 5 * time.Second}
	cc, err := t2.NewClientConn(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, outcome(StageTLS, fmt.Errorf("http2 client: %w", err))
	}
	closeAll := func() {
		_ = cc.Close()
		_ = tlsConn.Close()
	}

	// The request context must outlive the dial: x/net resets the stream when it is cancelled.
	sessCtx, sessCancel := context.WithCancel(context.Background())
	type result struct {
		conn *connectip.Conn
		rsp  *http.Response
		err  error
	}
	results := make(chan result, 1)
	connectStarted := time.Now()
	go func() {
		c, rsp, err := connectip.DialH2(sessCtx, &http.Client{Transport: h2SingleConn{cc}}, uritemplate.MustNew(connectURI),
			http.Header{"cf-connect-proto": []string{connectIPProtocol}, "pq-enabled": []string{"false"}, "User-Agent": []string{""}})
		results <- result{c, rsp, err}
	}()
	budget := o.connectIPTimeout
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < budget {
		budget = time.Until(dl)
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	var res result
	select {
	case res = <-results:
	case <-timer.C:
		sessCancel()
		closeAll()
		go func() {
			if late := <-results; late.conn != nil {
				_ = late.conn.Close()
			}
		}()
		oc := outcome(StageConnectIP, fmt.Errorf("%w within %s", errConnectIPNoAnswer, time.Since(connectStarted).Round(time.Millisecond)))
		oc.handshakeMs = handshakeMs
		return nil, oc
	case <-ctx.Done():
		sessCancel()
		closeAll()
		go func() {
			if late := <-results; late.conn != nil {
				_ = late.conn.Close()
			}
		}()
		oc := outcome(StageConnectIP, fmt.Errorf("%w: %v", errConnectIPNoAnswer, ctx.Err()))
		oc.handshakeMs = handshakeMs
		return nil, oc
	}
	connectIPMs := time.Since(connectStarted).Milliseconds()
	if res.err != nil || res.rsp == nil || res.rsp.StatusCode/100 != 2 {
		if res.conn != nil {
			_ = res.conn.Close()
		}
		sessCancel()
		closeAll()
		err := res.err
		if err == nil {
			err = errors.New("connect-ip: no response")
		}
		oc := outcome(StageConnectIP, err)
		if res.rsp != nil {
			oc.status = res.rsp.StatusCode
		}
		oc.handshakeMs, oc.connectIPMs = handshakeMs, connectIPMs
		return nil, oc
	}
	log.Debug("CONNECT-IP open over HTTP/2", "endpoint", spec.endpoint, "status", res.rsp.StatusCode, "ms", connectIPMs)

	s := newSession(spec, res.conn)
	s.status = res.rsp.StatusCode
	s.handshakeMs, s.connectIPMs = handshakeMs, connectIPMs
	s.sentPackets = func() (int64, int64) { return counted.writes.Load(), counted.reads.Load() }
	s.addCloser(func() { _ = res.conn.Close() })
	s.addCloser(sessCancel)
	s.addCloser(closeAll)
	return s, nil
}

// h2SingleConn runs requests on one established HTTP/2 connection, keeping the pinned TLS config.
type h2SingleConn struct{ cc *http2.ClientConn }

func (t h2SingleConn) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.cc.RoundTrip(req)
}

// logControlCapsules logs ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT once, 3 x 2 s attempts
// (masque.go:1150-1185). Diagnostics only; the H2 transport has no control capsules.
func logControlCapsules(s *session, conn *connectip.Conn, log *Logger) {
	if !log.DebugEnabled() {
		return
	}
	for attempt := 1; attempt <= 3; attempt++ {
		select {
		case <-s.done:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		prefixes, err := conn.LocalPrefixes(ctx)
		cancel()
		if err == nil {
			log.Debug("ADDRESS_ASSIGN", "prefixes", fmt.Sprint(prefixes))
			return
		}
	}
}
