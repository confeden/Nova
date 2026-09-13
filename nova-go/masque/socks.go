package masque

// `nova-go masque socks`: MASQUE tunnel -> gVisor netstack -> SOCKS5 (and-masque.md §8.2-§8.5).
//
// Order matters and is the contract with nova.pyw: the SOCKS listener opens only after a
// data-plane probe through the tunnel got bytes back, so "port 1370 accepts" means "tunnel ready".

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	socks5 "github.com/things-go/go-socks5"
	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"nova-pc/nova-go/internal/events"
)

// Transport modes of --transport.
const (
	TransportAuto    = "auto"
	TransportH3      = "h3"
	TransportH2      = "h2"
	TransportH3First = "h3first"
)

type socksOptions struct {
	common           commonOptions
	configPath       string
	bind             string
	info             string
	readyFile        string
	endpoints        stringList
	ports            string
	ipv6             bool
	transport        string
	snis             stringList
	sniFile          string
	allowCFSNI       bool
	maxAttempts      int
	attemptTimeout   time.Duration
	connectIPTimeout time.Duration
	zeroRxLimit      int
	mtu              int
	initialPacket    int
	cidLen           int
	keepAlive        time.Duration
	idleTimeout      time.Duration
	noWrapSocket     bool
	dns              string
	dnsTimeout       time.Duration
	localDNS         bool
	noTunnelV4       bool
	noTunnelV6       bool
	reconnectDelay   time.Duration
	reconnectBudget  int
	stallTimeout     time.Duration
	username         string
	password         string
	allowLAN         bool
}

func newSocksFlags(o *socksOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("masque socks", flag.ContinueOnError)
	o.common.register(fs)
	fs.StringVar(&o.configPath, "config", "", "MASQUE profile (Android or usque JSON shape)")
	fs.StringVar(&o.bind, "bind", "127.0.0.1:1370", "SOCKS5 listen address")
	fs.StringVar(&o.info, "info", "", "loopback HTTP status address (GET /status); empty = off")
	fs.StringVar(&o.readyFile, "ready-file", "", "atomically written copy of the ready event")
	fs.Var(&o.endpoints, "endpoint", "endpoint ip[:port] (repeatable); default = profile candidates")
	fs.StringVar(&o.ports, "ports", "", "comma list of ports, tried in order; default = profile ports")
	fs.BoolVar(&o.ipv6, "ipv6", false, "also dial IPv6 endpoints")
	fs.StringVar(&o.transport, "transport", TransportAuto, "auto|h3|h2|h3first")
	fs.Var(&o.snis, "sni", "TLS server name (repeatable, ordered)")
	fs.StringVar(&o.sniFile, "sni-file", "", "file with one server name per line")
	fs.BoolVar(&o.allowCFSNI, "allow-cloudflare-sni", false, "permit *.cloudflareclient.com server names")
	fs.IntVar(&o.maxAttempts, "max-attempts", 16, "attempts per matrix walk")
	fs.DurationVar(&o.attemptTimeout, "attempt-timeout", 8*time.Second, "per attempt: dial + SETTINGS + CONNECT-IP (the data-plane probe adds up to 3s)")
	fs.DurationVar(&o.connectIPTimeout, "connect-ip-timeout", 4500*time.Millisecond, "SETTINGS + CONNECT-IP budget")
	fs.IntVar(&o.zeroRxLimit, "zero-rx-limit", 2, "CONNECT-IP 2xx attempts without inbound packets before giving up")
	fs.IntVar(&o.mtu, "mtu", 1179, "netstack MTU")
	fs.IntVar(&o.initialPacket, "initial-packet-size", 1242, "QUIC initial packet size")
	fs.IntVar(&o.cidLen, "cid-len", 20, "QUIC connection ID length")
	fs.DurationVar(&o.keepAlive, "keepalive", 5*time.Second, "QUIC keepalive period")
	fs.DurationVar(&o.idleTimeout, "idle-timeout", 90*time.Second, "QUIC idle timeout")
	fs.BoolVar(&o.noWrapSocket, "no-wrap-socket", false, "hand quic-go the raw UDP socket (diagnostic)")
	fs.StringVar(&o.dns, "dns", "1.1.1.1,1.0.0.1,2606:4700:4700::1111", "DNS servers inside the tunnel")
	fs.DurationVar(&o.dnsTimeout, "dns-timeout", 2*time.Second, "DNS query timeout")
	fs.BoolVar(&o.localDNS, "local-dns", false, "resolve names outside the tunnel")
	fs.BoolVar(&o.noTunnelV4, "no-tunnel-ipv4", false, "omit the IPv4 tunnel address")
	fs.BoolVar(&o.noTunnelV6, "no-tunnel-ipv6", false, "omit the IPv6 tunnel address")
	fs.DurationVar(&o.reconnectDelay, "reconnect-delay", time.Second, "pause before a redial")
	fs.IntVar(&o.reconnectBudget, "reconnect-budget", 3, "redials of the winning tuple before re-walking the matrix")
	fs.DurationVar(&o.stallTimeout, "stall-timeout", 12*time.Second, "sent bytes stay unanswered this long (and a check probe fails) -> redial")
	fs.StringVar(&o.username, "username", "", "SOCKS username (needs --password)")
	fs.StringVar(&o.password, "password", "", "SOCKS password (needs --username)")
	fs.BoolVar(&o.allowLAN, "allow-lan", false, "permit a non-loopback --bind/--info")
	return fs
}

func (o *socksOptions) validate() error {
	if strings.TrimSpace(o.configPath) == "" {
		return errors.New("--config is required")
	}
	switch o.transport {
	case TransportAuto, TransportH3, TransportH2, TransportH3First:
	default:
		return fmt.Errorf("unknown --transport %q (auto|h3|h2|h3first)", o.transport)
	}
	if err := checkListenAddr("--bind", o.bind, o.allowLAN, false); err != nil {
		return err
	}
	if err := checkListenAddr("--info", o.info, o.allowLAN, true); err != nil {
		return err
	}
	if (o.username == "") != (o.password == "") {
		return errors.New("--username and --password must be given together")
	}
	if o.noTunnelV4 && o.noTunnelV6 {
		return errors.New("--no-tunnel-ipv4 and --no-tunnel-ipv6 together leave no tunnel address")
	}
	switch {
	case o.maxAttempts < 1:
		return errors.New("--max-attempts must be >= 1")
	case o.attemptTimeout < time.Second:
		return errors.New("--attempt-timeout must be >= 1s")
	case o.connectIPTimeout < 500*time.Millisecond:
		return errors.New("--connect-ip-timeout must be >= 500ms")
	case o.zeroRxLimit < 1:
		return errors.New("--zero-rx-limit must be >= 1")
	case o.mtu < 576 || o.mtu > 1500:
		return errors.New("--mtu must be within 576..1500")
	case o.initialPacket < 1200 || o.initialPacket > 1452:
		return errors.New("--initial-packet-size must be within 1200..1452")
	case o.cidLen < 4 || o.cidLen > 20:
		return errors.New("--cid-len must be within 4..20")
	case o.keepAlive <= 0 || o.idleTimeout <= o.keepAlive:
		return errors.New("--keepalive must be > 0 and below --idle-timeout")
	case o.dnsTimeout <= 0:
		return errors.New("--dns-timeout must be > 0")
	case o.reconnectDelay < 0 || o.reconnectBudget < 0:
		return errors.New("--reconnect-delay and --reconnect-budget must not be negative")
	case o.stallTimeout < 2*time.Second:
		return errors.New("--stall-timeout must be >= 2s")
	}
	return nil
}

// checkListenAddr requires ip:port with a loopback ip unless allowLAN.
func checkListenAddr(flagName, value string, allowLAN, optional bool) error {
	if strings.TrimSpace(value) == "" {
		if optional {
			return nil
		}
		return fmt.Errorf("%s is required", flagName)
	}
	ap, err := netip.ParseAddrPort(value)
	if err != nil {
		return fmt.Errorf("%s must be ip:port: %v", flagName, err)
	}
	if ap.Port() == 0 {
		return fmt.Errorf("%s needs a port", flagName)
	}
	if !ap.Addr().IsLoopback() && !allowLAN {
		return fmt.Errorf("%s %s is not loopback (pass --allow-lan to expose it)", flagName, value)
	}
	return nil
}

// parseEndpoints turns --endpoint values into (address, optional port) pairs.
func parseEndpoints(values []string) ([]endpointTarget, error) {
	var out []endpointTarget
	for _, v := range values {
		v = strings.TrimSpace(v)
		if ap, err := netip.ParseAddrPort(v); err == nil {
			out = append(out, endpointTarget{addr: ap.Addr().Unmap(), port: int(ap.Port())})
			continue
		}
		addr, err := netip.ParseAddr(strings.Trim(v, "[]"))
		if err != nil {
			return nil, fmt.Errorf("--endpoint %q must be an IP address with an optional port", v)
		}
		out = append(out, endpointTarget{addr: addr.Unmap()})
	}
	return out, nil
}

func parsePorts(value string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("bad port %q", part)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, errors.New("empty port list")
	}
	return out, nil
}

func parseDNSList(value string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("bad DNS server %q", part)
		}
		out = append(out, a.Unmap())
	}
	if len(out) == 0 {
		return nil, errors.New("--dns is empty")
	}
	return out, nil
}

type endpointTarget struct {
	addr netip.Addr
	port int // 0 = use the port list
	// noH2 marks a sibling or extra candidate of the profile. Measured: H2/TCP on the sibling
	// 162.159.198.1:443 presents another endpoint key (pubkey_mismatch) while H3 on it works with the
	// same identity, so H2 goes only to the enrolled endpoint_v4/endpoint_v6. An H2 attempt there
	// wastes a cell and, where QUIC is blocked, turns a network block into exit 12.
	noH2 bool
}

// profileTargets are the endpoints of a profile in dial order: IPv4 candidates, then IPv6 ones with
// --ipv6. Only the enrolled endpoints (endpoint_v4, endpoint_v6) get H2.
func profileTargets(id Identity, ipv6 bool) []endpointTarget {
	var out []endpointTarget
	add := func(candidates []string, primary string) {
		for _, c := range candidates {
			addr, err := netip.ParseAddr(c)
			if err != nil {
				continue // normalize() keeps only IPs; defensive for hand-built identities
			}
			out = append(out, endpointTarget{addr: addr.Unmap(), noH2: c != primary})
		}
	}
	add(id.EndpointV4Candidates, id.EndpointV4)
	if ipv6 {
		add(id.EndpointV6Candidates, id.EndpointV6)
	}
	return out
}

// transportsFor is the transport order of one port: auto = Android (443: H2 then H3; others H3).
func transportsFor(mode string, port int) []string {
	switch mode {
	case TransportH3:
		return []string{transportH3}
	case TransportH2:
		return []string{transportH2}
	case TransportH3First:
		if port == 443 {
			return []string{transportH3, transportH2}
		}
		return []string{transportH3}
	default:
		if port == 443 {
			return []string{transportH2, transportH3}
		}
		return []string{transportH3}
	}
}

// buildMatrix orders the cells: for endpoint, for port, for transport. SNI is chosen per attempt.
// A noH2 target gets no H2 cell in any mode (with --transport h2 it gets no cell at all).
func buildMatrix(targets []endpointTarget, ports []int, mode string) []dialSpec {
	var out []dialSpec
	for _, t := range targets {
		list := ports
		if t.port != 0 {
			list = []int{t.port}
		}
		for _, p := range list {
			for _, tr := range transportsFor(mode, p) {
				if tr == transportH2 && t.noH2 {
					continue
				}
				out = append(out, dialSpec{endpoint: netip.AddrPortFrom(t.addr, uint16(p)), transport: tr})
			}
		}
	}
	return out
}

// ---- runtime ----------------------------------------------------------------------------------

type socksRuntime struct {
	o       socksOptions
	log     *Logger
	em      *events.Emitter
	crypto  *Crypto
	id      Identity
	snis    []string
	matrix  []dialSpec
	dialOpt dialOptions
	dnsList []netip.Addr

	tunDev tun.Device
	tunNet *netstack.Net
	hasV4  bool
	hasV6  bool

	// stallCheck replaces the check probe of a suspected stall in tests; nil = probe the netstack.
	stallCheck func(ctx context.Context, s *session) bool

	current  atomic.Pointer[session]
	serving  atomic.Bool
	attemptN atomic.Int64
	sniIndex int
	rxTotal  atomic.Int64
	txTotal  atomic.Int64

	statusMu    sync.Mutex
	state       string
	readySince  int64
	reconnects  int
	lastClass   string
	lastError   string
	lastSession *session
}

// socksStatus is the GET /status body (mirrors GetMasqueRuntimeStats; rx/tx are process totals).
type socksStatus struct {
	State                string `json:"state"`
	Transport            string `json:"transport"`
	Endpoint             string `json:"endpoint"`
	SNI                  string `json:"sni"`
	RxBytes              int64  `json:"rx_bytes"`
	TxBytes              int64  `json:"tx_bytes"`
	LastHandshakeTimeSec int64  `json:"last_handshake_time_sec"`
	ReadySince           int64  `json:"ready_since"`
	Reconnects           int    `json:"reconnects"`
	LastClass            string `json:"last_class"`
	LastError            string `json:"last_error"`
}

func (rt *socksRuntime) setState(state string) {
	rt.statusMu.Lock()
	rt.state = state
	rt.statusMu.Unlock()
}

func (rt *socksRuntime) noteFailure(class string, err error) {
	rt.statusMu.Lock()
	rt.lastClass = class
	if err != nil {
		rt.lastError = truncate(err.Error(), 300)
	}
	rt.statusMu.Unlock()
}

func (rt *socksRuntime) status() socksStatus {
	rt.statusMu.Lock()
	defer rt.statusMu.Unlock()
	st := socksStatus{State: rt.state, RxBytes: rt.rxTotal.Load(), TxBytes: rt.txTotal.Load(),
		ReadySince: rt.readySince, Reconnects: rt.reconnects, LastClass: rt.lastClass, LastError: rt.lastError}
	if s := rt.lastSession; s != nil {
		st.Transport, st.Endpoint, st.SNI = s.spec.transport, s.spec.endpoint.String(), s.spec.sni
		if !s.closed() {
			st.LastHandshakeTimeSec = s.started.Unix()
		}
	}
	return st
}

func runSocks(args []string, env *cliEnv) int {
	var o socksOptions
	if ok, code := env.parseFlags(newSocksFlags(&o), args); !ok {
		return code
	}
	log, em, cleanup, code := env.setup(o.common, "socks")
	if code != 0 {
		return code
	}
	defer cleanup()

	if err := o.validate(); err != nil {
		log.Error("bad flags", "err", err)
		return emitExit(em, ExitUsage, "usage", 0, err)
	}
	rt := &socksRuntime{o: o, log: log, em: em, state: "connecting"}
	return rt.run(env)
}

func emitExit(em *events.Emitter, code int, class string, attempts int, err error, extra ...events.Field) int {
	fields := []events.Field{events.F("code", code), events.F("class", class), events.F("attempts", attempts)}
	if err != nil {
		fields = append(fields, events.F("err", truncate(err.Error(), 300)))
	}
	fields = append(fields, extra...)
	em.Emit("exit", fields...)
	return code
}

func (rt *socksRuntime) run(env *cliEnv) int {
	o := &rt.o
	log := rt.log

	id, _, err := LoadIdentityFile(o.configPath)
	if err != nil {
		log.Error("profile rejected", "config", o.configPath, "err", err)
		return emitExit(rt.em, ExitConfig, ClassConfig, 0, err)
	}
	rt.id = id
	if rt.crypto, err = PrepareCrypto(id); err != nil {
		log.Error("profile keys rejected", "config", o.configPath, "err", err)
		return emitExit(rt.em, ExitConfig, ClassConfig, 0, err)
	}
	if rt.snis, err = BuildSNIOrder(o.snis, o.sniFile, o.allowCFSNI); err != nil {
		log.Error("bad SNI list", "err", err)
		return emitExit(rt.em, ExitUsage, "usage", 0, err)
	}
	if rt.dnsList, err = parseDNSList(o.dns); err != nil {
		log.Error("bad DNS list", "err", err)
		return emitExit(rt.em, ExitUsage, "usage", 0, err)
	}
	ports := id.Ports
	if strings.TrimSpace(o.ports) != "" {
		if ports, err = parsePorts(o.ports); err != nil {
			log.Error("bad --ports", "err", err)
			return emitExit(rt.em, ExitUsage, "usage", 0, err)
		}
	}
	var targets []endpointTarget
	if len(o.endpoints) > 0 {
		if targets, err = parseEndpoints(o.endpoints); err != nil {
			log.Error("bad --endpoint", "err", err)
			return emitExit(rt.em, ExitUsage, "usage", 0, err)
		}
	} else {
		targets = profileTargets(id, o.ipv6)
	}
	if len(targets) == 0 {
		err := errors.New("no endpoint to dial (IPv4 candidates empty; pass --ipv6 or --endpoint)")
		log.Error("no endpoints", "err", err)
		return emitExit(rt.em, ExitConfig, ClassConfig, 0, err)
	}
	rt.matrix = buildMatrix(targets, ports, o.transport)
	if len(rt.matrix) == 0 {
		err := fmt.Errorf("no cell to dial with --transport %s on these endpoints", o.transport)
		log.Error("empty attempt matrix", "err", err)
		return emitExit(rt.em, ExitConfig, ClassConfig, 0, err)
	}
	rt.dialOpt = dialOptions{connectIPTimeout: o.connectIPTimeout, cidLen: o.cidLen, wrapSocket: !o.noWrapSocket,
		initialPacketSize: uint16(o.initialPacket), keepAlive: o.keepAlive, idleTimeout: o.idleTimeout}

	var local []netip.Addr
	if !o.noTunnelV4 && id.IPv4 != "" {
		local = append(local, netip.MustParseAddr(id.IPv4))
		rt.hasV4 = true
	}
	if !o.noTunnelV6 && id.IPv6 != "" {
		local = append(local, netip.MustParseAddr(id.IPv6))
		rt.hasV6 = true
	}
	if len(local) == 0 {
		err := errors.New("no tunnel address left after --no-tunnel-ipv4/--no-tunnel-ipv6")
		log.Error("no tunnel address", "err", err)
		return emitExit(rt.em, ExitConfig, ClassConfig, 0, err)
	}

	if o.readyFile != "" {
		if err := os.Remove(o.readyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Error("cannot remove a stale ready file", "path", o.readyFile, "err", err)
			return emitExit(rt.em, ExitInternal, "ready_file", 0, err)
		}
	}
	rt.em.Emit("start", events.F("pid", os.Getpid()), events.F("config", o.configPath), events.F("bind", o.bind))
	log.Info("starting", "config", o.configPath, "device", DeviceIDPrefix(id.DeviceID), "bind", o.bind,
		"transport", o.transport, "cells", len(rt.matrix), "sni", strings.Join(rt.snis, ","), "mtu", o.mtu)

	// Fail fast on a busy SOCKS port instead of after a whole matrix walk. The probe listener is
	// closed at once, so an open port still means "tunnel ready".
	if l, err := net.Listen("tcp", o.bind); err != nil {
		log.Error("SOCKS port is not free", "bind", o.bind, "err", err)
		rt.em.Emit("fail", events.F("n", 0), events.F("class", ClassBind), events.F("stage", "bind"), events.F("err", err.Error()))
		return emitExit(rt.em, ExitBind, ClassBind, 0, err)
	} else if err := l.Close(); err != nil {
		log.Warn("closing the SOCKS port probe failed", "err", err)
	}
	if o.info != "" {
		infoL, err := net.Listen("tcp", o.info)
		if err != nil {
			log.Error("info port is not free", "info", o.info, "err", err)
			rt.em.Emit("fail", events.F("n", 0), events.F("class", ClassBind), events.F("stage", "bind"), events.F("err", err.Error()))
			return emitExit(rt.em, ExitBind, ClassBind, 0, err)
		}
		srv := &http.Server{Handler: rt.infoHandler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.Serve(infoL); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("info server stopped", "err", err)
			}
		}()
		defer srv.Close()
	}

	rt.tunDev, rt.tunNet, err = netstack.CreateNetTUN(local, rt.dnsList, o.mtu)
	if err != nil {
		log.Error("netstack creation failed", "err", err)
		return emitExit(rt.em, ExitInternal, "netstack", 0, err)
	}
	// The netstack is not closed on exit: gVisor may still emit a packet into a closed channel and
	// panic; the process ends right after anyway.
	var allowedV4, allowedV6 net.IP
	if rt.hasV4 {
		allowedV4 = net.ParseIP(id.IPv4).To4()
	}
	if rt.hasV6 {
		allowedV6 = net.ParseIP(id.IPv6).To16()
	}
	up := &uplink{dev: rt.tunDev, allowedV4: allowedV4, allowedV6: allowedV6, current: &rt.current, log: log, txTotal: &rt.txTotal}
	go func() {
		if err := up.run(65535); err != nil {
			log.Debug("netstack reader stopped", "err", err)
		}
	}()

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	if code, stop := env.startStopWatch(ctx, cancel, o.common.parentPID, log); stop {
		return emitExit(rt.em, code, stopClass(code), 0, nil)
	}

	return rt.supervise(ctx)
}

var (
	errStopSignal = errors.New("signal")
	errParentGone = errors.New("parent_exit")
)

func (rt *socksRuntime) supervise(ctx context.Context) int {
	o := &rt.o
	sess, t := rt.walk(ctx)
	if sess == nil {
		return rt.finish(ctx, nil, t)
	}
	listener, err := net.Listen("tcp", o.bind)
	if err != nil {
		rt.current.CompareAndSwap(sess, nil)
		sess.fail(ClassBind, err)
		rt.log.Error("SOCKS listen failed", "bind", o.bind, "err", err)
		rt.em.Emit("fail", events.F("n", 0), events.F("class", ClassBind), events.F("stage", "bind"), events.F("err", err.Error()))
		rt.setState("failed")
		return emitExit(rt.em, ExitBind, ClassBind, t.attempts, err)
	}
	server := rt.newSocksServer()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			rt.log.Error("SOCKS server stopped", "err", err)
		}
	}()
	defer listener.Close()

	if err := rt.markReady(sess, false); err != nil {
		rt.log.Error("cannot write the ready file", "path", o.readyFile, "err", err)
		_ = listener.Close()
		rt.current.CompareAndSwap(sess, nil)
		sess.close()
		rt.setState("failed")
		return emitExit(rt.em, ExitInternal, "ready_file", t.attempts, err)
	}

	for {
		class, lostErr := rt.watch(ctx, sess)
		if ctx.Err() != nil {
			return rt.finish(ctx, listener, t)
		}
		rt.serving.Store(false)
		rt.current.CompareAndSwap(sess, nil)
		sess.fail(class, lostErr)
		rt.noteFailure(class, lostErr)
		rt.setState("reconnecting")
		rt.em.Emit("lost", events.F("class", class), events.F("uptime_s", int64(time.Since(sess.started).Seconds())),
			events.F("rx", sess.rx.Load()), events.F("tx", sess.tx.Load()))
		rt.log.Warn("session lost", "class", class, "err", lostErr, "spec", sess.spec)

		// Redial the same endpoint/port/SNI/transport first; do not rotate while it may recover (N20).
		spec := sess.spec
		sess = nil
		t = newTally()
		for i := 0; i < o.reconnectBudget && sess == nil; i++ {
			if !sleepCtx(ctx, o.reconnectDelay) {
				return rt.finish(ctx, listener, t)
			}
			s, fail := rt.attempt(ctx, spec)
			t.attempts++
			if s != nil {
				sess = s
			} else {
				t.add(fail.class)
			}
		}
		if sess == nil {
			if ctx.Err() != nil {
				return rt.finish(ctx, listener, t)
			}
			var walkTally *tally
			sess, walkTally = rt.walk(ctx)
			for class, n := range walkTally.counts {
				t.counts[class] += n
			}
			t.attempts += walkTally.attempts
			if walkTally.last != "" {
				t.last = walkTally.last
			}
			if sess == nil {
				return rt.finish(ctx, listener, t)
			}
		}
		rt.statusMu.Lock()
		rt.reconnects++
		rt.statusMu.Unlock()
		if err := rt.markReady(sess, true); err != nil {
			rt.log.Error("cannot rewrite the ready file", "path", o.readyFile, "err", err)
		}
	}
}

// finish ends the process: a cancelled context is a clean stop (0), otherwise the tally decides.
func (rt *socksRuntime) finish(ctx context.Context, listener net.Listener, t *tally) int {
	rt.serving.Store(false)
	if listener != nil {
		_ = listener.Close()
	}
	if s := rt.current.Swap(nil); s != nil {
		s.close()
	}
	if rt.o.readyFile != "" {
		if err := os.Remove(rt.o.readyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			rt.log.Warn("cannot remove the ready file", "path", rt.o.readyFile, "err", err)
		}
	}
	if ctx.Err() != nil {
		rt.setState("failed")
		class := "stopped"
		if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
			class = cause.Error()
		}
		rt.log.Info("stopping", "reason", class)
		return emitExit(rt.em, ExitOK, class, t.attempts, nil)
	}
	rt.setState("failed")
	code, class := t.exit()
	rt.log.Error("giving up", "code", code, "class", class, "attempts", t.attempts)
	return emitExit(rt.em, code, class, t.attempts, nil)
}

// walk goes through the matrix (cycling it, so SNIs rotate) until a session passes the probe,
// --max-attempts is spent or --zero-rx-limit sessions stayed silent.
func (rt *socksRuntime) walk(ctx context.Context) (*session, *tally) {
	t := newTally()
	zeroRx := 0
	for i := 0; t.attempts < rt.o.maxAttempts && len(rt.matrix) > 0; i++ {
		if ctx.Err() != nil {
			break
		}
		spec := rt.matrix[i%len(rt.matrix)]
		spec.sni = rt.snis[rt.sniIndex%len(rt.snis)]
		s, fail := rt.attempt(ctx, spec)
		t.attempts++
		if s != nil {
			return s, t
		}
		t.add(fail.class)
		rt.sniIndex++ // the SNI advances on each failure, like Android's failure counter
		if fail.class == ClassZeroRx {
			zeroRx++
			if zeroRx >= rt.o.zeroRxLimit {
				rt.log.Warn("CONNECT-IP opens but nothing comes back; stopping the walk", "zero_rx", zeroRx)
				break
			}
		}
	}
	return nil, t
}

// attempt dials one cell and runs the data-plane probe. On success the session is current and its
// downlink runs; the caller still has to mark it ready.
func (rt *socksRuntime) attempt(ctx context.Context, spec dialSpec) (*session, *dialOutcome) {
	n := rt.attemptN.Add(1)
	rt.em.Emit("attempt", events.F("n", n), events.F("endpoint", spec.endpoint.String()),
		events.F("transport", spec.transport), events.F("sni", spec.sni))
	started := time.Now()
	actx, cancel := context.WithTimeout(ctx, rt.o.attemptTimeout)
	defer cancel()

	var (
		s    *session
		fail *dialOutcome
	)
	tlsConf, err := NewTLSConfig(rt.crypto, spec.sni, rt.o.allowCFSNI)
	if err != nil {
		fail = &dialOutcome{stage: StageDial, class: ClassConfig, err: err}
	} else if spec.transport == transportH2 {
		s, fail = dialH2(actx, spec, tlsConf, rt.dialOpt, rt.log)
	} else {
		s, fail = dialH3(actx, spec, tlsConf, rt.dialOpt, rt.log)
	}
	if s != nil {
		rt.current.Store(s)
		go downlink(s, rt.tunDev, &rt.rxTotal, rt.log)
		// The probe gets its own budget from the CONNECT-IP answer on: a slow dial on a lossy path
		// must not leave it the last milliseconds of the attempt and turn a working tunnel into
		// zero_rx, which counts toward --zero-rx-limit and wins the exit code (13).
		pctx, pcancel := context.WithTimeout(ctx, probeBudget)
		kind, probeRx, ok := rt.probe(pctx, s)
		pcancel()
		if ok {
			s.probeKind, s.probeRx = kind, probeRx
			rt.log.Info("tunnel passed the data-plane probe", "n", n, "spec", spec, "probe", kind, "probe_rx", probeRx,
				"ms", time.Since(started).Milliseconds())
			return s, nil
		}
		rt.current.CompareAndSwap(s, nil)
		class, serr := s.failure()
		stage := StageProbe
		if serr != nil {
			// The session died during the probe; its error may carry a signature (access denied).
			if c := classifyError(StageSession, spec.transport, serr); c != ClassClosed {
				class = c
			} else {
				class = ClassZeroRx
			}
		} else {
			class = ClassZeroRx
			serr = errors.New("CONNECT-IP opened but no packet came back through the tunnel")
		}
		sent, recv := int64(0), int64(0)
		if s.sentPackets != nil {
			sent, recv = s.sentPackets()
		}
		s.fail(class, serr)
		fail = &dialOutcome{stage: stage, class: class, err: serr, sent: sent, recv: recv}
	}
	rt.noteFailure(fail.class, fail.err)
	errText := ""
	if fail.err != nil {
		errText = truncate(fail.err.Error(), 300)
	}
	fields := []events.Field{events.F("n", n), events.F("class", fail.class), events.F("stage", fail.stage),
		events.F("ms", time.Since(started).Milliseconds()), events.F("sent", fail.sent), events.F("recv", fail.recv),
		events.F("err", errText)}
	if fail.status != 0 {
		fields = append(fields, events.F("status", fail.status))
	}
	rt.em.Emit("fail", fields...)
	rt.log.Info("attempt failed", "n", n, "spec", spec, "class", fail.class, "stage", fail.stage, "err", errText)
	return nil, fail
}

// markReady publishes a probed session: SOCKS dials start passing, the ready event and file go out.
func (rt *socksRuntime) markReady(s *session, reconnect bool) error {
	now := time.Now().Unix()
	rt.statusMu.Lock()
	rt.state = "ready"
	rt.readySince = now
	rt.lastSession = s
	rt.statusMu.Unlock()
	rt.serving.Store(true)
	tunnelV4 := ""
	if rt.hasV4 {
		tunnelV4 = rt.id.IPv4
	}
	fields := []events.Field{
		events.F("socks", rt.o.bind), events.F("info", rt.o.info), events.F("transport", s.spec.transport),
		events.F("endpoint", s.spec.endpoint.String()), events.F("sni", s.spec.sni), events.F("attempt", rt.attemptN.Load()),
		events.F("connect_ms", s.handshakeMs), events.F("settings_ms", s.settingsMs), events.F("connectip_ms", s.connectIPMs),
		events.F("probe", s.probeKind), events.F("probe_rx", s.probeRx), events.F("tunnel_ipv4", tunnelV4),
		events.F("reconnect", reconnect),
	}
	// File first, event second: whoever sees the event may read the file at once.
	if rt.o.readyFile != "" {
		if err := writeFileAtomic(rt.o.readyFile, []byte(events.Format("ready", fields...)+"\n")); err != nil {
			return err
		}
	}
	rt.em.Emit("ready", fields...)
	rt.log.Info("ready", "socks", rt.o.bind, "spec", s.spec, "reconnect", reconnect)
	return nil
}

// stallMinUnanswered is how many sent bytes without any inbound packet it takes to suspect a stall.
const stallMinUnanswered = 256

// watch blocks until the session ends, stalls, or ctx is cancelled.
//
// A stall is sent bytes left unanswered for --stall-timeout, timed from the first unanswered send:
// rx silence alone is an idle tunnel, and a burst after minutes of idleness must not count those
// minutes. Before tearing a session down the tunnel gets a check probe, because one-sided traffic
// is not always a dead path (gVisor retransmitting flows of a previous session that the new egress
// drops): a session that still answers is kept.
func (rt *socksRuntime) watch(ctx context.Context, s *session) (string, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastRx := s.rx.Load()
	txAtLastRx := s.tx.Load()
	var unansweredSince time.Time // zero while nothing was sent since lastRx changed
	for {
		select {
		case <-ctx.Done():
			return "", nil
		case <-s.done:
			class, err := s.failure()
			if class == "" {
				class = ClassClosed
			}
			if err != nil {
				if c := classifyError(StageSession, s.spec.transport, err); c != ClassClosed {
					class = c
				}
			}
			return class, err
		case now := <-ticker.C:
			if rx := s.rx.Load(); rx != lastRx {
				lastRx, txAtLastRx, unansweredSince = rx, s.tx.Load(), time.Time{}
				continue
			}
			if since := s.writeSince.Load(); since != 0 && now.Sub(time.Unix(0, since)) >= rt.o.stallTimeout {
				return ClassStall, fmt.Errorf("a tunnel write is blocked for %s", now.Sub(time.Unix(0, since)).Round(time.Second))
			}
			grew := s.tx.Load() - txAtLastRx
			if grew <= 0 {
				continue
			}
			if unansweredSince.IsZero() {
				unansweredSince = now
				continue
			}
			flat := now.Sub(unansweredSince)
			if flat < rt.o.stallTimeout || grew < stallMinUnanswered {
				continue
			}
			if rt.tunnelAnswers(ctx, s) {
				rt.log.Info("sent bytes went unanswered but the tunnel answered a check probe; keeping the session",
					"unanswered", grew, "for", flat.Round(time.Second).String(), "spec", s.spec)
				lastRx, txAtLastRx, unansweredSince = s.rx.Load(), s.tx.Load(), time.Time{}
				continue
			}
			if ctx.Err() != nil {
				return "", nil
			}
			if s.closed() {
				continue // the done case reports the session's own failure
			}
			return ClassStall, fmt.Errorf("sent %d bytes, received nothing for %s", grew, flat.Round(time.Second))
		}
	}
}

// tunnelAnswers runs the data-plane probe on a live session to confirm a suspected stall.
func (rt *socksRuntime) tunnelAnswers(ctx context.Context, s *session) bool {
	if rt.stallCheck != nil {
		return rt.stallCheck(ctx, s)
	}
	if rt.tunNet == nil {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, probeBudget)
	defer cancel()
	_, _, ok := rt.probe(pctx, s)
	return ok
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ---- data-plane probe -------------------------------------------------------------------------

const probeBudget = 3 * time.Second

// probe proves the tunnel carries data: one DNS query through the netstack to the first usable
// --dns server, then a TCP connect to 1.1.1.1:443 if that stays silent. Pass = at least one inbound
// packet within min(3 s, ctx deadline); callers give it a fresh 3 s context. A 2xx CONNECT-IP with
// rx=0 is the SNI-block signature (and-masque.md §4.7), so "CONNECT-IP opened" alone is never "ready".
func (rt *socksRuntime) probe(ctx context.Context, s *session) (string, int64, bool) {
	budget := probeBudget
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem < budget {
			budget = rem
		}
	}
	if budget <= 0 {
		return "", 0, false
	}
	deadline := time.Now().Add(budget)
	baseline := s.rxPackets.Load()
	baseBytes := s.rx.Load()
	got := func() bool { return s.rxPackets.Load() > baseline }

	if server, ok := rt.probeDNSServer(); ok {
		dnsDeadline := time.Now().Add(budget / 2)
		conn, err := rt.tunNet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server, 53))
		if err != nil {
			rt.log.Debug("probe: DNS socket failed", "err", err)
		} else {
			qtype := dnsmessage.TypeA
			if !rt.hasV4 {
				qtype = dnsmessage.TypeAAAA
			}
			query, qerr := buildDNSQuery("cloudflare.com.", qtype)
			if qerr == nil {
				_ = conn.SetDeadline(dnsDeadline)
				if _, werr := conn.Write(query); werr != nil {
					rt.log.Debug("probe: DNS write failed", "err", werr)
				} else {
					go func() {
						buf := make([]byte, 1500)
						_, _ = conn.Read(buf) // drains the answer; the packet counter is the verdict
					}()
					if waitUntil(got, dnsDeadline, s.done) {
						_ = conn.Close()
						return "dns", s.rx.Load() - baseBytes, true
					}
				}
			}
			_ = conn.Close()
		}
	}
	if s.closed() {
		return "", 0, false
	}
	target := netip.MustParseAddrPort("1.1.1.1:443")
	if !rt.hasV4 {
		target = netip.MustParseAddrPort("[2606:4700:4700::1111]:443")
	}
	tctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	go func() {
		c, err := rt.tunNet.DialContextTCPAddrPort(tctx, target)
		if err == nil {
			_ = c.Close()
		}
	}()
	if waitUntil(got, deadline, s.done) {
		return "tcp", s.rx.Load() - baseBytes, true
	}
	return "", 0, false
}

func (rt *socksRuntime) probeDNSServer() (netip.Addr, bool) {
	for _, a := range rt.dnsList {
		if (a.Is4() && rt.hasV4) || (a.Is6() && rt.hasV6) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func waitUntil(cond func() bool, deadline time.Time, done <-chan struct{}) bool {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if cond() {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-done:
			return cond()
		case <-ticker.C:
		}
	}
}

func buildDNSQuery(name string, qtype dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	var idb [2]byte
	if _, err := randRead(idb[:]); err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: uint16(idb[0])<<8 | uint16(idb[1]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	return msg.Pack()
}

// ---- SOCKS5 -----------------------------------------------------------------------------------

var errTunnelNotReady = errors.New("MASQUE tunnel is reconnecting")

const socksDialTimeout = 20 * time.Second

func (rt *socksRuntime) newSocksServer() *socks5.Server {
	opts := []socks5.Option{
		socks5.WithLogger(socksLogger{rt.log}),
		socks5.WithDial(rt.dialTunnel),
		socks5.WithResolver(&tunnelResolver{rt: rt}),
	}
	if rt.o.username != "" {
		opts = append(opts, socks5.WithCredential(socks5.StaticCredentials{rt.o.username: rt.o.password}))
	}
	return socks5.NewServer(opts...)
}

// dialTunnel fails fast while no probed session exists: go-socks5 then answers 0x04 host
// unreachable instead of letting the client wait for gVisor's SYN retries into nowhere.
func (rt *socksRuntime) dialTunnel(ctx context.Context, network, addr string) (net.Conn, error) {
	if !rt.serving.Load() {
		return nil, errTunnelNotReady
	}
	dctx, cancel := context.WithTimeout(ctx, socksDialTimeout)
	defer cancel()
	return rt.tunNet.DialContext(dctx, network, addr)
}

type socksLogger struct{ l *Logger }

func (s socksLogger) Errorf(format string, args ...any) {
	s.l.Debug("socks5: " + fmt.Sprintf(format, args...))
}

// tunnelResolver resolves through the tunnel (or locally with --local-dns), querying every DNS
// server in parallel and taking the first answer. It prefers an address family the netstack has,
// IPv4 first (usque returned ips[0], which may be an AAAA the tunnel cannot use).
type tunnelResolver struct{ rt *socksRuntime }

// tcpDNSMinTimeout bounds DNS over TCP inside the tunnel: it pays for a netstack TCP handshake first,
// and that handshake alone took 0.2-6 s through CONNECT-IP (measured 2026-09-13, h2 and h3).
const tcpDNSMinTimeout = 8 * time.Second

func (r *tunnelResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	rt := r.rt
	if !rt.o.localDNS && !rt.serving.Load() {
		return ctx, nil, errTunnelNotReady
	}
	ip, err := r.lookup(ctx, name, "", rt.o.dnsTimeout)
	if ip != nil || rt.o.localDNS || ctx.Err() != nil {
		return ctx, ip, err
	}
	// UDP through the tunnel can be dead while TCP is not: an H2 CONNECT-IP session on 2026-09-13 left
	// the helper's DNS probe silent, passed its TCP probe, and then answered every SOCKS request by
	// name with 0x04 after exactly --dns-timeout. A browser on the PAC's SOCKS5 sends names, so the
	// tunnel carried nothing for it. DNS over TCP to the same servers, inside the tunnel, still works.
	tcpTimeout := 4 * rt.o.dnsTimeout
	if tcpTimeout < tcpDNSMinTimeout {
		tcpTimeout = tcpDNSMinTimeout
	}
	tcpIP, tcpErr := r.lookup(ctx, name, "tcp", tcpTimeout)
	if tcpIP != nil {
		rt.log.Debug("DNS over UDP in the tunnel failed, TCP answered", "name", name, "udp_err", err)
		return ctx, tcpIP, nil
	}
	if tcpErr != nil {
		err = tcpErr
	}
	return ctx, nil, err
}

// lookup queries every DNS server in parallel and returns the first usable address. A non-empty
// forceNetwork replaces the network Go's resolver asks for ("tcp": a stream connection, which the
// resolver frames as DNS over TCP because a netstack TCP conn is not a PacketConn).
func (r *tunnelResolver) lookup(ctx context.Context, name, forceNetwork string, timeout time.Duration) (net.IP, error) {
	rt := r.rt
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type answer struct {
		ip  net.IP
		err error
	}
	answers := make(chan answer, len(rt.dnsList))
	for _, server := range rt.dnsList {
		serverAddr := netip.AddrPortFrom(server, 53).String()
		go func() {
			resolver := &net.Resolver{PreferGo: true, Dial: func(dctx context.Context, network, _ string) (net.Conn, error) {
				if forceNetwork != "" {
					network = forceNetwork
				}
				if rt.o.localDNS {
					return (&net.Dialer{}).DialContext(dctx, network, serverAddr)
				}
				return rt.tunNet.DialContext(dctx, network, serverAddr)
			}}
			addrs, err := resolver.LookupNetIP(qctx, "ip", name)
			if err != nil {
				answers <- answer{err: err}
				return
			}
			answers <- answer{ip: pickAddress(addrs, rt.hasV4, rt.hasV6)}
		}()
	}
	var lastErr error
	for range rt.dnsList {
		a := <-answers
		if a.ip != nil {
			return a.ip, nil
		}
		if a.err != nil {
			lastErr = a.err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable address for %s", name)
	}
	return nil, lastErr
}

// pickAddress prefers IPv4 when the tunnel has it, then IPv6 when the tunnel has it.
func pickAddress(addrs []netip.Addr, hasV4, hasV6 bool) net.IP {
	if hasV4 {
		for _, a := range addrs {
			if a.Unmap().Is4() {
				return net.IP(a.Unmap().AsSlice())
			}
		}
	}
	if hasV6 {
		for _, a := range addrs {
			if a.Is6() && !a.Is4In6() {
				return net.IP(a.AsSlice())
			}
		}
	}
	return nil
}

// ---- info server ------------------------------------------------------------------------------

func (rt *socksRuntime) infoHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(rt.status()); err != nil {
			rt.log.Debug("status write failed", "err", err)
		}
	})
	return mux
}

// ---- stop handling ----------------------------------------------------------------------------

// installSignalStop cancels ctx on Ctrl+C / Ctrl+Break.
func installSignalStop(ctx context.Context, cancel context.CancelCauseFunc) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		defer signal.Stop(ch)
		select {
		case <-ch:
			cancel(errStopSignal)
		case <-ctx.Done():
		}
	}()
}
