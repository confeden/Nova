package masque

// The packet path between the userspace netstack and one CONNECT-IP session. Port of
// nova-core/engine/masque.go:970-1148 (runMasqueTunnel) with the Android OS TUN replaced by the
// gVisor netstack of usque's socks mode (and-masque.md §5).

import (
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
)

// session is one open CONNECT-IP tunnel.
type session struct {
	spec    dialSpec
	ipConn  *connectip.Conn
	started time.Time

	handshakeMs, settingsMs, connectIPMs int64
	status                               int
	probeKind                            string
	probeRx                              int64
	// sentPackets reports transport-level (datagram or TCP segment) counters for diagnostics.
	sentPackets func() (sent, recv int64)

	rx, tx    atomic.Int64 // IP bytes through the tunnel
	rxPackets atomic.Int64
	// writeSince is the unix-nano start of a WritePacket still in progress (0 = none). The H2
	// transport writes into a pipe that blocks when the TCP path is stuck; tx does not grow then,
	// so the stall detector watches this instead.
	writeSince atomic.Int64

	closersMu sync.Mutex
	closers   []func()

	done      chan struct{}
	closeOnce sync.Once
	errMu     sync.Mutex
	err       error
	class     string
}

func newSession(spec dialSpec, conn *connectip.Conn) *session {
	return &session{spec: spec, ipConn: conn, started: time.Now(), done: make(chan struct{})}
}

func (s *session) addCloser(fn func()) {
	s.closersMu.Lock()
	s.closers = append(s.closers, fn)
	s.closersMu.Unlock()
}

// fail records the first failure and closes the session.
func (s *session) fail(class string, err error) {
	s.errMu.Lock()
	if s.err == nil && s.class == "" {
		s.class, s.err = class, err
	}
	s.errMu.Unlock()
	s.close()
}

func (s *session) failure() (string, error) {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.class, s.err
}

func (s *session) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.closersMu.Lock()
		closers := s.closers
		s.closers = nil
		s.closersMu.Unlock()
		for _, fn := range closers {
			fn()
		}
	})
}

func (s *session) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// isClosedError reports errors that end a session (masque.go:1529-1542).
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	var closeErr *connectip.CloseError
	if errors.As(err, &closeErr) {
		return true
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
}

// packetDevice is the part of the netstack TUN the pumps use.
type packetDevice interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
}

// shouldDropTTL drops IPv4 TTL<=1 / IPv6 hop limit<=1 before the library would, so such packets
// never reach the tunnel (masque.go:1218-1237; the fork drops them too, with a log line each).
func shouldDropTTL(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	switch pkt[0] >> 4 {
	case 4:
		return len(pkt) >= 20 && pkt[8] <= 1
	case 6:
		return len(pkt) >= 40 && pkt[7] <= 1
	}
	return false
}

// sourceAllowed passes only packets whose source is the tunnel address Cloudflare assigned. A
// foreign source (a LAN address) made Cloudflare silence the whole session (masque.go:1053-1067,
// 1906-1929). With the netstack bound to exactly these addresses this should never trigger; it
// stays as cheap defence in depth. A missing family admits nothing of that family.
func sourceAllowed(pkt []byte, allowedV4, allowedV6 net.IP) bool {
	if len(pkt) < 20 {
		return false
	}
	switch pkt[0] >> 4 {
	case 4:
		return allowedV4 != nil && net.IP(pkt[12:16]).Equal(allowedV4)
	case 6:
		return len(pkt) >= 40 && allowedV6 != nil && net.IP(pkt[8:24]).Equal(allowedV6)
	}
	return false
}

// uplink reads the netstack for the whole process lifetime and forwards to the current session.
// One reader for all sessions keeps the netstack drained: gVisor blocks its write path while a
// packet waits to be read, so a reader that exits with its session would freeze every socket.
type uplink struct {
	dev        packetDevice
	allowedV4  net.IP
	allowedV6  net.IP
	current    *atomic.Pointer[session]
	log        *Logger
	txTotal    *atomic.Int64
	droppedSrc atomic.Int64
	logged     atomic.Int64
}

const tunPacketLogLimit = 5

func (u *uplink) run(bufSize int) error {
	bufs := [][]byte{make([]byte, bufSize)}
	sizes := []int{0}
	for {
		sizes[0] = 0
		if _, err := u.dev.Read(bufs, sizes, 0); err != nil {
			return err
		}
		n := sizes[0]
		if n <= 0 {
			continue
		}
		pkt := bufs[0][:n]
		if shouldDropTTL(pkt) {
			continue
		}
		if !sourceAllowed(pkt, u.allowedV4, u.allowedV6) {
			if c := u.droppedSrc.Add(1); c == 1 || c%50 == 0 {
				u.log.Debug("dropped a packet with a foreign source", "packet", describePacket(pkt), "total", c)
			}
			continue
		}
		s := u.current.Load()
		if s == nil || s.closed() {
			continue // no tunnel: the packet is lost, TCP retransmits after the redial
		}
		if c := u.logged.Load(); c < tunPacketLogLimit && u.log.DebugEnabled() {
			u.logged.Add(1)
			u.log.Debug("tunnel packet", "n", c+1, "packet", describePacket(pkt))
		}
		s.writeSince.Store(time.Now().UnixNano())
		icmp, err := s.ipConn.WritePacket(pkt)
		s.writeSince.Store(0)
		if err != nil {
			if isClosedError(err) {
				s.fail(ClassClosed, err)
			} else {
				u.log.Debug("tunnel write warning", "err", err)
			}
			continue
		}
		s.tx.Add(int64(n))
		u.txTotal.Add(int64(n))
		if len(icmp) > 0 {
			if _, werr := u.dev.Write([][]byte{icmp}, 0); werr != nil {
				u.log.Debug("ICMP reply to netstack failed", "err", werr)
			}
		}
	}
}

// downlink forwards tunnel packets into the netstack until the session ends.
func downlink(s *session, dev packetDevice, rxTotal *atomic.Int64, log *Logger) {
	for {
		pkt, err := s.ipConn.ReadPacketZeroCopy(true)
		if err != nil {
			if isClosedError(err) || s.closed() {
				s.fail(ClassClosed, err)
				return
			}
			// Malformed datagrams are dropped by the library; any other read error ends the session:
			// retrying a broken stream only spins.
			s.fail(ClassClosed, err)
			return
		}
		if len(pkt) == 0 {
			continue
		}
		// Write copies the packet into a gVisor buffer, so the zero-copy slice may be reused after.
		if _, err := dev.Write([][]byte{pkt}, 0); err != nil {
			log.Debug("netstack rejected an inbound packet", "err", err, "len", len(pkt))
			continue
		}
		s.rx.Add(int64(len(pkt)))
		s.rxPackets.Add(1)
		rxTotal.Add(int64(len(pkt)))
	}
}

func describePacket(pkt []byte) string {
	if len(pkt) < 20 {
		return "short packet"
	}
	switch pkt[0] >> 4 {
	case 4:
		return "IPv4 " + net.IP(pkt[12:16]).String() + " -> " + net.IP(pkt[16:20]).String() + " proto=" + itoa(int(pkt[9])) + " len=" + itoa(len(pkt))
	case 6:
		if len(pkt) < 40 {
			return "short IPv6 packet"
		}
		return "IPv6 " + net.IP(pkt[8:24]).String() + " -> " + net.IP(pkt[24:40]).String() + " next=" + itoa(int(pkt[6])) + " len=" + itoa(len(pkt))
	}
	return "unknown IP version"
}

func itoa(v int) string { return strconv.Itoa(v) }
