package warp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// proxyEndpoint is a parsed --api-proxy value. Credentials stay out of String().
type proxyEndpoint struct {
	scheme   string // "http", "https", "socks5" or "socks5h" (no authentication)
	host     string
	port     string
	username string
	password string
	hasAuth  bool
}

// parseProxyURL accepts http://[user:pass@]host:port and https://... (TLS to the proxy itself, as
// the relay speaks), and socks5://host:port / socks5h://host:port: a local tunnel's SOCKS5 port
// (Nova's primary slot, Tor), unauthenticated, the name always resolved by the proxy. A bare
// host:port means http.
func parseProxyURL(raw string) (*proxyEndpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: empty proxy URL", ErrUsage)
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Parse errors quote the input, which may hold a password.
		return nil, fmt.Errorf("%w: proxy URL does not parse", ErrUsage)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" && !isSocksScheme(scheme) {
		return nil, fmt.Errorf("%w: proxy scheme %q is not http, https, socks5 or socks5h", ErrUsage, scheme)
	}
	if isSocksScheme(scheme) && u.User != nil {
		// Never echo the value: it may hold a password.
		return nil, fmt.Errorf("%w: a socks5 proxy with credentials is not supported", ErrUsage)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: proxy URL has no host", ErrUsage)
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}[scheme]
	}
	p := &proxyEndpoint{scheme: scheme, host: host, port: port}
	if u.User != nil {
		p.username = u.User.Username()
		p.password, _ = u.User.Password()
		p.hasAuth = true
	}
	return p, nil
}

func isSocksScheme(scheme string) bool { return scheme == "socks5" || scheme == "socks5h" }

func (p *proxyEndpoint) address() string { return net.JoinHostPort(p.host, p.port) }

// String is the log-safe form: scheme://host:port, never the credentials.
func (p *proxyEndpoint) String() string { return p.scheme + "://" + p.address() }

// ProxyError is a CONNECT refused by the proxy. Reason carries X-Nova-Relay-Reason when the Nova
// relay sent one ("outdated-client" means the relay key is stale).
type ProxyError struct {
	StatusCode int
	Status     string
	Reason     string
}

func (e *ProxyError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("proxy refused CONNECT: %s (reason: %s)", e.Status, e.Reason)
	}
	return "proxy refused CONNECT: " + e.Status
}

// errProxyDial marks a failure to reach the proxy itself, which no TLS profile can fix.
var errProxyDial = errors.New("proxy unreachable")

// dialViaProxy opens a CONNECT tunnel to target through p. The returned conn carries no deadline.
func dialViaProxy(ctx context.Context, p *proxyEndpoint, target string, proxyRoots *x509.CertPool) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", p.address())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errProxyDial, err)
	}
	conn := raw
	ok := false
	// Cancellation must unblock the CONNECT exchange, not only the deadline.
	stopWatch := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer func() {
		stopWatch()
		if !ok {
			_ = conn.Close()
		}
	}()
	if err := conn.SetDeadline(boundedDeadline(ctx, 10*time.Second)); err != nil {
		return nil, fmt.Errorf("set proxy deadline: %w", err)
	}
	if isSocksScheme(p.scheme) {
		if err := socks5Connect(conn, target); err != nil {
			return nil, err
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			return nil, fmt.Errorf("clear proxy deadline: %w", err)
		}
		ok = true
		return conn, nil
	}
	if p.scheme == "https" {
		tlsConn := tls.Client(raw, &tls.Config{ServerName: p.host, MinVersion: tls.VersionTLS12, RootCAs: proxyRoots})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("%w: tls to proxy: %v", errProxyDial, err)
		}
		conn = tlsConn
	}

	var sb strings.Builder
	sb.WriteString("CONNECT " + target + " HTTP/1.1\r\n")
	sb.WriteString("Host: " + target + "\r\n")
	if p.hasAuth {
		cred := base64.StdEncoding.EncodeToString([]byte(p.username + ":" + p.password))
		sb.WriteString("Proxy-Authorization: Basic " + cred + "\r\n")
	}
	sb.WriteString("\r\n")
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	// A CONNECT answer has no body worth reading; the tunnel starts right after the headers.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = resp.Body.Close()
		return nil, &ProxyError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Reason:     strings.TrimSpace(resp.Header.Get("X-Nova-Relay-Reason")),
		}
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear proxy deadline: %w", err)
	}
	ok = true
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn replays bytes the CONNECT reader pulled past the response headers.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// socks5Connect runs a no-authentication SOCKS5 CONNECT to target ("host:port") over conn. A host
// name is sent as such (ATYP 3), so the proxy resolves it: the local resolver may be filtered, and
// a name resolved here would not reach the same address anyway.
//
// A server that does not speak SOCKS5, or hangs up mid-exchange, is "proxy unreachable" (nothing a
// TLS profile can fix); one that answers with a refusal is a *ProxyError, like a refused CONNECT.
func socks5Connect(conn net.Conn, target string) error {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("socks5 target: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("socks5 target: bad port %q", portText)
	}
	fail := func(stage string, err error) error {
		return fmt.Errorf("%w: socks5 %s: %v", errProxyDial, stage, err)
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil { // version 5, one method: no authentication
		return fail("greeting", err)
	}
	var method [2]byte
	if _, err := readFull(conn, method[:]); err != nil {
		return fail("method reply", err)
	}
	if method[0] != 5 {
		return fail("method reply", errors.New("not a SOCKS5 server"))
	}
	if method[1] != 0 {
		return &ProxyError{Status: fmt.Sprintf("socks5 wants authentication (method 0x%02x)", method[1])}
	}

	req := []byte{5, 1, 0}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			a := ip.As4()
			req = append(req, 1)
			req = append(req, a[:]...)
		} else {
			a := ip.As16()
			req = append(req, 4)
			req = append(req, a[:]...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("socks5 target: bad host length %d", len(host))
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return fail("request", err)
	}
	var head [4]byte
	if _, err := readFull(conn, head[:]); err != nil {
		return fail("reply", err)
	}
	if head[0] != 5 {
		return fail("reply", errors.New("not a SOCKS5 reply"))
	}
	if head[1] != 0 {
		return &ProxyError{Status: fmt.Sprintf("socks5 reply 0x%02x (%s)", head[1], socks5ReplyText(head[1]))}
	}
	var skip int
	switch head[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		var n [1]byte
		if _, err := readFull(conn, n[:]); err != nil {
			return fail("reply", err)
		}
		skip = int(n[0]) + 2
	default:
		return fail("reply", fmt.Errorf("unknown address type 0x%02x", head[3]))
	}
	if _, err := readFull(conn, make([]byte, skip)); err != nil {
		return fail("reply", err)
	}
	return nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	return io.ReadFull(conn, buf)
}

func socks5ReplyText(code byte) string {
	switch code {
	case 1:
		return "general failure"
	case 2:
		return "not allowed by ruleset"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "TTL expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	}
	return "unknown"
}
