package warp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// proxyEndpoint is a parsed --api-proxy value. Credentials stay out of String().
type proxyEndpoint struct {
	scheme   string // "http" or "https"
	host     string
	port     string
	username string
	password string
	hasAuth  bool
}

// parseProxyURL accepts http://[user:pass@]host:port and https://... (TLS to the proxy itself, as
// the relay speaks). A bare host:port means http.
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
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("%w: proxy scheme %q is not http or https", ErrUsage, scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: proxy URL has no host", ErrUsage)
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[scheme]
	}
	p := &proxyEndpoint{scheme: scheme, host: host, port: port}
	if u.User != nil {
		p.username = u.User.Username()
		p.password, _ = u.User.Password()
		p.hasAuth = true
	}
	return p, nil
}

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
