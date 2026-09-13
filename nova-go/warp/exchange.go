package warp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// requestIOTimeout bounds writing the request and reading the whole answer after the handshake.
const requestIOTimeout = 12 * time.Second

// APIRequest is one Cloudflare client API call.
type APIRequest struct {
	Label     string // log label, e.g. "warp-register"
	Method    string // default POST
	Path      string // default RegistrationPath
	Body      []byte
	AuthToken string // sent as "Authorization: Bearer <token>" when set; never logged
	// ValidateOK, when set, is applied to a 200 body; an error counts as a failed attempt and the
	// next tier is tried.
	ValidateOK func(body []byte) error
}

// APIResponse is the raw answer and the path that produced it.
type APIResponse struct {
	StatusCode int
	Status     string
	Proto      string
	Body       []byte
	Via        string // "direct/<ip>/<profile>", "proxy/<profile>" or "plain"
}

// newAPIHTTPRequest builds the request with register.go's header set. CF-Client-Version keeps the
// case the real OkHttp client sends; net/http would otherwise canonicalise it to Cf-Client-Version.
func newAPIHTTPRequest(ctx context.Context, apiReq APIRequest) (*http.Request, error) {
	method := strings.ToUpper(strings.TrimSpace(apiReq.Method))
	if method == "" {
		method = http.MethodPost
	}
	path := strings.TrimSpace(apiReq.Path)
	if path == "" {
		path = RegistrationPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+APIHost+path, bytes.NewReader(apiReq.Body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header["CF-Client-Version"] = []string{ClientVersion}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "close")
	if token := strings.TrimSpace(apiReq.AuthToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

// tlsExchange runs uTLS over conn (a raw, fragmented or tunnelled TCP stream), then one request.
// The parrots for Chrome and Firefox offer h2 in ALPN and Cloudflare picks it, so the request is
// spoken as HTTP/2 when negotiated and as HTTP/1.1 otherwise. Certificates are verified against
// APIHost; the pinned address never relaxes that.
func tlsExchange(ctx context.Context, conn net.Conn, helloID utls.ClientHelloID, handshakeTimeout time.Duration, apiReq APIRequest, roots *x509.CertPool) (*APIResponse, error) {
	uconn := utls.UClient(conn, &utls.Config{
		ServerName: APIHost,
		NextProtos: []string{"http/1.1"},
		MinVersion: utls.VersionTLS12,
		MaxVersion: utls.VersionTLS13,
		RootCAs:    roots,
	}, helloID)
	if err := uconn.SetDeadline(boundedDeadline(ctx, handshakeTimeout)); err != nil {
		return nil, fmt.Errorf("set handshake deadline: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}
	if err := uconn.SetDeadline(boundedDeadline(ctx, requestIOTimeout)); err != nil {
		return nil, fmt.Errorf("set request deadline: %w", err)
	}

	req, err := newAPIHTTPRequest(ctx, apiReq)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if uconn.ConnectionState().NegotiatedProtocol == "h2" {
		return roundTripH2(uconn, req)
	}
	return roundTripH1(uconn, req)
}

func roundTripH1(conn net.Conn, req *http.Request) (*APIResponse, error) {
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("write request failed: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}
	return readAPIResponse(resp)
}

func roundTripH2(conn net.Conn, req *http.Request) (*APIResponse, error) {
	// Connection is a hop-by-hop header HTTP/2 forbids.
	req.Header.Del("Connection")
	transport := &http2.Transport{DisableCompression: true}
	cc, err := transport.NewClientConn(conn)
	if err != nil {
		return nil, fmt.Errorf("h2 client: %w", err)
	}
	defer cc.Close()
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("h2 request failed: %w", err)
	}
	return readAPIResponse(resp)
}

func readAPIResponse(resp *http.Response) (*APIResponse, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	return &APIResponse{StatusCode: resp.StatusCode, Status: resp.Status, Proto: resp.Proto, Body: body}, nil
}

// doPlain is an ordinary HTTPS request with the system resolver and Go's TLS stack. It exists for
// runs where the API is known to be reachable without obfuscation (inside a tunnel).
func doPlain(ctx context.Context, apiReq APIRequest, hooks *testHooks) (*APIResponse, error) {
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: hooks.roots},
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 12 * time.Second,
	}
	if hooks.directAddr != nil {
		target := hooks.directAddr(netip.Addr{})
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		}
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := newAPIHTTPRequest(ctx, apiReq)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("plain request failed: %w", err)
	}
	out, err := readAPIResponse(resp)
	if err != nil {
		return nil, err
	}
	out.Via = "plain"
	return out, nil
}

// boundedDeadline is now+d, or the context deadline when that comes first.
func boundedDeadline(ctx context.Context, d time.Duration) time.Time {
	deadline := time.Now().Add(d)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}
