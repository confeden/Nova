package masque

// Cloudflare WARP API transport. Port of nova-core/engine/register.go:26-750 without the Android
// in-tunnel and local-proxy defaults. api.cloudflareclient.com is SNI-filtered in RU, so the direct
// route is uTLS with a fragmented ClientHello to the two pinned API addresses; the Opera HTTP
// proxy (127.0.0.1:1371) is a legitimate route too (N12 exonerated the enroll transport).
//
// This is a private copy inside package masque: nova-go/warp is written concurrently and did not
// build when this was ported. Merge the two once both exist.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	usquemodels "github.com/Diniboy1123/usque/models"
	utls "github.com/refraction-networking/utls"
)

const (
	apiHost    = "api.cloudflareclient.com"
	apiRegPath = "/v0a4471/reg"
	apiVersion = "a-6.35-4471"
	// apiBodyLimit bounds a response body; a device record is a few kilobytes.
	apiBodyLimit = 512 * 1024
)

// API modes of --api-mode.
const (
	APIModeAuto   = "auto"
	APIModeProxy  = "proxy"
	APIModeDirect = "direct"
	APIModePlain  = "plain"
)

// apiPinnedIPs are the only addresses accepted for the API (register.go:63-75, 721-724). Android
// also resolved the name through six DNS servers, but kept only these two addresses, so the lookup
// could add nothing and cost up to 15 s where DNS is filtered; the PC port dials them directly.
var apiPinnedIPs = []netip.Addr{
	netip.MustParseAddr("104.16.192.82"),
	netip.MustParseAddr("104.16.24.84"),
}

// ErrAPIUnreachable wraps "every route failed without an HTTP response".
var ErrAPIUnreachable = errors.New("Cloudflare API unreachable via every route")

type apiProfile struct {
	label            string
	helloID          utls.ClientHelloID
	splitPlan        []int
	fragmentSize     int
	fragmentBytes    int
	fragmentDelay    time.Duration
	handshakeTimeout time.Duration
}

// apiProfiles is register.go:310-433 verbatim.
func apiProfiles() []apiProfile {
	return []apiProfile{
		{"android-okhttp-multisplit-512", utls.HelloAndroid_11_OkHttp, []int{1, 255, 256}, 0, 512, 4 * time.Millisecond, 9 * time.Second},
		{"android-okhttp-multisplit-664", utls.HelloAndroid_11_OkHttp, []int{1, 663}, 0, 664, 4 * time.Millisecond, 9 * time.Second},
		{"chrome-multisplit-681", utls.HelloChrome_Auto, []int{1, 680}, 0, 681, 4 * time.Millisecond, 9 * time.Second},
		{"chrome-multisplit-540", utls.HelloChrome_Auto, []int{1, 269, 270}, 0, 540, 4 * time.Millisecond, 9 * time.Second},
		{"firefox-multisplit-681", utls.HelloFirefox_Auto, []int{1, 680}, 0, 681, 4 * time.Millisecond, 9 * time.Second},
		{"firefox-multisplit-540", utls.HelloFirefox_Auto, []int{1, 269, 270}, 0, 540, 4 * time.Millisecond, 9 * time.Second},
		{"randomized-noalpn-multisplit-664", utls.HelloRandomizedNoALPN, []int{1, 663}, 0, 664, 4 * time.Millisecond, 9 * time.Second},
		{"randomized-noalpn-multisplit-540", utls.HelloRandomizedNoALPN, []int{1, 269, 270}, 0, 540, 4 * time.Millisecond, 9 * time.Second},
		{"android-okhttp-split-16", utls.HelloAndroid_11_OkHttp, nil, 16, 640, 5 * time.Millisecond, 8 * time.Second},
		{"android-okhttp-split-32", utls.HelloAndroid_11_OkHttp, nil, 32, 768, 4 * time.Millisecond, 8 * time.Second},
		{"chrome-split-32", utls.HelloChrome_Auto, nil, 32, 896, 4 * time.Millisecond, 8 * time.Second},
		{"firefox-split-24", utls.HelloFirefox_Auto, nil, 24, 768, 4 * time.Millisecond, 8 * time.Second},
		{"randomized-noalpn-split-24", utls.HelloRandomizedNoALPN, nil, 24, 768, 4 * time.Millisecond, 8 * time.Second},
		{"chrome-split-16", utls.HelloChrome_Auto, nil, 16, 640, 4 * time.Millisecond, 8 * time.Second},
		{"android-okhttp-split-24", utls.HelloAndroid_11_OkHttp, nil, 24, 736, 5 * time.Millisecond, 6 * time.Second},
	}
}

type apiRequest struct {
	label   string
	method  string
	path    string
	body    []byte
	token   string
	headers map[string]string
}

type apiResponse struct {
	StatusCode int
	Status     string
	Body       []byte
	Via        string
}

// apiRoute is one way to reach the API.
type apiRoute struct {
	kind    string // "proxy" | "direct" | "plain"
	ip      netip.Addr
	profile apiProfile
	proxy   *url.URL // kind "proxy"
}

// label names the route without credentials: "104.16.192.82/<profile>", "proxy https://host:port", "plain".
func (r apiRoute) label() string {
	switch r.kind {
	case "direct":
		return r.ip.String() + "/" + r.profile.label
	case "proxy":
		return "proxy " + proxyURLLabel(r.proxy)
	default:
		return r.kind
	}
}

// group is what a non-200 answer ends: every direct profile reaches the same server, while each
// proxy (and plain) leaves through its own egress.
func (r apiRoute) group() string {
	if r.kind == "direct" {
		return r.kind
	}
	return r.label()
}

// proxyURLLabel is the log-safe form of a proxy URL: scheme://host:port, never the credentials.
func proxyURLLabel(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// APIClient performs Cloudflare API calls over the configured routes.
type APIClient struct {
	mode    string
	proxies []*url.URL // tried in order before the direct routes
	log     *Logger

	// dialContext (plain route only) and rootCAs replace the network and the system roots in tests.
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	rootCAs     *x509.CertPool

	mu            sync.Mutex
	winner        *apiRoute // last route that returned HTTP 200; tried first next time
	relayOutdated bool      // a Nova relay refused CONNECT with X-Nova-Relay-Reason: outdated-client
	relayCurrent  string    // its X-Nova-Relay-Current, when sent
	// proxyDown holds proxies auto mode skips for the rest of the run: not accepting connections, or
	// refusing CONNECT with 407. routes() runs for every API call, and re-probing a dead remote relay
	// each time would spend the --timeout budget before the direct routes.
	proxyDown map[*url.URL]bool
}

// NewAPIClient validates the mode/proxy combination.
func NewAPIClient(mode, proxy string, log *Logger) (*APIClient, error) {
	var proxies []string
	if strings.TrimSpace(proxy) != "" {
		proxies = []string{proxy}
	}
	return newAPIClient(mode, proxies, log)
}

// newAPIClient is NewAPIClient with several proxies, tried in the given order (duplicates dropped).
func newAPIClient(mode string, proxies []string, log *Logger) (*APIClient, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = APIModeAuto
	}
	switch mode {
	case APIModeAuto, APIModeProxy, APIModeDirect, APIModePlain:
	default:
		return nil, fmt.Errorf("unknown --api-mode %q (auto|proxy|direct|plain)", mode)
	}
	c := &APIClient{mode: mode, log: log}
	seen := make(map[string]bool)
	for _, raw := range proxies {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			// Never echo the value: a relay URL carries a password.
			return nil, fmt.Errorf("--api-proxy and %s must hold http:// or https:// URLs", apiProxyEnv)
		}
		if seen[u.String()] {
			continue
		}
		seen[u.String()] = true
		c.proxies = append(c.proxies, u)
	}
	if mode == APIModeProxy && len(c.proxies) == 0 {
		return nil, fmt.Errorf("--api-mode proxy needs --api-proxy or %s", apiProxyEnv)
	}
	return c, nil
}

// winnerLabel names the route of the last HTTP 200 ("" before any), log-safe.
func (c *APIClient) winnerLabel() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.winner == nil {
		return ""
	}
	return c.winner.label()
}

// proxyLabel lists the configured proxies in log-safe form (credentials removed).
func (c *APIClient) proxyLabel() string {
	labels := make([]string, 0, len(c.proxies))
	for _, u := range c.proxies {
		labels = append(labels, proxyURLLabel(u))
	}
	return strings.Join(labels, ", ")
}

// relayState reports whether a Nova relay called this client outdated, and the version it named.
func (c *APIClient) relayState() (outdated bool, current string) {
	if c == nil {
		return false, ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.relayOutdated, c.relayCurrent
}

func (c *APIClient) routes(ctx context.Context) []apiRoute {
	var direct []apiRoute
	for _, ip := range apiPinnedIPs {
		for _, p := range apiProfiles() {
			direct = append(direct, apiRoute{kind: "direct", ip: ip, profile: p})
		}
	}
	var out []apiRoute
	switch c.mode {
	case APIModeProxy:
		for _, u := range c.proxies {
			out = append(out, apiRoute{kind: "proxy", proxy: u})
		}
	case APIModeDirect:
		out = direct
	case APIModePlain:
		out = []apiRoute{{kind: "plain"}}
	default:
		// auto = proxies (given and reachable) -> direct uTLS profiles -> plain (and-masque.md §8.2).
		for _, u := range c.proxies {
			c.mu.Lock()
			down := c.proxyDown[u]
			c.mu.Unlock()
			switch {
			case down:
			case c.proxyReachable(ctx, u):
				out = append(out, apiRoute{kind: "proxy", proxy: u})
			default:
				c.markProxyDown(u)
				c.log.Warn("API proxy is not accepting connections, skipping it", "proxy", proxyURLLabel(u))
			}
		}
		out = append(out, direct...)
		out = append(out, apiRoute{kind: "plain"})
	}
	c.mu.Lock()
	winner := c.winner
	c.mu.Unlock()
	if winner != nil {
		for i, r := range out {
			if r.label() == winner.label() {
				out = append([]apiRoute{r}, slices.Delete(out, i, i+1)...)
				break
			}
		}
	}
	return out
}

func (c *APIClient) markProxyDown(u *url.URL) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proxyDown == nil {
		c.proxyDown = make(map[*url.URL]bool)
	}
	c.proxyDown[u] = true
}

func (c *APIClient) proxyReachable(ctx context.Context, u *url.URL) bool {
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	// A local proxy that is not running refuses at once; a remote relay needs a name lookup and a
	// round trip first.
	wait := time.Second
	if ip, err := netip.ParseAddr(u.Hostname()); err != nil || !ip.IsLoopback() {
		wait = 4 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", host)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// do sends one API request. It returns the first HTTP 200; otherwise the first non-200 response
// (a real answer from Cloudflare beats a transport error); otherwise ErrAPIUnreachable.
//
// A non-200 answer ends the current route group: every direct profile reaches the same server, so
// asking 29 more times would only repeat the answer. Each proxy and plain are still tried because
// their egress addresses differ.
func (c *APIClient) do(ctx context.Context, req apiRequest) (*apiResponse, error) {
	var (
		failures  []string
		first     *apiResponse
		skipGroup string
	)
	for _, route := range c.routes(ctx) {
		if err := ctx.Err(); err != nil {
			break
		}
		if route.group() == skipGroup {
			continue
		}
		started := time.Now()
		c.log.Debug("API request", "label", req.label, "route", c.routeLog(route))
		resp, err := c.doRoute(ctx, route, req)
		if err != nil {
			failures = append(failures, route.label()+": "+err.Error())
			c.log.Debug("API route failed", "label", req.label, "route", c.routeLog(route), "err", err)
			continue
		}
		c.log.Info("API response", "label", req.label, "status", resp.Status, "route", c.routeLog(route),
			"ms", time.Since(started).Milliseconds())
		if resp.StatusCode == http.StatusOK {
			r := route
			c.mu.Lock()
			c.winner = &r
			c.mu.Unlock()
			return resp, nil
		}
		if first == nil {
			first = resp
		}
		skipGroup = route.group()
	}
	if first != nil {
		return first, nil
	}
	if err := ctx.Err(); err != nil && len(failures) == 0 {
		return nil, fmt.Errorf("%w: %v", ErrAPIUnreachable, err)
	}
	if len(failures) > 6 {
		failures = append(failures[:6], fmt.Sprintf("… %d more", len(failures)-6))
	}
	return nil, fmt.Errorf("%w: %s", ErrAPIUnreachable, strings.Join(failures, " | "))
}

func (c *APIClient) routeLog(r apiRoute) string {
	return r.label()
}

func (c *APIClient) doRoute(ctx context.Context, route apiRoute, req apiRequest) (*apiResponse, error) {
	switch route.kind {
	case "direct":
		return c.doDirect(ctx, route, req)
	case "proxy":
		return c.doHTTPClient(ctx, req, route.proxy, route.label())
	case "plain":
		return c.doHTTPClient(ctx, req, nil, "plain")
	}
	return nil, fmt.Errorf("unknown route %q", route.kind)
}

func newAPIHTTPRequest(ctx context.Context, req apiRequest) (*http.Request, error) {
	method := strings.ToUpper(strings.TrimSpace(req.method))
	if method == "" {
		method = http.MethodPost
	}
	path := req.path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	hr, err := http.NewRequestWithContext(ctx, method, "https://"+apiHost+path, bytes.NewReader(req.body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("User-Agent", "WARP for Android")
	hr.Header.Set("CF-Client-Version", apiVersion)
	hr.Header.Set("Content-Type", "application/json; charset=UTF-8")
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("Accept-Encoding", "identity")
	hr.Header.Set("Connection", "close")
	if strings.TrimSpace(req.token) != "" {
		hr.Header.Set("Authorization", "Bearer "+strings.TrimSpace(req.token))
	}
	for k, v := range req.headers {
		hr.Header.Set(k, v)
	}
	return hr, nil
}

// doDirect is register.go:435-521: TCP to a pinned IP, fragmented uTLS ClientHello, raw HTTP/1.1.
// The certificate is verified against api.cloudflareclient.com with the system roots.
func (c *APIClient) doDirect(parent context.Context, route apiRoute, req apiRequest) (*apiResponse, error) {
	p := route.profile
	ctx, cancel := context.WithTimeout(parent, p.handshakeTimeout+6*time.Second)
	defer cancel()

	rawConn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(route.ip.String(), "443"))
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	defer rawConn.Close()
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	if tcp, ok := rawConn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	conn := rawConn
	if len(p.splitPlan) > 0 || (p.fragmentSize > 0 && p.fragmentBytes > 0) {
		conn = &fragmentedConn{Conn: rawConn, splitPlan: slices.Clone(p.splitPlan), fragmentSize: p.fragmentSize,
			fragmentBytes: p.fragmentBytes, delay: p.fragmentDelay}
	}
	tlsConn := utls.UClient(conn, &utls.Config{
		ServerName: apiHost,
		NextProtos: []string{"http/1.1"},
		MinVersion: utls.VersionTLS12,
		MaxVersion: utls.VersionTLS13,
	}, p.helloID)
	if err := tlsConn.SetDeadline(time.Now().Add(p.handshakeTimeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	hr, err := newAPIHTTPRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	hr.Host = apiHost
	if err := tlsConn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		return nil, fmt.Errorf("set request deadline: %w", err)
	}
	if err := hr.Write(tlsConn); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), hr)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiBodyLimit))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return &apiResponse{StatusCode: resp.StatusCode, Status: resp.Status, Body: body, Via: route.label()}, nil
}

// proxyRefusedError is a CONNECT the proxy answered with a non-200 status. A Nova relay names the
// reason in X-Nova-Relay-Reason ("outdated-client": the relay login/key of this Nova version is
// retired) and the current version in X-Nova-Relay-Current; Go's own error would drop both.
type proxyRefusedError struct {
	Status  string
	Reason  string
	Current string
}

func (e *proxyRefusedError) Error() string {
	msg := "proxy refused CONNECT: " + e.Status
	switch {
	case e.Reason != "" && e.Current != "":
		msg += " (reason: " + e.Reason + ", current: " + e.Current + ")"
	case e.Reason != "":
		msg += " (reason: " + e.Reason + ")"
	}
	return msg
}

func (c *APIClient) doHTTPClient(parent context.Context, req apiRequest, proxy *url.URL, via string) (*apiResponse, error) {
	transport := &http.Transport{
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if c.rootCAs != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: c.rootCAs}
	}
	if proxy != nil {
		transport.Proxy = http.ProxyURL(proxy)
		transport.OnProxyConnectResponse = func(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
			if res.StatusCode == http.StatusOK {
				return nil
			}
			refused := &proxyRefusedError{Status: res.Status, Reason: strings.TrimSpace(res.Header.Get("X-Nova-Relay-Reason")),
				Current: truncate(strings.TrimSpace(res.Header.Get("X-Nova-Relay-Current")), 40)}
			if res.StatusCode == http.StatusProxyAuthRequired {
				c.markProxyDown(proxy) // the login will not change during this run
			}
			if refused.Reason == "outdated-client" {
				c.mu.Lock()
				c.relayOutdated = true
				if refused.Current != "" {
					c.relayCurrent = refused.Current
				}
				c.mu.Unlock()
				c.log.Warn("Nova relay refused an outdated client; update Nova", "proxy", proxyURLLabel(proxy), "current", refused.Current)
			}
			return refused
		}
	} else if c.dialContext != nil {
		transport.DialContext = c.dialContext
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	hr, err := newAPIHTTPRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(hr)
	if err != nil {
		return nil, sanitizeProxyError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiBodyLimit))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return &apiResponse{StatusCode: resp.StatusCode, Status: resp.Status, Body: body, Via: via}, nil
}

// sanitizeProxyError drops the URL from *url.Error: a proxy URL may carry credentials and the
// request URL adds nothing.
func sanitizeProxyError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// fragmentedConn splits the first bytes (the ClientHello) into small writes (register.go:752-832).
type fragmentedConn struct {
	net.Conn
	splitPlan     []int
	fragmentSize  int
	fragmentBytes int
	delay         time.Duration
}

func (c *fragmentedConn) Write(p []byte) (int, error) {
	if c.fragmentBytes <= 0 || len(p) == 0 {
		return c.Conn.Write(p)
	}
	total := 0
	limit := min(len(p), c.fragmentBytes)
	for len(c.splitPlan) > 0 && total < limit {
		next := c.splitPlan[0]
		c.splitPlan = c.splitPlan[1:]
		if next <= 0 {
			continue
		}
		end := min(total+next, limit)
		n, err := c.Conn.Write(p[total:end])
		total += n
		if err != nil {
			c.fragmentBytes = max(c.fragmentBytes-total, 0)
			return total, err
		}
		if total < limit && c.delay > 0 {
			time.Sleep(c.delay)
		}
	}
	if c.fragmentSize <= 0 {
		c.fragmentSize = limit
	}
	for total < limit {
		end := min(total+c.fragmentSize, limit)
		n, err := c.Conn.Write(p[total:end])
		total += n
		if err != nil {
			c.fragmentBytes = max(c.fragmentBytes-total, 0)
			return total, err
		}
		if total < limit && c.delay > 0 {
			time.Sleep(c.delay)
		}
	}
	c.fragmentBytes = max(c.fragmentBytes-total, 0)
	if total == len(p) {
		return total, nil
	}
	n, err := c.Conn.Write(p[total:])
	return total + n, err
}

// ---- API operations ------------------------------------------------------------------------

// apiStatusError is a non-200 answer from Cloudflare.
type apiStatusError struct {
	Status string
	Code   int
	Detail string
	API    *usquemodels.APIError
}

func (e *apiStatusError) Error() string {
	if e.Detail != "" {
		return "Cloudflare API " + e.Status + ": " + e.Detail
	}
	return "Cloudflare API " + e.Status
}

func statusError(resp *apiResponse) error {
	e := &apiStatusError{Status: resp.Status, Code: resp.StatusCode}
	var apiErr usquemodels.APIError
	if json.Unmarshal(resp.Body, &apiErr) == nil && len(apiErr.Errors) > 0 {
		e.API = &apiErr
		e.Detail = apiErr.ErrorsAsString("; ")
	} else {
		e.Detail = truncate(strings.TrimSpace(string(resp.Body)), 200)
	}
	return e
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}

// cloudflareTime is the long-form TOS timestamp in UTC (register.go:748-750).
func cloudflareTime(now time.Time) string {
	return now.UTC().Format("2006-01-02T15:04:05.000-07:00")
}

func randomSerial() (string, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buf), nil
}

// registerDevice is POST /reg with a throwaway curve25519 key: the WireGuard key is replaced by the
// MASQUE enroll anyway (usque api/cloudflare.go:16-17).
func (c *APIClient) registerDevice(ctx context.Context, model, locale, jwt string) (usquemodels.AccountData, *apiResponse, error) {
	wgKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, wgKey); err != nil {
		return usquemodels.AccountData{}, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return usquemodels.AccountData{}, nil, err
	}
	body, err := json.Marshal(usquemodels.Registration{
		Key:     encodeB64(wgKey),
		Tos:     cloudflareTime(time.Now()),
		Model:   model,
		Serial:  serial,
		KeyType: "curve25519",
		TunType: "wireguard",
		Locale:  locale,
	})
	if err != nil {
		return usquemodels.AccountData{}, nil, err
	}
	req := apiRequest{label: "register", method: http.MethodPost, path: apiRegPath, body: body}
	if strings.TrimSpace(jwt) != "" {
		req.headers = map[string]string{"CF-Access-Jwt-Assertion": strings.TrimSpace(jwt)}
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return usquemodels.AccountData{}, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return usquemodels.AccountData{}, resp, statusError(resp)
	}
	var account usquemodels.AccountData
	if err := json.Unmarshal(resp.Body, &account); err != nil {
		return usquemodels.AccountData{}, resp, fmt.Errorf("decode registration: %w", err)
	}
	if strings.TrimSpace(account.ID) == "" || strings.TrimSpace(account.Token) == "" {
		return usquemodels.AccountData{}, resp, errors.New("registration response has no device id or token")
	}
	return account, resp, nil
}

// enrollKey is PATCH /reg/{id} with the MASQUE key (masque.go:445-535, without the activation).
func (c *APIClient) enrollKey(ctx context.Context, deviceID, token string, publicDER []byte, name string) (usquemodels.AccountData, *apiResponse, error) {
	update := usquemodels.DeviceUpdate{Key: encodeB64(publicDER), KeyType: "secp256r1", TunType: "masque", Name: strings.TrimSpace(name)}
	body, err := json.Marshal(update)
	if err != nil {
		return usquemodels.AccountData{}, nil, err
	}
	return c.deviceCall(ctx, "enroll", http.MethodPatch, deviceID, token, body)
}

// activateWarp is PATCH {"warp_enabled":true}. `{"warp":true}` returns 200 and is silently ignored,
// so callers check the flag in the answer, not the status (masque.go:513-532).
func (c *APIClient) activateWarp(ctx context.Context, deviceID, token string) (usquemodels.AccountData, *apiResponse, error) {
	return c.deviceCall(ctx, "activate", http.MethodPatch, deviceID, token, []byte(`{"warp_enabled":true}`))
}

// fetchDevice is GET /reg/{id}; it never rotates anything.
func (c *APIClient) fetchDevice(ctx context.Context, deviceID, token string) (usquemodels.AccountData, *apiResponse, error) {
	return c.deviceCall(ctx, "device", http.MethodGet, deviceID, token, nil)
}

// setLicense is PUT /reg/{id}/account; returns account_type as the server sees it.
func (c *APIClient) setLicense(ctx context.Context, deviceID, token, license string) (string, error) {
	body, err := json.Marshal(map[string]string{"license": strings.TrimSpace(license)})
	if err != nil {
		return "", err
	}
	resp, err := c.do(ctx, apiRequest{label: "license", method: http.MethodPut,
		path: apiRegPath + "/" + url.PathEscape(deviceID) + "/account", body: body, token: token})
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", statusError(resp)
	}
	var account struct {
		AccountType string `json:"account_type"`
	}
	if err := json.Unmarshal(resp.Body, &account); err != nil {
		return "", fmt.Errorf("decode license answer: %w", err)
	}
	return strings.TrimSpace(account.AccountType), nil
}

func (c *APIClient) deviceCall(ctx context.Context, label, method, deviceID, token string, body []byte) (usquemodels.AccountData, *apiResponse, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" || strings.TrimSpace(token) == "" {
		return usquemodels.AccountData{}, nil, errors.New("device id and access token are required")
	}
	resp, err := c.do(ctx, apiRequest{label: label, method: method, path: apiRegPath + "/" + url.PathEscape(deviceID), body: body, token: token})
	if err != nil {
		return usquemodels.AccountData{}, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return usquemodels.AccountData{}, resp, statusError(resp)
	}
	var account usquemodels.AccountData
	if err := json.Unmarshal(resp.Body, &account); err != nil {
		return usquemodels.AccountData{}, resp, fmt.Errorf("decode %s answer: %w", label, err)
	}
	return account, resp, nil
}

// logDeviceShape logs which fields Cloudflare sent and the flag values (masque.go:537-564): the
// model's omitempty flags read false both when sent as false and when absent.
func logDeviceShape(l *Logger, stage string, body []byte) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return
	}
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	slices.Sort(names)
	kv := []any{"stage", stage, "fields", strings.Join(names, ",")}
	for _, flag := range []string{"warp_enabled", "enabled", "waitlist_enabled", "type", "tunnel_type", "key_type"} {
		if v, ok := raw[flag]; ok {
			kv = append(kv, flag, strings.Trim(string(v), `"`))
		}
	}
	l.Info("device record", kv...)
}
