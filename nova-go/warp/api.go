package warp

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Mode selects which transports DoAPIRequest may use.
type Mode string

const (
	// ModeAuto tries the direct uTLS tiers, then the proxy tier when a proxy is configured.
	ModeAuto Mode = "auto"
	// ModeDirect uses only the pinned addresses with uTLS profiles and fragmentation.
	ModeDirect Mode = "direct"
	// ModeProxy uses only the CONNECT proxy (uTLS inside the tunnel).
	ModeProxy Mode = "proxy"
	// ModePlain is one ordinary HTTPS request (system DNS, Go TLS), for use inside a tunnel.
	ModePlain Mode = "plain"
)

// ParseMode accepts auto|direct|proxy|plain (empty means auto).
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return ModeAuto, nil
	case ModeAuto, ModeDirect, ModeProxy, ModePlain:
		return m, nil
	default:
		return "", fmt.Errorf("%w: unknown api mode %q (auto|direct|proxy|plain)", ErrUsage, s)
	}
}

const (
	// proxyReserve is the slice of the overall deadline that auto mode keeps for the proxy tier, so
	// a blackholed direct path (15 profiles x 2 addresses, up to 15 s each) cannot eat all of it.
	proxyReserve = 25 * time.Second
	// dnsBudget bounds the bootstrap resolver round; the lookups run concurrently.
	dnsBudget = 2500 * time.Millisecond
	// deadIPAfter consecutive TCP dial failures take a pinned address out of rotation.
	deadIPAfter = 2
	// minAttemptTime: an attempt with less time left than this is not started.
	minAttemptTime = 1500 * time.Millisecond
)

// ErrUnreachable wraps "no transport produced an HTTP answer".
var ErrUnreachable = errors.New("cloudflare api unreachable")

// StatusError is an HTTP answer other than 200 (or a 200 that failed ValidateOK on every tier).
type StatusError struct {
	StatusCode int
	Status     string
	Body       string // truncated to 200 bytes
	Via        string
}

func (e *StatusError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("api answered %s via %s: %s", e.Status, e.Via, e.Body)
	}
	return fmt.Sprintf("api answered %s via %s", e.Status, e.Via)
}

// APIOptions configures the transports.
type APIOptions struct {
	Mode     Mode
	ProxyURL string // http://[user:pass@]host:port or https://...; required for ModeProxy
	Logf     Logf
	hooks    *testHooks
}

// testHooks lets tests aim the tiers at local servers. Nil in production.
type testHooks struct {
	directAddr    func(ip netip.Addr) string // dial target for a pinned address
	pinnedIPs     []netip.Addr               // replaces the pinned list and skips DNS
	roots         *x509.CertPool             // trust anchors for the API certificate
	proxyRoots    *x509.CertPool             // trust anchors for an https proxy
	profiles      []registrationProfile
	proxyProfiles []proxyProfile
	proxyReserve  time.Duration
}

// DoAPIRequest sends req over the tiers opts allows and returns the first 200 (that passes
// ValidateOK). When nothing succeeds it returns the first non-200 answer with a *StatusError, or an
// error wrapping ErrUnreachable when no tier got an HTTP answer at all. A definitive 4xx (bad key,
// bad request) ends the search at once: another path would only repeat it. A 429 ends only the
// tier that got it: the limit is per client address, and the proxy leaves from another one.
func DoAPIRequest(ctx context.Context, req APIRequest, opts APIOptions) (*APIResponse, error) {
	mode, err := ParseMode(string(opts.Mode))
	if err != nil {
		return nil, err
	}
	if req.Label == "" {
		req.Label = "api"
	}
	var proxy *proxyEndpoint
	if strings.TrimSpace(opts.ProxyURL) != "" {
		if proxy, err = parseProxyURL(opts.ProxyURL); err != nil {
			return nil, err
		}
	}
	if mode == ModeProxy && proxy == nil {
		return nil, fmt.Errorf("%w: api mode proxy needs a proxy URL", ErrUsage)
	}

	run := &apiRun{req: req, logf: opts.Logf, hooks: opts.hooks}
	if run.hooks == nil {
		run.hooks = &testHooks{}
	}

	switch mode {
	case ModePlain:
		run.plain(ctx)
	case ModeDirect:
		run.direct(ctx)
	case ModeProxy:
		run.viaProxy(ctx, proxy)
	case ModeAuto:
		directCtx := ctx
		if proxy != nil {
			if deadline, ok := ctx.Deadline(); ok {
				reserve := proxyReserve
				if run.hooks.proxyReserve > 0 {
					reserve = run.hooks.proxyReserve
				}
				reserve = min(reserve, time.Until(deadline)/2)
				var cancel context.CancelFunc
				directCtx, cancel = context.WithDeadline(ctx, deadline.Add(-reserve))
				defer cancel()
			}
		}
		run.direct(directCtx)
		if run.win == nil && !run.stop && proxy != nil && ctx.Err() == nil {
			run.viaProxy(ctx, proxy)
		}
	}
	return run.result(ctx)
}

// apiRun accumulates the outcome of the tiers of one DoAPIRequest.
type apiRun struct {
	req      APIRequest
	logf     Logf
	hooks    *testHooks
	win      *APIResponse
	first    *APIResponse
	stop     bool
	failures []string
}

func (r *apiRun) fail(where string, err error) {
	r.failures = append(r.failures, where+": "+err.Error())
	r.logf.printf("api %s: %s failed: %v", r.req.Label, where, err)
}

// answer books an HTTP answer. It reports true when the current tier is over; r.stop additionally
// marks the whole search as over.
func (r *apiRun) answer(resp *APIResponse) bool {
	r.logf.printf("api %s: %s via %s (%s)", r.req.Label, resp.Status, resp.Via, resp.Proto)
	if resp.StatusCode == http.StatusOK {
		if r.req.ValidateOK != nil {
			if err := r.req.ValidateOK(resp.Body); err != nil {
				r.fail(resp.Via, fmt.Errorf("200 with unusable body: %w", err))
				return false
			}
		}
		r.win = resp
		return true
	}
	if r.first == nil {
		r.first = resp
	}
	if definitiveStatus(resp.StatusCode) {
		r.stop = true
		return true
	}
	return tierEndingStatus(resp.StatusCode)
}

func (r *apiRun) result(ctx context.Context) (*APIResponse, error) {
	if r.win != nil {
		return r.win, nil
	}
	if r.first != nil {
		return r.first, &StatusError{
			StatusCode: r.first.StatusCode,
			Status:     r.first.Status,
			Body:       truncate(string(r.first.Body), 200),
			Via:        r.first.Via,
		}
	}
	failures := r.failures
	if len(failures) > 8 {
		failures = failures[:8]
	}
	detail := strings.Join(failures, " | ")
	if ctx.Err() != nil {
		if detail == "" {
			detail = "no attempt finished"
		}
		return nil, fmt.Errorf("%w: %w: %s", ErrUnreachable, ctx.Err(), detail)
	}
	if detail == "" {
		detail = "no attempt was made"
	}
	return nil, fmt.Errorf("%w: %s", ErrUnreachable, detail)
}

// definitiveStatus: a 4xx that is about the request itself. 403/407/408/421/425 can depend on the
// path (edge filtering, a proxy, timing) and let the next tier try; 429 is tierEndingStatus.
func definitiveStatus(code int) bool {
	if code < 400 || code > 499 {
		return false
	}
	switch code {
	case http.StatusForbidden, http.StatusProxyAuthRequired, http.StatusRequestTimeout,
		http.StatusMisdirectedRequest, http.StatusTooEarly, http.StatusTooManyRequests:
		return false
	}
	return true
}

// tierEndingStatus: an answer that the rest of this tier would only repeat, while another tier
// (another egress address) may not. Cloudflare rate-limits registration per client address.
func tierEndingStatus(code int) bool {
	return code == http.StatusTooManyRequests
}

func (r *apiRun) plain(ctx context.Context) {
	r.logf.printf("api %s: plain request", r.req.Label)
	resp, err := doPlain(ctx, r.req, r.hooks)
	if err != nil {
		r.fail("plain", err)
		return
	}
	r.answer(resp)
}

// direct walks the profile table against the pinned addresses. The address rotates per attempt, so
// the first attempts cover different fingerprints on both addresses; a second round swaps them. An
// address whose TCP dial failed deadIPAfter times in a row is skipped for the rest of the run.
func (r *apiRun) direct(ctx context.Context) {
	ips := r.hooks.pinnedIPs
	if len(ips) == 0 {
		ips = resolveRegistrationIPs(ctx, r.logf)
	}
	profiles := r.hooks.profiles
	if len(profiles) == 0 {
		profiles = defaultProfiles()
	}
	dialFailures := make(map[netip.Addr]int, len(ips))
	for round := 0; round < len(ips); round++ {
		for k, profile := range profiles {
			if !hasTimeFor(ctx) {
				if ctx.Err() == nil {
					r.logf.printf("api %s: direct tier out of time", r.req.Label)
				}
				return
			}
			ip, ok := pickIP(ips, k+round, dialFailures)
			if !ok {
				r.logf.printf("api %s: no pinned address accepts TCP, leaving the direct tier", r.req.Label)
				return
			}
			where := "direct/" + ip.String() + "/" + profile.label
			resp, err := r.viaIP(ctx, ip, profile)
			if err != nil {
				if errors.Is(err, errTCPDial) {
					dialFailures[ip]++
				} else {
					dialFailures[ip] = 0
				}
				r.fail(where, err)
				continue
			}
			dialFailures[ip] = 0
			resp.Via = where
			if r.answer(resp) {
				return
			}
		}
	}
}

func pickIP(ips []netip.Addr, start int, dialFailures map[netip.Addr]int) (netip.Addr, bool) {
	for i := range ips {
		ip := ips[(start+i)%len(ips)]
		if dialFailures[ip] < deadIPAfter {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func hasTimeFor(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < minAttemptTime {
		return false
	}
	return true
}

var errTCPDial = errors.New("tcp dial failed")

func (r *apiRun) viaIP(parent context.Context, ip netip.Addr, profile registrationProfile) (*APIResponse, error) {
	ctx, cancel := context.WithTimeout(parent, profile.handshakeTimeout+6*time.Second)
	defer cancel()

	target := net.JoinHostPort(ip.String(), "443")
	if r.hooks.directAddr != nil {
		target = r.hooks.directAddr(ip)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp4", target)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errTCPDial, err)
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	// The local address tells "went out the physical interface" from "went through a tunnel".
	r.logf.printf("api %s: socket %s -> %s (%s)", r.req.Label, raw.LocalAddr(), raw.RemoteAddr(), profile.label)

	return tlsExchange(ctx, newFragmentedConn(raw, profile), profile.helloID, profile.handshakeTimeout, r.req, r.hooks.roots)
}

// viaProxy: CONNECT to APIHost:443 through the proxy, then uTLS inside. A proxy that cannot be
// reached or refuses CONNECT ends the tier; a TLS or HTTP failure moves to the next profile.
func (r *apiRun) viaProxy(ctx context.Context, proxy *proxyEndpoint) {
	profiles := r.hooks.proxyProfiles
	if len(profiles) == 0 {
		profiles = defaultProxyProfiles()
	}
	r.logf.printf("api %s: trying proxy %s", r.req.Label, proxy)
	for _, profile := range profiles {
		if !hasTimeFor(ctx) {
			return
		}
		where := "proxy/" + profile.label
		resp, err := r.viaProxyOnce(ctx, proxy, profile)
		if err != nil {
			r.fail(where, err)
			var proxyErr *ProxyError
			if errors.Is(err, errProxyDial) || errors.As(err, &proxyErr) {
				return
			}
			continue
		}
		resp.Via = where
		if r.answer(resp) {
			return
		}
	}
}

func (r *apiRun) viaProxyOnce(parent context.Context, proxy *proxyEndpoint, profile proxyProfile) (*APIResponse, error) {
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	conn, err := dialViaProxy(ctx, proxy, net.JoinHostPort(APIHost, "443"), r.hooks.proxyRoots)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	return tlsExchange(ctx, conn, profile.helloID, 10*time.Second, r.req, r.hooks.roots)
}

// resolveRegistrationIPs asks the bootstrap resolvers (concurrently, within dnsBudget) and keeps
// only answers that are pinned addresses, then adds the pinned list. The result is therefore always
// the pinned set in a stable order; the lookups are kept for parity with Android and for the log.
func resolveRegistrationIPs(ctx context.Context, logf Logf) []netip.Addr {
	lookupCtx, cancel := context.WithTimeout(ctx, dnsBudget)
	defer cancel()

	type answer struct {
		ips []net.IP
		err error
	}
	answers := make(chan answer, len(registrationDNS))
	for _, server := range registrationDNS {
		go func(server string) {
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "udp", server)
				},
			}
			ips, err := resolver.LookupIP(lookupCtx, "ip4", APIHost)
			answers <- answer{ips: ips, err: err}
		}(server)
	}

	seen := make(map[netip.Addr]bool)
	var ordered []netip.Addr
	add := func(ip netip.Addr) {
		if ip.IsValid() && ip.Is4() && isPinnedIP(ip) && !seen[ip] {
			seen[ip] = true
			ordered = append(ordered, ip)
		}
	}
	confirmed, unexpected, failed := 0, 0, 0
	for range registrationDNS {
		a := <-answers
		if a.err != nil {
			failed++
			continue
		}
		matched := false
		for _, raw := range a.ips {
			addr, ok := netip.AddrFromSlice(raw)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if isPinnedIP(addr) {
				matched = true
				add(addr)
			} else {
				unexpected++
			}
		}
		if matched {
			confirmed++
		}
	}
	for _, ip := range registrationPinnedIPs {
		add(ip)
	}
	slices.SortFunc(ordered, func(a, b netip.Addr) int { return strings.Compare(a.String(), b.String()) })
	logf.printf("api: bootstrap DNS %d/%d resolvers confirmed a pinned address, %d unexpected answers ignored, %d lookups failed",
		confirmed, len(registrationDNS), unexpected, failed)
	return ordered
}

func isPinnedIP(ip netip.Addr) bool {
	return slices.Contains(registrationPinnedIPs, ip)
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
