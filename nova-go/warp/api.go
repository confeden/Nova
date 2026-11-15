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
	"sync"
	"time"

	"nova-pc/nova-go/internal/apifail"
	"nova-pc/nova-go/internal/apistate"
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
	// directWidth is how many direct attempts may be in flight at once. A filter that swallows a
	// ClientHello makes an attempt cost its whole handshake timeout (6-9 s), so walking 15 profiles
	// one by one never gets past the first few inside the operation's deadline.
	directWidth = 3
	// hedgeStep starts one more attempt when the running ones are still silent after this long; a
	// failed attempt starts the next one at once.
	hedgeStep = 1500 * time.Millisecond
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
	// State, when set, remembers the last direct route that got an answer and the remote proxies that
	// did not accept a connection, across runs. Nil means no memory.
	State *apistate.Store
	hooks *testHooks
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
	directWidth   int           // 0 = directWidth
	hedgeStep     time.Duration // 0 = hedgeStep
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

	run := &apiRun{req: req, logf: opts.Logf, hooks: opts.hooks, state: opts.State}
	if run.hooks == nil {
		run.hooks = &testHooks{}
	}
	run.logPlan(ctx, mode, proxy)

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
		if !run.won() && !run.stopped() && proxy != nil && ctx.Err() == nil {
			run.viaProxy(ctx, proxy)
		}
	}
	return run.result(ctx)
}

// apiRun accumulates the outcome of the tiers of one DoAPIRequest. The direct tier runs attempts in
// parallel, so everything below mu may be touched from several goroutines.
type apiRun struct {
	req   APIRequest
	logf  Logf
	hooks *testHooks
	state *apistate.Store

	mu       sync.Mutex
	win      *APIResponse
	first    *APIResponse
	stop     bool
	tierDone bool // an attempt ended the current tier (a win, a definitive answer, a 429)
	failures []routeFailure
}

// routeFailure is one attempt that produced no HTTP answer. group names the route family for the
// summary ("direct 104.16.24.84", "proxy", "plain"); class is a short reason.
type routeFailure struct {
	where string
	group string
	class string
	err   error
}

func (r *apiRun) fail(where string, err error) {
	r.mu.Lock()
	r.failures = append(r.failures, routeFailure{where: where, group: failureGroup(where), class: failureClass(err), err: err})
	r.mu.Unlock()
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
		r.mu.Lock()
		r.win = resp
		r.tierDone = true
		r.mu.Unlock()
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.first == nil {
		r.first = resp
	}
	if definitiveStatus(resp.StatusCode) {
		r.stop = true
		r.tierDone = true
		return true
	}
	if tierEndingStatus(resp.StatusCode) {
		r.tierDone = true
		return true
	}
	return false
}

func (r *apiRun) over() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tierDone
}

func (r *apiRun) stopped() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stop
}

func (r *apiRun) won() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.win != nil
}

// beginTier re-arms tierDone: a 429 ends one tier, the next one starts clean.
func (r *apiRun) beginTier() {
	r.mu.Lock()
	r.tierDone = r.win != nil || r.stop
	r.mu.Unlock()
}

// logPlan writes which routes this call may use and how much time it has: the one line that tells a
// later reader whether "unreachable" meant "tried everything" or "tried little".
func (r *apiRun) logPlan(ctx context.Context, mode Mode, proxy *proxyEndpoint) {
	budget := "none"
	if deadline, ok := ctx.Deadline(); ok {
		budget = time.Until(deadline).Round(time.Second).String()
	}
	via := "none"
	if proxy != nil {
		via = proxy.String()
		if left, dead := r.state.ProxyDead(via); dead {
			via += " (quarantined " + left.Round(time.Second).String() + ")"
		}
	}
	remembered := "none"
	if ip, profile, ok := r.state.Winner(); ok {
		remembered = ip + "/" + profile
	}
	r.logf.printf("api %s: plan mode=%s proxy=%s budget=%s remembered-direct=%s", r.req.Label, mode, via, budget, remembered)
}

func (r *apiRun) result(ctx context.Context) (*APIResponse, error) {
	r.mu.Lock()
	win, first, failures := r.win, r.first, append([]routeFailure(nil), r.failures...)
	r.mu.Unlock()
	if win != nil {
		return win, nil
	}
	if first != nil {
		return first, &StatusError{
			StatusCode: first.StatusCode,
			Status:     first.Status,
			Body:       truncate(string(first.Body), 200),
			Via:        first.Via,
		}
	}
	raw := make([]string, 0, len(failures))
	for _, f := range failures {
		if f.class == apifail.Superseded {
			continue
		}
		raw = append(raw, f.where+": "+f.err.Error())
	}
	if len(raw) > 8 {
		raw = raw[:8]
	}
	// The summary goes first: callers truncate this text, and its first 240 characters must already
	// say which routes failed and how.
	detail := summarizeFailures(failures)
	if len(raw) > 0 {
		if detail != "" {
			detail += " | "
		}
		detail += strings.Join(raw, " | ")
	}
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

// failureGroup is the route family of a failure's "where" label.
func failureGroup(where string) string {
	parts := strings.Split(where, "/")
	switch parts[0] {
	case "direct":
		if len(parts) > 1 {
			return "direct " + parts[1]
		}
		return "direct"
	case "proxy":
		return "proxy"
	}
	return where
}

// failureClass names a transport failure in one short word, so that "3xtls-timeout" can be read at a
// glance where the raw text is a line of socket addresses.
func failureClass(err error) string {
	if err == nil {
		return "none"
	}
	var proxyErr *ProxyError
	switch {
	case errors.Is(err, errSuperseded):
		return apifail.Superseded
	case errors.As(err, &proxyErr):
		return "proxy-refused"
	case errors.Is(err, errProxyDial):
		return "proxy-dial"
	case errors.Is(err, errTCPDial):
		return "tcp-dial"
	}
	return apifail.ClassifyText(err.Error())
}

// summarizeFailures: "direct 104.16.24.84: 2xtls-timeout; direct 104.16.192.82: tls-timeout; proxy: proxy-dial".
func summarizeFailures(failures []routeFailure) string {
	entries := make([]apifail.Entry, 0, len(failures))
	for _, f := range failures {
		entries = append(entries, apifail.Entry{Group: f.group, Class: f.class})
	}
	return apifail.Summarize(entries)
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

// errSuperseded marks an attempt that was abandoned after its handshake because another attempt of
// the same call had already produced the answer. It is not a failure of its route.
var errSuperseded = errors.New("superseded by another attempt")

// apiGate admits one request at a time and reports the answer back while it still holds the gate.
type apiGate func(context.Context) (done func(*APIResponse, error), err error)

// direct walks the profile table against the pinned addresses, a few attempts at a time. The address
// rotates per attempt, so the first attempts cover different fingerprints on both addresses; a second
// round swaps them. An address whose TCP dial failed deadIPAfter times in a row is skipped for the
// rest of the run. The route that answered last time (apistate) goes first.
//
// Attempts overlap in their handshakes only: before a request is written each attempt takes a gate
// that admits one at a time and refuses once the call is answered, so a registration cannot be sent
// twice (it creates a device).
func (r *apiRun) direct(ctx context.Context) {
	ips := r.hooks.pinnedIPs
	if len(ips) == 0 {
		ips = resolveRegistrationIPs(ctx, r.logf)
	}
	profiles := r.hooks.profiles
	if len(profiles) == 0 {
		profiles = defaultProfiles()
	}
	ips, profiles = r.rememberedFirst(ips, profiles)

	width := directWidth
	if r.hooks.directWidth > 0 {
		width = r.hooks.directWidth
	}
	step := hedgeStep
	if r.hooks.hedgeStep > 0 {
		step = r.hooks.hedgeStep
	}
	r.logf.printf("api %s: direct tier %d address(es) x %d profiles, %d at a time", r.req.Label, len(ips), len(profiles), width)

	r.beginTier()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg           sync.WaitGroup
		dialFailures = make(map[netip.Addr]int, len(ips))
		total        = len(ips) * len(profiles)
		finished     = make(chan struct{}, total+1)
		sem          = make(chan struct{}, 1)
		inflight     int
		next         int
		canLaunch    = true
		exhausted    bool
	)
	hedge := time.NewTimer(step)
	defer hedge.Stop()

	for !r.over() {
		if canLaunch && inflight < width && next < total && !exhausted {
			if !hasTimeFor(runCtx) {
				if runCtx.Err() == nil {
					r.logf.printf("api %s: direct tier out of time", r.req.Label)
				}
				exhausted = true
				continue
			}
			round, k := next/len(profiles), next%len(profiles)
			r.mu.Lock()
			ip, ok := pickIP(ips, k+round, dialFailures)
			r.mu.Unlock()
			if !ok {
				r.logf.printf("api %s: no pinned address accepts TCP, leaving the direct tier", r.req.Label)
				exhausted = true
				continue
			}
			next++
			inflight++
			canLaunch = false
			if !hedge.Stop() {
				select {
				case <-hedge.C:
				default:
				}
			}
			hedge.Reset(step)
			wg.Add(1)
			go func(ip netip.Addr, profile registrationProfile) {
				defer wg.Done()
				defer func() { finished <- struct{}{} }()
				err := r.directAttempt(runCtx, ip, profile, sem)
				r.mu.Lock()
				if errors.Is(err, errTCPDial) {
					dialFailures[ip]++
				} else {
					dialFailures[ip] = 0
				}
				r.mu.Unlock()
			}(ip, profiles[k])
			continue
		}
		if inflight == 0 && (next >= total || exhausted) {
			break
		}
		select {
		case <-finished:
			inflight--
			canLaunch = true
		case <-hedge.C:
			canLaunch = true
		case <-runCtx.Done():
			exhausted = true
			canLaunch = false
			for inflight > 0 {
				<-finished
				inflight--
			}
		}
	}
	cancel()
	wg.Wait()
}

// directAttempt is one direct attempt: dial, fragmented uTLS handshake, then (through the gate) the
// request. It books its own outcome and returns the transport error, if any.
func (r *apiRun) directAttempt(ctx context.Context, ip netip.Addr, profile registrationProfile, sem chan struct{}) error {
	where := "direct/" + ip.String() + "/" + profile.label
	booked := false
	var gate apiGate = func(gctx context.Context) (func(*APIResponse, error), error) {
		select {
		case sem <- struct{}{}:
		case <-gctx.Done():
			return nil, gctx.Err()
		}
		if r.over() {
			<-sem
			return nil, errSuperseded
		}
		return func(resp *APIResponse, err error) {
			defer func() { <-sem }()
			if err != nil || resp == nil {
				return
			}
			resp.Via = where
			booked = true
			r.state.NoteWinner(ip.String(), profile.label) // any HTTP answer proves the path passes the filter
			r.answer(resp)
		}, nil
	}
	_, err := r.viaIP(ctx, ip, profile, gate)
	if err == nil || booked || errors.Is(err, errSuperseded) {
		return err
	}
	if ctx.Err() != nil && r.over() {
		return err // cut off by another attempt's answer: not this route's failure
	}
	r.fail(where, err)
	return err
}

// rememberedFirst moves the direct pair that answered last time to the front of the walk.
func (r *apiRun) rememberedFirst(ips []netip.Addr, profiles []registrationProfile) ([]netip.Addr, []registrationProfile) {
	ipText, label, ok := r.state.Winner()
	if !ok {
		return ips, profiles
	}
	addr, err := netip.ParseAddr(ipText)
	if err != nil {
		return ips, profiles
	}
	ipIdx := slices.Index(ips, addr)
	profIdx := slices.IndexFunc(profiles, func(p registrationProfile) bool { return p.label == label })
	if ipIdx < 0 || profIdx < 0 {
		return ips, profiles
	}
	reordered := append([]netip.Addr{}, ips[ipIdx:]...)
	reordered = append(reordered, ips[:ipIdx]...)
	first := []registrationProfile{profiles[profIdx]}
	first = append(first, profiles[:profIdx]...)
	first = append(first, profiles[profIdx+1:]...)
	r.logf.printf("api %s: remembered direct route %s/%s goes first", r.req.Label, ipText, label)
	return reordered, first
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

func (r *apiRun) viaIP(parent context.Context, ip netip.Addr, profile registrationProfile, gate apiGate) (*APIResponse, error) {
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

	return tlsExchangeGated(ctx, newFragmentedConn(raw, profile), profile.helloID, profile.handshakeTimeout, r.req, r.hooks.roots, gate)
}

// viaProxy: CONNECT to APIHost:443 through the proxy, then uTLS inside. A proxy that cannot be
// reached or refuses CONNECT ends the tier; a TLS or HTTP failure moves to the next profile. A remote
// proxy that would not accept a connection a few minutes ago is not asked again until its
// quarantine ends (apistate); loopback proxies are always asked, they refuse instantly.
func (r *apiRun) viaProxy(ctx context.Context, proxy *proxyEndpoint) {
	profiles := r.hooks.proxyProfiles
	if len(profiles) == 0 {
		profiles = defaultProxyProfiles()
	}
	key := proxy.String()
	if left, dead := r.state.ProxyDead(key); dead {
		r.fail("proxy/"+key, fmt.Errorf("skipped, it did not accept a connection recently (quarantine %s left)", left.Round(time.Second)))
		return
	}
	r.beginTier()
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
			if errors.Is(err, errProxyDial) {
				r.state.NoteProxyDead(key)
				return
			}
			if errors.As(err, &proxyErr) {
				return
			}
			continue
		}
		r.state.NoteProxyAlive(key)
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
