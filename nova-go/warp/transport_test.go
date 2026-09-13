package warp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// testPKI is a throwaway CA with one leaf valid for the API host and 127.0.0.1.
type testPKI struct {
	roots *x509.CertPool
	leaf  tls.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nova-go test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: APIHost},
		DNSNames:     []string{APIHost},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return &testPKI{roots: roots, leaf: tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}
}

type seenRequest struct {
	proto, method, path, clientVersion, userAgent, contentType, accept, acceptEncoding, auth, body string
}

// fakeAPI is a TLS server (h2 + http/1.1) standing in for api.cloudflareclient.com.
type fakeAPI struct {
	srv    *httptest.Server
	mu     sync.Mutex
	seen   []seenRequest
	answer func(n int) (int, string) // n is the 1-based request number
}

func newFakeAPI(t *testing.T, pki *testPKI, answer func(n int) (int, string)) *fakeAPI {
	t.Helper()
	f := &fakeAPI{answer: answer}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.seen = append(f.seen, seenRequest{
			proto: r.Proto, method: r.Method, path: r.URL.Path, clientVersion: r.Header.Get("CF-Client-Version"),
			userAgent: r.UserAgent(), contentType: r.Header.Get("Content-Type"), accept: r.Header.Get("Accept"),
			acceptEncoding: r.Header.Get("Accept-Encoding"), auth: r.Header.Get("Authorization"), body: string(body),
		})
		n := len(f.seen)
		f.mu.Unlock()
		code, payload := f.answer(n)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, payload)
	}))
	f.srv.EnableHTTP2 = true
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{pki.leaf}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) requests() []seenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenRequest(nil), f.seen...)
}

func (f *fakeAPI) addr() string { return f.srv.Listener.Addr().String() }

var loopback = netip.MustParseAddr("127.0.0.1")

func profileFor(label string, id utls.ClientHelloID, plan []int, bytes int) registrationProfile {
	return registrationProfile{label: label, helloID: id, splitPlan: plan, fragmentBytes: bytes,
		fragmentDelay: time.Millisecond, handshakeTimeout: 5 * time.Second}
}

func directHooks(pki *testPKI, target string, profiles ...registrationProfile) *testHooks {
	return &testHooks{
		pinnedIPs:  []netip.Addr{loopback},
		directAddr: func(netip.Addr) string { return target },
		roots:      pki.roots,
		profiles:   profiles,
	}
}

const okDevice = `{"result":{"id":"dev","token":"tok","config":{"client_id":"AAEC","peers":[{"public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="}],"interface":{"addresses":{"v4":"172.16.0.2"}}}}}`

func registerForTest(t *testing.T, opts APIOptions) (*APIResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return Register(ctx, RegisterOptions{PublicKey: testPublicKey(), API: opts})
}

func TestDirectTierOkHttpSpeaksHTTP1(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	profile := profileFor("okhttp-test", utls.HelloAndroid_11_OkHttp, []int{1, 255, 256}, 512)
	resp, err := registerForTest(t, APIOptions{Mode: ModeDirect, hooks: directHooks(pki, api.addr(), profile)})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.Via != "direct/127.0.0.1/okhttp-test" || resp.Proto != "HTTP/1.1" {
		t.Fatalf("resp = %d %q %q", resp.StatusCode, resp.Via, resp.Proto)
	}
	if _, err := ParseRegistration(resp.Body); err != nil {
		t.Fatalf("body not parseable: %v", err)
	}
	seen := api.requests()
	if len(seen) != 1 {
		t.Fatalf("requests = %d", len(seen))
	}
	r := seen[0]
	if r.method != "POST" || r.path != RegistrationPath || r.clientVersion != ClientVersion || r.userAgent != UserAgent ||
		r.contentType != "application/json; charset=UTF-8" || r.accept != "application/json" || r.acceptEncoding != "identity" || r.auth != "" {
		t.Fatalf("request = %+v", r)
	}
	if !strings.Contains(r.body, `"key":"`+testPublicKey()+`"`) || !strings.Contains(r.body, `"key_type":"curve25519"`) {
		t.Fatalf("body = %s", r.body)
	}
}

func TestDirectTierChromeNegotiatesHTTP2(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	profile := profileFor("chrome-test", utls.HelloChrome_Auto, []int{1, 680}, 681)
	resp, err := registerForTest(t, APIOptions{Mode: ModeDirect, hooks: directHooks(pki, api.addr(), profile)})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("proto = %q, want HTTP/2.0 (Chrome offers h2)", resp.Proto)
	}
	if seen := api.requests(); len(seen) != 1 || seen[0].proto != "HTTP/2.0" || seen[0].clientVersion != ClientVersion {
		t.Fatalf("server saw %+v", seen)
	}
}

func TestDirectTierVerifiesCertificate(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	hooks := directHooks(pki, api.addr(), profileFor("okhttp-test", utls.HelloAndroid_11_OkHttp, []int{1, 511}, 512))
	hooks.roots = x509.NewCertPool() // trusts nothing
	_, err := registerForTest(t, APIOptions{Mode: ModeDirect, hooks: hooks})
	if !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "tls handshake failed") {
		t.Fatalf("err = %v, want a certificate failure", err)
	}
	if len(api.requests()) != 0 {
		t.Fatal("a request went out over an unverified connection")
	}
}

func TestDefinitiveStatusStopsTheSearch(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) {
		return 400, `{"success":false,"errors":[{"code":1000,"message":"Invalid public key"}]}`
	})
	okhttp := profileFor("a", utls.HelloAndroid_11_OkHttp, []int{1, 511}, 512)
	chrome := profileFor("b", utls.HelloChrome_Auto, []int{1, 680}, 681)
	resp, err := registerForTest(t, APIOptions{Mode: ModeDirect, hooks: directHooks(pki, api.addr(), okhttp, chrome)})
	var statusErr *StatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != 400 || resp == nil || resp.StatusCode != 400 {
		t.Fatalf("err = %v resp = %+v", err, resp)
	}
	if !strings.Contains(statusErr.Error(), "Invalid public key") {
		t.Fatalf("status error lacks the body: %v", statusErr)
	}
	if n := len(api.requests()); n != 1 {
		t.Fatalf("requests = %d, want 1 (400 is definitive)", n)
	}
}

func TestTransientStatusTriesNextProfile(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(n int) (int, string) {
		if n == 1 {
			return 503, `{"error":"busy"}`
		}
		return 200, okDevice
	})
	okhttp := profileFor("first", utls.HelloAndroid_11_OkHttp, []int{1, 511}, 512)
	chrome := profileFor("second", utls.HelloChrome_Auto, []int{1, 680}, 681)
	resp, err := registerForTest(t, APIOptions{Mode: ModeDirect, hooks: directHooks(pki, api.addr(), okhttp, chrome)})
	if err != nil || resp.Via != "direct/127.0.0.1/second" {
		t.Fatalf("err = %v resp = %+v", err, resp)
	}
}

func TestUnusable200TriesNextTierThenFails(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, `<html>portal</html>` })
	okhttp := profileFor("first", utls.HelloAndroid_11_OkHttp, []int{1, 511}, 512)
	other := profileFor("second", utls.HelloAndroid_11_OkHttp, nil, 0)
	_, err := registerForTest(t, APIOptions{Mode: ModeDirect, hooks: directHooks(pki, api.addr(), okhttp, other)})
	if !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "not a JSON object") {
		t.Fatalf("err = %v", err)
	}
	if n := len(api.requests()); n != 2 {
		t.Fatalf("requests = %d, want 2", n)
	}
}

// closedAddr returns a loopback address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestDeadAddressLeavesDirectTier(t *testing.T) {
	pki := newTestPKI(t)
	var profiles []registrationProfile
	for i := 0; i < 15; i++ {
		profiles = append(profiles, profileFor("p", utls.HelloAndroid_11_OkHttp, []int{1, 511}, 512))
	}
	hooks := directHooks(pki, closedAddr(t), profiles...)
	var dials atomic.Int64
	target := hooks.directAddr(loopback)
	hooks.directAddr = func(netip.Addr) string { dials.Add(1); return target }
	_, err := registerForTest(t, APIOptions{Mode: ModeDirect, hooks: hooks})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v", err)
	}
	if n := dials.Load(); n != deadIPAfter {
		t.Fatalf("dials = %d, want %d before the address is dropped", n, deadIPAfter)
	}
}

// fakeProxy is a CONNECT proxy that maps api.cloudflareclient.com:443 to the fake API.
type fakeProxy struct {
	ln       net.Listener
	connects atomic.Int64
	lastAuth atomic.Value
}

func newFakeProxy(t *testing.T, upstream string, wantAuth string, refuse func(w io.Writer) bool) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProxy{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c, upstream, wantAuth, refuse)
		}
	}()
	return p
}

func (p *fakeProxy) serve(c net.Conn, upstream, wantAuth string, refuse func(w io.Writer) bool) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect || req.Host != APIHost+":443" {
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	p.connects.Add(1)
	p.lastAuth.Store(req.Header.Get("Proxy-Authorization"))
	if refuse != nil && refuse(c) {
		return
	}
	if wantAuth != "" && req.Header.Get("Proxy-Authorization") != wantAuth {
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp4", upstream)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() { _, _ = io.Copy(up, br); _ = up.Close() }()
	_, _ = io.Copy(c, up)
}

func (p *fakeProxy) url(userinfo string) string {
	if userinfo != "" {
		return "http://" + userinfo + "@" + p.ln.Addr().String()
	}
	return "http://" + p.ln.Addr().String()
}

func TestProxyTierWithBasicAuth(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("nova-pc-1.38:s3cr3t"))
	proxy := newFakeProxy(t, api.addr(), wantAuth, nil)
	logs := &logSink{}
	hooks := &testHooks{roots: pki.roots}
	resp, err := registerForTest(t, APIOptions{Mode: ModeProxy, ProxyURL: proxy.url("nova-pc-1.38:s3cr3t"), Logf: logs.logf, hooks: hooks})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Via != "proxy/android-okhttp" || resp.Proto != "HTTP/1.1" {
		t.Fatalf("via = %q proto = %q", resp.Via, resp.Proto)
	}
	if strings.Contains(logs.joined(), "s3cr3t") {
		t.Fatalf("log leaks the proxy password:\n%s", logs.joined())
	}

	// The chrome proxy profile speaks h2 through the same tunnel.
	hooks.proxyProfiles = []proxyProfile{{label: "chrome", helloID: utls.HelloChrome_Auto}}
	resp, err = registerForTest(t, APIOptions{Mode: ModeProxy, ProxyURL: proxy.url("nova-pc-1.38:s3cr3t"), hooks: hooks})
	if err != nil || resp.Proto != "HTTP/2.0" || resp.Via != "proxy/chrome" {
		t.Fatalf("chrome via proxy: err = %v resp = %+v", err, resp)
	}
}

func TestProxyRefusalEndsTierWithReason(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	proxy := newFakeProxy(t, api.addr(), "", func(w io.Writer) bool {
		_, _ = io.WriteString(w, "HTTP/1.1 407 Proxy Authentication Required\r\nX-Nova-Relay-Reason: outdated-client\r\nContent-Length: 0\r\n\r\n")
		return true
	})
	logs := &logSink{}
	_, err := registerForTest(t, APIOptions{Mode: ModeProxy, ProxyURL: proxy.url("user:hunter2"), Logf: logs.logf, hooks: &testHooks{roots: pki.roots}})
	if !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "reason: outdated-client") {
		t.Fatalf("err = %v", err)
	}
	if n := proxy.connects.Load(); n != 1 {
		t.Fatalf("CONNECTs = %d, want 1 (a refusing proxy is not retried per profile)", n)
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(logs.joined(), "hunter2") {
		t.Fatal("proxy password leaked")
	}
}

func TestAutoFallsBackToProxy(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	proxy := newFakeProxy(t, api.addr(), "", nil)
	hooks := directHooks(pki, closedAddr(t), profileFor("dead", utls.HelloAndroid_11_OkHttp, []int{1, 511}, 512))
	hooks.proxyReserve = 5 * time.Second
	resp, err := registerForTest(t, APIOptions{Mode: ModeAuto, ProxyURL: proxy.url(""), hooks: hooks})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Via != "proxy/android-okhttp" || proxy.connects.Load() != 1 {
		t.Fatalf("via = %q connects = %d", resp.Via, proxy.connects.Load())
	}
}

func TestAutoRateLimitedDirectTriesProxy(t *testing.T) {
	pki := newTestPKI(t)
	direct := newFakeAPI(t, pki, func(int) (int, string) {
		return 429, `{"success":false,"errors":[{"code":1015,"message":"rate limited"}]}`
	})
	upstream := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	proxy := newFakeProxy(t, upstream.addr(), "", nil)
	okhttp := profileFor("first", utls.HelloAndroid_11_OkHttp, []int{1, 511}, 512)
	chrome := profileFor("second", utls.HelloChrome_Auto, []int{1, 680}, 681)
	hooks := directHooks(pki, direct.addr(), okhttp, chrome)
	hooks.proxyReserve = 5 * time.Second
	resp, err := registerForTest(t, APIOptions{Mode: ModeAuto, ProxyURL: proxy.url(""), hooks: hooks})
	if err != nil {
		t.Fatalf("err = %v, want the proxy tier to answer after a direct 429", err)
	}
	if resp.Via != "proxy/android-okhttp" || proxy.connects.Load() != 1 {
		t.Fatalf("via = %q connects = %d", resp.Via, proxy.connects.Load())
	}
	if n := len(direct.requests()); n != 1 {
		t.Fatalf("direct requests = %d, want 1 (429 ends the direct tier)", n)
	}
}

func TestRateLimitIsReportedWhenProxyFailsToo(t *testing.T) {
	pki := newTestPKI(t)
	direct := newFakeAPI(t, pki, func(int) (int, string) { return 429, `{"error":"slow down"}` })
	okhttp := profileFor("first", utls.HelloAndroid_11_OkHttp, []int{1, 511}, 512)
	hooks := directHooks(pki, direct.addr(), okhttp)
	hooks.proxyReserve = 5 * time.Second
	resp, err := registerForTest(t, APIOptions{Mode: ModeAuto, ProxyURL: "http://" + closedAddr(t), hooks: hooks})
	var statusErr *StatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != 429 || resp == nil || resp.StatusCode != 429 {
		t.Fatalf("err = %v resp = %+v, want the direct 429", err, resp)
	}
	if statusErr.Via != "direct/127.0.0.1/first" {
		t.Fatalf("status error via = %q, want the direct answer", statusErr.Via)
	}
}

func TestAutoWithoutProxyStaysDirect(t *testing.T) {
	pki := newTestPKI(t)
	hooks := directHooks(pki, closedAddr(t), profileFor("dead", utls.HelloAndroid_11_OkHttp, []int{1, 511}, 512))
	_, err := registerForTest(t, APIOptions{Mode: ModeAuto, hooks: hooks})
	if !errors.Is(err, ErrUnreachable) || strings.Contains(err.Error(), "proxy") {
		t.Fatalf("err = %v", err)
	}
}

func TestProxyOptionsValidation(t *testing.T) {
	ctx := context.Background()
	if _, err := DoAPIRequest(ctx, APIRequest{}, APIOptions{Mode: ModeProxy}); !errors.Is(err, ErrUsage) {
		t.Fatalf("proxy mode without URL: %v", err)
	}
	for _, bad := range []string{"socks5://127.0.0.1:1080", "http://", "http://user:pa ss@[::1"} {
		_, err := DoAPIRequest(ctx, APIRequest{}, APIOptions{Mode: ModeProxy, ProxyURL: bad})
		if !errors.Is(err, ErrUsage) {
			t.Errorf("%q: err = %v", bad, err)
		}
		if err != nil && strings.Contains(err.Error(), "pa ss") {
			t.Errorf("error echoes credentials: %v", err)
		}
	}
	p, err := parseProxyURL("127.0.0.1:1371")
	if err != nil || p.String() != "http://127.0.0.1:1371" || p.hasAuth {
		t.Fatalf("bare host:port: %+v %v", p, err)
	}
	p, err = parseProxyURL("https://nova-pc-1.38:pw@relay.example:8443")
	if err != nil || p.String() != "https://relay.example:8443" || !p.hasAuth || p.password != "pw" {
		t.Fatalf("https relay: %+v %v", p, err)
	}
	p, err = parseProxyURL("https://relay.example")
	if err != nil || p.port != "443" {
		t.Fatalf("default https port: %+v %v", p, err)
	}
}

func TestHTTPSProxy(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	plain := newFakeProxy(t, api.addr(), "", nil)
	// TLS in front of the plain proxy, certificate valid for 127.0.0.1.
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pki.leaf}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				up, err := net.Dial("tcp4", plain.ln.Addr().String())
				if err != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	resp, err := registerForTest(t, APIOptions{
		Mode: ModeProxy, ProxyURL: "https://" + ln.Addr().String(),
		hooks: &testHooks{roots: pki.roots, proxyRoots: pki.roots},
	})
	if err != nil || resp.Via != "proxy/android-okhttp" {
		t.Fatalf("err = %v resp = %+v", err, resp)
	}
}

func TestPlainMode(t *testing.T) {
	pki := newTestPKI(t)
	api := newFakeAPI(t, pki, func(int) (int, string) { return 200, okDevice })
	hooks := &testHooks{roots: pki.roots, directAddr: func(netip.Addr) string { return api.addr() }}
	resp, err := registerForTest(t, APIOptions{Mode: ModePlain, hooks: hooks})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Via != "plain" || resp.StatusCode != 200 {
		t.Fatalf("resp = %+v", resp)
	}
	if seen := api.requests(); len(seen) != 1 || seen[0].clientVersion != ClientVersion || seen[0].userAgent != UserAgent {
		t.Fatalf("seen = %+v", seen)
	}
}

func TestResultWithoutAnyAttemptIsUnreachable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pki := newTestPKI(t)
	hooks := directHooks(pki, closedAddr(t), profileFor("x", utls.HelloAndroid_11_OkHttp, []int{1, 511}, 512))
	_, err := DoAPIRequest(ctx, APIRequest{}, APIOptions{Mode: ModeDirect, hooks: hooks})
	if !errors.Is(err, ErrUnreachable) || !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("err = %v", err)
	}
}
