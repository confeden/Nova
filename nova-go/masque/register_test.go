package masque

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	usquemodels "github.com/Diniboy1123/usque/models"
)

// fakeAPI is a TLS server that answers the device calls of api.cloudflareclient.com with one record.
type fakeAPI struct {
	srv   *httptest.Server
	roots *x509.CertPool
	peer  string

	mu             sync.Mutex
	key            string // "key" of the device record
	omitKeyOnPatch bool   // the PATCH answer carries no key, only the GET does
	requests       []string
}

func newFakeAPI(t *testing.T, recordKey, peerPEM string) *fakeAPI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nova test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: apiHost}, DNSNames: []string{apiHost},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAPI{key: recordKey, peer: peerPEM, roots: x509.NewCertPool()}
	f.roots.AddCert(caCert)
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) addr() string { return f.srv.Listener.Addr().String() }

func (f *fakeAPI) setKey(key string) {
	f.mu.Lock()
	f.key = key
	f.mu.Unlock()
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	key := f.key
	if r.Method == http.MethodPatch && f.omitKeyOnPatch {
		key = ""
	}
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer secret-token-value" || !strings.HasPrefix(r.URL.Path, apiRegPath+"/") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var rec usquemodels.AccountData
	rec.ID = strings.TrimPrefix(r.URL.Path, apiRegPath+"/")
	rec.Key, rec.KeyType, rec.TunType, rec.WarpEnabled = key, "secp256r1", "masque", true
	rec.Account.AccountType = "free"
	rec.Config.Interface.Addresses.V4 = "172.16.0.2"
	rec.Config.Interface.Addresses.V6 = "2606:4700:110:8a36::2"
	var peer usquemodels.Peer
	peer.PublicKey = f.peer
	peer.Endpoint.V4 = "162.159.198.2:0"
	peer.Endpoint.Ports = []int{443}
	rec.Config.Peers = []usquemodels.Peer{peer}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}

// useFakeAPI makes every API client of the next CLI runs trust the fake and send plain requests to it.
func useFakeAPI(t *testing.T, f *fakeAPI) {
	t.Helper()
	apiClientHook = func(c *APIClient) {
		c.rootCAs = f.roots
		c.dialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, f.addr())
		}
	}
	t.Cleanup(func() { apiClientHook = nil })
}

// connectProxy is a Basic-auth CONNECT proxy that tunnels every request to one target, or refuses
// with 407 and the Nova relay headers.
type connectProxy struct {
	addr, target, auth string

	mu       sync.Mutex
	reason   string // non-empty: answer 407 with this X-Nova-Relay-Reason
	current  string
	connects []string
}

func newConnectProxy(t *testing.T, target, user, pass string) *connectProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	p := &connectProxy{addr: l.Addr().String(), target: target,
		auth: "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go p.handle(c)
		}
	}()
	return p
}

func (p *connectProxy) refuse(reason, current string) {
	p.mu.Lock()
	p.reason, p.current = reason, current
	p.mu.Unlock()
}

func (p *connectProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.connects...)
}

func (p *connectProxy) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	authorized := req.Method == http.MethodConnect && req.Header.Get("Proxy-Authorization") == p.auth
	p.mu.Lock()
	p.connects = append(p.connects, fmt.Sprintf("%s %s auth=%t", req.Method, req.Host, authorized))
	reason, current := p.reason, p.current
	p.mu.Unlock()
	if !authorized || reason != "" {
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nX-Nova-Relay-Reason: "+reason+
			"\r\nX-Nova-Relay-Current: "+current+"\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", p.target)
	if err != nil {
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() {
		_, _ = io.Copy(up, br)
		_ = up.(*net.TCPConn).CloseWrite()
	}()
	_, _ = io.Copy(c, up)
}

func lastEvent(t *testing.T, evs []map[string]any) map[string]any {
	t.Helper()
	if len(evs) == 0 {
		t.Fatal("no events")
	}
	return evs[len(evs)-1]
}

// GM-7: `enroll --activate-only` must not report success for a device whose key a later enroll
// replaced; the profile stays untouched and the exit tells Nova to run a full enroll.
func TestEnrollActivateOnlyRefusesASupersededKey(t *testing.T) {
	path, id := writeTestProfile(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPub, _ := GenerateKeyPair()
	api := newFakeAPI(t, base64.StdEncoding.EncodeToString(otherPub), id.EndpointPubKey)
	useFakeAPI(t, api)

	code, evs, stderr := runCLI(t, "enroll", "--config", path, "--activate-only", "--api-mode", "plain")
	if last := lastEvent(t, evs); code != ExitAccessDenied || last["ev"] != "exit" || last["class"] != classKeySuperseded {
		t.Fatalf("superseded key: code=%d last=%v stderr=%s", code, last, stderr)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("the profile was rewritten with a key the server no longer holds")
	}

	// A PATCH answer without the key: the GET record decides.
	api.mu.Lock()
	api.omitKeyOnPatch = true
	api.mu.Unlock()
	if code, evs, _ := runCLI(t, "enroll", "--config", path, "--activate-only", "--api-mode", "plain"); code != ExitAccessDenied {
		t.Fatalf("superseded key seen only in GET: code=%d events=%v", code, evs)
	}
	if !reflect.DeepEqual(api.requests[len(api.requests)-2:], []string{"PATCH " + apiRegPath + "/" + id.DeviceID, "GET " + apiRegPath + "/" + id.DeviceID}) {
		t.Fatalf("requests = %v", api.requests)
	}

	// The server holds the profile key: activation succeeds and the profile is written.
	own, _ := PublicKeyB64FromPrivate(id.PrivateKey)
	api.setKey(own)
	code, evs, stderr = runCLI(t, "enroll", "--config", path, "--activate-only", "--api-mode", "plain")
	if last := lastEvent(t, evs); code != ExitOK || last["ev"] != "enrolled" || last["mode"] != "activate-only" {
		t.Fatalf("matching key: code=%d last=%v stderr=%s", code, last, stderr)
	}
	back, _, err := LoadIdentityFile(path)
	if err != nil || back.PrivateKey != id.PrivateKey {
		t.Fatalf("profile after activation: %v", err)
	}
}

func TestSameMasqueKeyForms(t *testing.T) {
	privDER, pubDER, _ := GenerateKeyPair()
	priv := base64.StdEncoding.EncodeToString(privDER)
	key, _ := x509.ParseECPrivateKey(privDER)
	point, _ := key.PublicKey.ECDH()
	_, otherDER, _ := GenerateKeyPair()
	cases := []struct {
		name, serverKey, keyType string
		same, known              bool
	}{
		{"base64 pkix", base64.StdEncoding.EncodeToString(pubDER), "secp256r1", true, true},
		{"pem", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})), "", true, true},
		{"raw point", base64.StdEncoding.EncodeToString(point.Bytes()), "secp256r1", true, true},
		{"other key", base64.StdEncoding.EncodeToString(otherDER), "secp256r1", false, true},
		{"wireguard key", base64.StdEncoding.EncodeToString(make([]byte, 32)), "curve25519", false, true},
		{"absent", "", "", false, false},
		{"garbage", "not base64 at all", "", false, false},
	}
	for _, c := range cases {
		if same, known := sameMasqueKey(c.serverKey, c.keyType, priv); same != c.same || known != c.known {
			t.Errorf("%s: same=%t known=%t, want %t %t", c.name, same, known, c.same, c.known)
		}
	}
}

// GM-5: relay URLs with credentials reach the helper through NOVA_API_PROXY, never argv; a relay that
// retired this version's login is reported as such, and the password never appears in the output.
func TestEnrollTakesRelayProxiesFromTheEnvironment(t *testing.T) {
	const secret = "relay-s3cret-value"
	path, id := writeTestProfile(t)
	own, _ := PublicKeyB64FromPrivate(id.PrivateKey)
	api := newFakeAPI(t, own, id.EndpointPubKey)
	useFakeAPI(t, api)
	relay := newConnectProxy(t, api.addr(), "nova-pc-1.39", secret)
	t.Setenv(apiProxyEnv, "  http://nova-pc-1.39:"+secret+"@"+relay.addr+"\n")

	leaks := func(evs []map[string]any, stderr string) bool {
		line, _ := json.Marshal(evs)
		return strings.Contains(string(line), secret) || strings.Contains(stderr, secret)
	}
	code, evs, stderr := runCLI(t, "enroll", "--config", path, "--activate-only", "--api-mode", "proxy")
	last := lastEvent(t, evs)
	if code != ExitOK || last["ev"] != "enrolled" || last["api_via"] != "proxy http://"+relay.addr {
		t.Fatalf("enroll through the env relay: code=%d last=%v stderr=%s", code, last, stderr)
	}
	if _, ok := last["relay_outdated"]; ok {
		t.Fatalf("relay_outdated on a working relay: %v", last)
	}
	if seen := relay.seen(); len(seen) == 0 || seen[0] != "CONNECT "+apiHost+":443 auth=true" {
		t.Fatalf("relay saw %v", seen)
	}
	if leaks(evs, stderr) {
		t.Fatal("the relay password leaked into the output")
	}

	relay.refuse("outdated-client", "1.40")
	code, evs, stderr = runCLI(t, "enroll", "--config", path, "--activate-only", "--api-mode", "proxy")
	last = lastEvent(t, evs)
	if code != ExitAPIUnreachable || last["ev"] != "exit" || last["relay_outdated"] != true || last["relay_current"] != "1.40" ||
		!strings.Contains(fmt.Sprint(last["err"]), "outdated-client") {
		t.Fatalf("outdated relay: code=%d last=%v stderr=%s", code, last, stderr)
	}
	if leaks(evs, stderr) {
		t.Fatal("the relay password leaked into the output")
	}
}

func TestAPIProxyListAndProxyRoutes(t *testing.T) {
	got := apiProxyList(" http://127.0.0.1:1371 ", "https://u:p%2C1@relay.example:8443\n https://u:p@relay.example:2053;https://u:p@relay.example:2053")
	want := []string{"http://127.0.0.1:1371", "https://u:p%2C1@relay.example:8443", "https://u:p@relay.example:2053", "https://u:p@relay.example:2053"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("apiProxyList = %v", got)
	}
	log := NewLogger(io.Discard, false)
	c, err := newAPIClient(APIModeProxy, got, log)
	if err != nil {
		t.Fatal(err)
	}
	routes := c.routes(t.Context())
	var labels []string
	for _, r := range routes {
		labels = append(labels, r.label())
	}
	if !reflect.DeepEqual(labels, []string{"proxy http://127.0.0.1:1371", "proxy https://relay.example:8443", "proxy https://relay.example:2053"}) {
		t.Fatalf("proxy routes = %v", labels)
	}
	// A non-200 through one proxy must not skip the next: each proxy is its own group.
	if routes[0].group() == routes[1].group() {
		t.Fatal("two proxies share a route group")
	}
	if d := (apiRoute{kind: "direct", ip: apiPinnedIPs[0], profile: apiProfiles()[0]}); d.group() != (apiRoute{kind: "direct", ip: apiPinnedIPs[1]}).group() {
		t.Fatal("direct routes must share one group")
	}
	if _, err := newAPIClient(APIModeAuto, []string{"ftp://user:hunter2@host:21"}, log); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("bad proxy URL: %v", err)
	}
	t.Setenv(apiProxyEnv, "")
	if code, _, _ := runCLI(t, "enroll", "--config", "x.json", "--api-mode", "proxy"); code != ExitUsage {
		t.Fatalf("proxy mode with neither --api-proxy nor %s: code=%d", apiProxyEnv, code)
	}
}

// A proxy that is down or refuses the login is skipped by later calls of the same auto-mode run.
func TestAutoModeSkipsADeadProxyForTheRestOfTheRun(t *testing.T) {
	log := NewLogger(io.Discard, false)
	dead := freeLoopbackAddr(t)
	c, err := newAPIClient(APIModeAuto, []string{"http://" + dead}, log)
	if err != nil {
		t.Fatal(err)
	}
	if r := c.routes(t.Context()); r[0].kind != "direct" {
		t.Fatalf("unreachable proxy offered: %s", r[0].label())
	}
	if !c.proxyDown[c.proxies[0]] {
		t.Fatal("unreachable proxy not remembered")
	}

	api := newFakeAPI(t, "", "peer")
	relay := newConnectProxy(t, api.addr(), "nova-pc-1.30", "old")
	relay.refuse("outdated-client", "1.40")
	c2, _ := newAPIClient(APIModeAuto, []string{"http://nova-pc-1.30:old@" + relay.addr}, log)
	c2.rootCAs = api.roots
	if r := c2.routes(t.Context()); r[0].kind != "proxy" {
		t.Fatalf("reachable relay not offered first: %s", r[0].label())
	}
	if _, err := c2.doHTTPClient(t.Context(), apiRequest{label: "device", method: http.MethodGet, path: apiRegPath + "/x"},
		c2.proxies[0], "proxy"); err == nil || !strings.Contains(err.Error(), "outdated-client") {
		t.Fatalf("407 through the relay: %v", err)
	}
	if outdated, current := c2.relayState(); !outdated || current != "1.40" {
		t.Fatalf("relay state = %t %q", outdated, current)
	}
	if r := c2.routes(t.Context()); r[0].kind != "direct" {
		t.Fatalf("relay that refused the login offered again: %s", r[0].label())
	}
}
