package masque

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"nova-pc/nova-go/internal/events"
)

func runCLI(t *testing.T, args ...string) (int, []map[string]any, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	env := &cliEnv{stdout: &out, stderr: &errOut, version: "test"}
	code := env.main(args)
	var evs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		prefix, obj, ok := strings.Cut(line, " ")
		if !ok || prefix != EventPrefix {
			t.Fatalf("stdout carries a non-event line: %q", line)
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(obj), &ev); err != nil {
			t.Fatalf("event is not JSON: %q", line)
		}
		if ev["v"] != float64(1) {
			t.Fatalf("event without v:1: %q", line)
		}
		evs = append(evs, ev)
	}
	return code, evs, errOut.String()
}

func writeTestProfile(t *testing.T) (string, Identity) {
	t.Helper()
	priv, peer := testKeys(t)
	id := Identity{PrivateKey: priv, EndpointV4: "162.159.198.2", EndpointPubKey: peer, IPv4: "172.16.0.2",
		IPv6: "2606:4700:110:8a36::2", AccessToken: "secret-token-value", DeviceID: "89f65481-aaaa-bbbb", IssuedAt: 1789273257}
	id.normalize()
	doc, err := MarshalDocument(id, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "Cloudflare MASQUE 1.json")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, id
}

func TestCheckPrintsSecretsFreeSummary(t *testing.T) {
	path, id := writeTestProfile(t)
	code, evs, stderr := runCLI(t, "check", "--config", path)
	if code != ExitOK || len(evs) != 1 {
		t.Fatalf("check: code=%d events=%v stderr=%s", code, evs, stderr)
	}
	ev := evs[0]
	if ev["ev"] != "check" || ev["ok"] != true || ev["device_id_prefix"] != "89f65481" || ev["has_ipv6"] != true {
		t.Fatalf("check event = %v", ev)
	}
	line, _ := json.Marshal(ev)
	for _, secret := range []string{id.PrivateKey, id.AccessToken, id.DeviceID} {
		if strings.Contains(string(line), secret) || strings.Contains(stderr, secret) {
			t.Fatal("check leaked a secret")
		}
	}

	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"private_key":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, evs, _ = runCLI(t, "check", "--config", bad)
	if code != ExitConfig || evs[0]["ok"] != false {
		t.Fatalf("invalid profile: code=%d events=%v", code, evs)
	}
}

func TestSocksRefusesCloudflareSNIAndLAN(t *testing.T) {
	path, _ := writeTestProfile(t)
	code, evs, _ := runCLI(t, "socks", "--config", path, "--bind", "127.0.0.1:14899", "--sni", "zt-masque.cloudflareclient.com")
	if code != ExitUsage {
		t.Fatalf("cloudflareclient SNI: code=%d, want 2", code)
	}
	if last := evs[len(evs)-1]; last["ev"] != "exit" || last["code"] != float64(ExitUsage) {
		t.Fatalf("last event = %v", last)
	}
	if code, _, _ := runCLI(t, "socks", "--config", path, "--bind", "0.0.0.0:14899"); code != ExitUsage {
		t.Fatalf("non-loopback bind: code=%d, want 2", code)
	}
	if code, _, _ := runCLI(t, "socks", "--config", path, "--transport", "h4"); code != ExitUsage {
		t.Fatalf("bad transport: code=%d, want 2", code)
	}
	if code, _, _ := runCLI(t, "socks", "--bogus-flag"); code != ExitUsage {
		t.Fatalf("unknown flag: code=%d, want 2", code)
	}
	if code, _, _ := runCLI(t, "socks", "-h"); code != ExitOK {
		t.Fatalf("-h: code=%d, want 0", code)
	}
}

func TestSocksConfigAndBindFailures(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	code, evs, _ := runCLI(t, "socks", "--config", missing, "--bind", "127.0.0.1:14899")
	if code != ExitConfig || evs[len(evs)-1]["class"] != ClassConfig {
		t.Fatalf("missing profile: code=%d events=%v", code, evs)
	}

	// A busy SOCKS port fails before any dial (ephemeral port, never Nova's 1369-1396).
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	path, _ := writeTestProfile(t)
	ready := filepath.Join(t.TempDir(), "ready.json")
	if err := os.WriteFile(ready, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, evs, _ = runCLI(t, "socks", "--config", path, "--bind", busy.Addr().String(), "--ready-file", ready)
	if code != ExitBind {
		t.Fatalf("busy port: code=%d, want 4 (events %v)", code, evs)
	}
	names := []string{}
	for _, ev := range evs {
		names = append(names, ev["ev"].(string))
	}
	if !reflect.DeepEqual(names, []string{"start", "fail", "exit"}) {
		t.Fatalf("events = %v", names)
	}
	if _, err := os.Stat(ready); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a stale ready file survived the start")
	}
}

func TestRegisterUsageChecksNeedNoNetwork(t *testing.T) {
	t.Setenv(apiProxyEnv, "") // an inherited relay list would satisfy --api-mode proxy
	out := filepath.Join(t.TempDir(), "p.json")
	if code, evs, _ := runCLI(t, "register", "--out", out); code != ExitUsage || evs[0]["class"] != "usage" {
		t.Fatalf("missing --accept-tos: code=%d events=%v", code, evs)
	}
	if code, _, _ := runCLI(t, "register", "--accept-tos"); code != ExitUsage {
		t.Fatalf("missing --out: code=%d", code)
	}
	if code, _, _ := runCLI(t, "register", "--out", out, "--accept-tos", "--api-mode", "proxy"); code != ExitUsage {
		t.Fatalf("proxy mode without proxy: code=%d", code)
	}
	if err := os.WriteFile(out, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "register", "--out", out, "--accept-tos"); code != ExitUsage {
		t.Fatalf("existing profile without --force: code=%d", code)
	}
	// A held lock is exit 23, before any network call.
	lock, err := lockProfile(out)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	if code, evs, _ := runCLI(t, "register", "--out", out, "--accept-tos", "--force"); code != ExitLocked || evs[0]["class"] != "locked" {
		t.Fatalf("locked profile: code=%d events=%v", code, evs)
	}
	if code, _, _ := runCLI(t, "enroll", "--config", out); code != ExitLocked {
		t.Fatalf("enroll on a locked profile: code=%d", code)
	}
}

func TestUnknownCommandAndPanicSafety(t *testing.T) {
	if code, _, _ := runCLI(t, "teleport"); code != ExitUsage {
		t.Fatalf("unknown command: code=%d", code)
	}
	if code, _, _ := runCLI(t); code != ExitUsage {
		t.Fatalf("no command: code=%d", code)
	}
}

func TestReadyEventFieldOrderMatchesSpec(t *testing.T) {
	var out bytes.Buffer
	em := events.New(EventPrefix, &out)
	rt := &socksRuntime{o: socksOptions{bind: "127.0.0.1:1370", info: "127.0.0.1:1397"}, em: em, log: NewLogger(io.Discard, false), hasV4: true,
		id: Identity{IPv4: "172.16.0.2"}}
	s := newSession(dialSpec{endpoint: netip.MustParseAddrPort("162.159.198.2:8443"), transport: "h3", sni: "www.google.com"}, nil)
	s.handshakeMs, s.settingsMs, s.connectIPMs, s.probeKind, s.probeRx = 412, 35, 37, "dns", 389
	rt.attemptN.Store(3)
	if err := rt.markReady(s, false); err != nil {
		t.Fatal(err)
	}
	want := `NOVA_MASQUE {"v":1,"ev":"ready","socks":"127.0.0.1:1370","info":"127.0.0.1:1397","transport":"h3","endpoint":"162.159.198.2:8443","sni":"www.google.com","attempt":3,"connect_ms":412,"settings_ms":35,"connectip_ms":37,"probe":"dns","probe_rx":389,"tunnel_ipv4":"172.16.0.2","reconnect":false}` + "\n"
	if out.String() != want {
		t.Fatalf("ready line:\n got %s\nwant %s", out.String(), want)
	}
	if !rt.serving.Load() || rt.status().State != "ready" {
		t.Fatal("markReady did not publish the session")
	}

	out.Reset()
	emitExit(em, ExitZeroRx, ClassZeroRx, 16, nil)
	if got := out.String(); got != `NOVA_MASQUE {"v":1,"ev":"exit","code":13,"class":"zero_rx","attempts":16}`+"\n" {
		t.Fatalf("exit line: %s", got)
	}
}

func TestMatrixOrderAndFlagParsing(t *testing.T) {
	a := netip.MustParseAddr("162.159.198.2")
	b := netip.MustParseAddr("162.159.198.1")
	m := buildMatrix([]endpointTarget{{addr: a}, {addr: b, port: 8443}}, []int{443, 8443}, TransportAuto)
	var got []string
	for _, s := range m {
		got = append(got, s.transport+"@"+s.endpoint.String())
	}
	want := []string{"h2@162.159.198.2:443", "h3@162.159.198.2:443", "h3@162.159.198.2:8443", "h3@162.159.198.1:8443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("auto matrix = %v, want %v", got, want)
	}
	if tr := transportsFor(TransportH3First, 443); !reflect.DeepEqual(tr, []string{"h3", "h2"}) {
		t.Fatalf("h3first on 443 = %v", tr)
	}
	if tr := transportsFor(TransportH3, 443); !reflect.DeepEqual(tr, []string{"h3"}) {
		t.Fatalf("h3 on 443 = %v", tr)
	}
	eps, err := parseEndpoints([]string{"162.159.198.2", "162.159.198.1:500", "[2606:4700:103::1]:443"})
	if err != nil || len(eps) != 3 || eps[1].port != 500 || !eps[2].addr.Is6() {
		t.Fatalf("parseEndpoints = %v %v", eps, err)
	}
	if _, err := parseEndpoints([]string{"engage.cloudflareclient.com:2408"}); err == nil {
		t.Fatal("hostname endpoint accepted")
	}
	if p, err := parsePorts("443, 8443,500"); err != nil || !reflect.DeepEqual(p, []int{443, 8443, 500}) {
		t.Fatalf("parsePorts = %v %v", p, err)
	}
	if _, err := parsePorts("443,99999"); err == nil {
		t.Fatal("bad port accepted")
	}
	if err := checkListenAddr("--bind", "[::1]:1080", false, false); err != nil {
		t.Fatalf("IPv6 loopback refused: %v", err)
	}
	if err := checkListenAddr("--bind", "192.168.1.5:1080", true, false); err != nil {
		t.Fatalf("--allow-lan ignored: %v", err)
	}
}

func matrixLabels(m []dialSpec) []string {
	var out []string
	for _, s := range m {
		out = append(out, s.transport+"@"+s.endpoint.String())
	}
	return out
}

// Lead request / GM-4: H2 goes only to the enrolled endpoint_v4/endpoint_v6. H2/TCP on the sibling
// 162.159.198.1:443 presents another endpoint key (measured), and extra candidates are unproven;
// H3 still walks every candidate.
func TestProfileMatrixOffersH2OnlyOnEnrolledEndpoints(t *testing.T) {
	priv, peer := testKeys(t)
	raw, _ := json.Marshal(map[string]any{"private_key": priv, "endpoint_pub_key": peer, "ipv4": "172.16.0.2",
		"endpoint_v4": "162.159.198.2", "endpoint_v4_candidates": []string{"162.159.198.2", "10.0.0.1"},
		"endpoint_v6": "2606:4700:103::2"})
	id, err := ParseIdentity(raw)
	if err != nil {
		t.Fatal(err)
	}
	ports := []int{443, 8443}
	got := matrixLabels(buildMatrix(profileTargets(id, true), ports, TransportAuto))
	want := []string{
		"h2@162.159.198.2:443", "h3@162.159.198.2:443", "h3@162.159.198.2:8443",
		"h3@10.0.0.1:443", "h3@10.0.0.1:8443",
		"h3@162.159.198.1:443", "h3@162.159.198.1:8443",
		"h2@[2606:4700:103::2]:443", "h3@[2606:4700:103::2]:443", "h3@[2606:4700:103::2]:8443",
		"h3@[2606:4700:103::1]:443", "h3@[2606:4700:103::1]:8443",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("auto matrix:\n got %v\nwant %v", got, want)
	}
	if got := matrixLabels(buildMatrix(profileTargets(id, false), []int{443}, TransportH3First)); !reflect.DeepEqual(got,
		[]string{"h3@162.159.198.2:443", "h2@162.159.198.2:443", "h3@10.0.0.1:443", "h3@162.159.198.1:443"}) {
		t.Fatalf("h3first matrix = %v", got)
	}
	if got := matrixLabels(buildMatrix(profileTargets(id, false), ports, TransportH2)); !reflect.DeepEqual(got,
		[]string{"h2@162.159.198.2:443", "h2@162.159.198.2:8443"}) {
		t.Fatalf("h2 matrix = %v", got)
	}
	// The enrolled endpoint decides, not the address: a profile enrolled on .1 keeps H2 there.
	raw1, _ := json.Marshal(map[string]any{"private_key": priv, "endpoint_pub_key": peer, "ipv4": "172.16.0.2",
		"endpoint_v4": "162.159.198.1"})
	id1, err := ParseIdentity(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if got := matrixLabels(buildMatrix(profileTargets(id1, false), []int{443}, TransportAuto)); !reflect.DeepEqual(got,
		[]string{"h2@162.159.198.1:443", "h3@162.159.198.1:443", "h3@162.159.198.2:443"}) {
		t.Fatalf("matrix of a profile enrolled on .1 = %v", got)
	}
	// Explicit --endpoint values are the caller's choice and keep every transport.
	eps, _ := parseEndpoints([]string{"162.159.198.1:443"})
	if got := matrixLabels(buildMatrix(eps, ports, TransportAuto)); !reflect.DeepEqual(got, []string{"h2@162.159.198.1:443", "h3@162.159.198.1:443"}) {
		t.Fatalf("explicit endpoint matrix = %v", got)
	}
}

// The same rule seen from the running helper: with --transport h2 an extra candidate is never dialled.
func TestSocksDialsH2OnlyOnTheEnrolledEndpoint(t *testing.T) {
	priv, peer := testKeys(t)
	closed := freeLoopbackAddr(t) // nothing listens: every dial is refused
	_, port, _ := net.SplitHostPort(closed)
	raw, _ := json.Marshal(map[string]any{"private_key": priv, "endpoint_pub_key": peer, "ipv4": "172.16.0.2",
		"endpoint_v4": "127.0.0.1", "endpoint_v4_candidates": []string{"127.0.0.2"}})
	profile := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(profile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	code, evs, _ := runCLI(t, "socks", "--config", profile, "--bind", freeLoopbackAddr(t), "--transport", "h2",
		"--ports", port, "--max-attempts", "2", "--attempt-timeout", "3s", "--sni", "www.google.com")
	if code != ExitNoResponse {
		t.Fatalf("code = %d, want 10 (events %v)", code, evs)
	}
	var dialled []string
	for _, ev := range evs {
		if ev["ev"] == "attempt" {
			dialled = append(dialled, ev["endpoint"].(string))
		}
	}
	if want := []string{"127.0.0.1:" + port, "127.0.0.1:" + port}; !reflect.DeepEqual(dialled, want) {
		t.Fatalf("H2 attempts went to %v, want only the enrolled endpoint %v", dialled, want)
	}
}

func TestPickAddressPrefersTunnelFamily(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("2606:4700::6810:84e5"), netip.MustParseAddr("104.16.132.229")}
	if ip := pickAddress(addrs, true, true); ip.String() != "104.16.132.229" {
		t.Fatalf("v4 not preferred: %v", ip)
	}
	if ip := pickAddress(addrs, false, true); ip.String() != "2606:4700::6810:84e5" {
		t.Fatalf("v6-only tunnel got %v", ip)
	}
	if ip := pickAddress(addrs[:1], true, false); ip != nil {
		t.Fatalf("v4-only tunnel got an AAAA: %v", ip)
	}
}

func TestLockPendingAndAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "p.json")
	l1, err := lockProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockProfile(profile); !errors.Is(err, errLocked) {
		t.Fatalf("second lock: %v, want errLocked", err)
	}
	l1.Unlock()
	l2, err := lockProfile(profile)
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	l2.Unlock()

	if err := writeFileAtomic(profile, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(profile, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(profile); string(data) != "two" {
		t.Fatalf("atomic replace wrote %q", data)
	}
	if _, err := os.Stat(profile + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary file left behind")
	}

	priv, _, _ := GenerateKeyPair()
	pending := pendingKey{PrivateKey: base64.StdEncoding.EncodeToString(priv), DeviceID: "dev", AccessToken: "tok", IssuedAt: 7}
	pp := profile + ".pending"
	if p, err := readPending(pp); p != nil || err != nil {
		t.Fatalf("absent pending: %v %v", p, err)
	}
	if err := writePending(pp, pending); err != nil {
		t.Fatal(err)
	}
	back, err := readPending(pp)
	if err != nil || back == nil || *back != pending {
		t.Fatalf("pending round trip: %+v %v", back, err)
	}
	if err := os.WriteFile(pp, []byte(`{"private_key":"AAAA","device_id":"d","access_token":"t"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPending(pp); err == nil {
		t.Fatal("pending with a broken key accepted")
	}
	setAsidePending(pp, NewLogger(io.Discard, false))
	if _, err := os.Stat(pp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending not set aside")
	}
	matches, _ := filepath.Glob(pp + ".*.bak")
	if len(matches) != 1 {
		t.Fatalf("set-aside copy missing: %v", matches)
	}
}

func TestLoggerRedactsSecrets(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.now = func() time.Time { return time.Date(2026, 9, 13, 10, 0, 0, 123e6, time.UTC) }
	l.Info("device record", "access_token", "abcdef", "license", "LIC-1", "note", "two words", "multi", "a\nb")
	l.Debug("hidden")
	want := `2026-09-13T10:00:00.123Z INF masque: device record access_token="<6 chars>" license="<5 chars>" note="two words" multi=a\nb` + "\n"
	if buf.String() != want {
		t.Fatalf("log line:\n got %q\nwant %q", buf.String(), want)
	}
}

func TestParentWatchStopsOnGoneParent(t *testing.T) {
	env := &cliEnv{stdout: io.Discard, stderr: io.Discard}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	// Process ids on Windows are multiples of 4; an odd id is never a live process.
	code, stop := env.startStopWatch(ctx, cancel, 0x7FFFFFF1, NewLogger(io.Discard, false))
	if !stop || code != ExitOK {
		t.Fatalf("gone parent: code=%d stop=%v", code, stop)
	}
}
