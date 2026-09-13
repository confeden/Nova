package masque

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newEchoCONNECTServer answers CONNECT and sends every IPv4 packet back with source and destination
// swapped. For the data-plane probe that is indistinguishable from a resolver answering: an inbound
// packet arrives at the tunnel address through the netstack.
func newEchoCONNECTServer(t *testing.T, serverKey *ecdsa.PrivateKey) *httptest.Server {
	return newSlowEchoCONNECTServer(t, serverKey, 0, 0)
}

// newSlowEchoCONNECTServer is newEchoCONNECTServer on a slow path: the CONNECT answer comes after
// answerDelay and every echoed packet after rtt.
func newSlowEchoCONNECTServer(t *testing.T, serverKey *ecdsa.PrivateKey, answerDelay, rtt time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get("Cf-Connect-Proto") != "cf-connect-ip" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if answerDelay > 0 {
			select {
			case <-time.After(answerDelay):
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			typ, payload, err := readCapsule(r.Body)
			if err != nil {
				return
			}
			if typ != 0 || len(payload) < 20 || payload[0]>>4 != 4 {
				continue
			}
			if rtt > 0 {
				time.Sleep(rtt)
			}
			var src [4]byte
			copy(src[:], payload[12:16])
			copy(payload[12:16], payload[16:20])
			copy(payload[16:20], src[:])
			payload[8] = 64
			binary.BigEndian.PutUint16(payload[10:12], ipv4Checksum(payload[:20]))
			if _, err := w.Write(appendCapsule(nil, 0, payload)); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{selfSigned(t, serverKey)}, PrivateKey: serverKey}},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// eventPipe turns the helper's stdout into a channel of decoded events.
func eventPipe(t *testing.T) (io.Writer, <-chan map[string]any) {
	pr, pw := io.Pipe()
	ch := make(chan map[string]any, 64)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			_, obj, ok := strings.Cut(sc.Text(), " ")
			if !ok {
				continue
			}
			var ev map[string]any
			if json.Unmarshal([]byte(obj), &ev) == nil {
				ch <- ev
			}
		}
	}()
	t.Cleanup(func() { _ = pw.Close() })
	return pw, ch
}

func waitEvent(t *testing.T, ch <-chan map[string]any, name string, match func(map[string]any) bool) map[string]any {
	t.Helper()
	timeout := time.After(20 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("event stream ended while waiting for %q", name)
			}
			if ev["ev"] == name && (match == nil || match(ev)) {
				return ev
			}
		case <-timeout:
			t.Fatalf("timed out waiting for event %q", name)
		}
	}
}

func TestSocksRuntimeReadyReconnectAndExit(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("uses ping.exe as a watched parent process")
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := newEchoCONNECTServer(t, serverKey)

	profile := writeLoopbackProfile(t, serverKey)
	ready := filepath.Join(filepath.Dir(profile), "ready.json")
	socksAddr := freeLoopbackAddr(t)

	parent := exec.Command("ping.exe", "-n", "120", "127.0.0.1")
	if err := parent.Start(); err != nil {
		t.Skipf("cannot start a parent stand-in: %v", err)
	}
	t.Cleanup(func() { _ = parent.Process.Kill(); _, _ = parent.Process.Wait() })

	stdout, evs := eventPipe(t)
	env := &cliEnv{stdout: stdout, stderr: io.Discard, version: "test"}
	exitCode := make(chan int, 1)
	go func() {
		exitCode <- env.main([]string{"socks", "--config", profile, "--bind", socksAddr, "--ready-file", ready,
			"--endpoint", srv.Listener.Addr().String(), "--transport", "h2", "--sni", "www.google.com",
			"--reconnect-delay", "100ms", "--reconnect-budget", "2", "--attempt-timeout", "3s", "--max-attempts", "2",
			"--parent-pid", strconv.Itoa(parent.Process.Pid)})
	}()

	first := waitEvent(t, evs, "ready", nil)
	if first["reconnect"] != false || first["transport"] != "h2" || first["probe"] != "dns" {
		t.Fatalf("first ready = %v", first)
	}
	if data, err := os.ReadFile(ready); err != nil || !strings.Contains(string(data), `"ev":"ready"`) {
		t.Fatalf("ready file: %q %v", data, err)
	}
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("SOCKS listener not open after ready: %v", err)
	}
	_ = conn.Close()

	// Cut the tunnel: the helper must report the loss and redial the same tuple.
	srv.CloseClientConnections()
	lost := waitEvent(t, evs, "lost", nil)
	if lost["class"] != ClassClosed {
		t.Fatalf("lost = %v", lost)
	}
	again := waitEvent(t, evs, "ready", func(ev map[string]any) bool { return ev["reconnect"] == true })
	if again["endpoint"] != first["endpoint"] || again["sni"] != first["sni"] {
		t.Fatalf("redial changed the tuple: %v vs %v", again, first)
	}

	// Take the endpoint away: budget, re-walk, then the most specific exit code and a closed port.
	_ = srv.Listener.Close()
	srv.CloseClientConnections()
	exitEv := waitEvent(t, evs, "exit", nil)
	if exitEv["code"] != float64(ExitNoResponse) || exitEv["class"] != ClassH2TLS {
		t.Fatalf("exit = %v", exitEv)
	}
	select {
	case code := <-exitCode:
		if code != ExitNoResponse {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runtime did not return")
	}
	if c, err := net.DialTimeout("tcp", socksAddr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("SOCKS listener still open after exit")
	}
	if _, err := os.Stat(ready); !os.IsNotExist(err) {
		t.Fatal("ready file left after exit")
	}
}

// writeLoopbackProfile writes a profile that pins serverKey, for the local fake CONNECT-IP servers.
func writeLoopbackProfile(t *testing.T, serverKey *ecdsa.PrivateKey) string {
	t.Helper()
	clientDER, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peerDER, _ := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	id := Identity{
		PrivateKey:     base64.StdEncoding.EncodeToString(clientDER),
		EndpointV4:     "127.0.0.1",
		EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: peerDER})),
		IPv4:           "172.16.0.2",
	}
	doc, err := MarshalDocument(id, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(profile, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	return profile
}

// freeLoopbackAddr returns an ephemeral loopback address that was free a moment ago.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := free.Addr().String()
	_ = free.Close()
	return addr
}

// GM-2: a dial that uses most of --attempt-timeout on a slow path still gets the full data-plane
// probe. Before, the probe got only the leftover attempt time, called a working tunnel zero_rx
// twice and ended the walk with exit 13.
func TestSlowDialStillGetsTheFullProbeBudget(t *testing.T) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// CONNECT answered 2 s into a 3 s attempt; echoes come back 1.5 s after each packet.
	srv := newSlowEchoCONNECTServer(t, serverKey, 2*time.Second, 1500*time.Millisecond)
	profile := writeLoopbackProfile(t, serverKey)
	socksAddr := freeLoopbackAddr(t)

	stdout, evs := eventPipe(t)
	env := &cliEnv{stdout: stdout, stderr: io.Discard, version: "test"}
	exitCode := make(chan int, 1)
	go func() {
		exitCode <- env.main([]string{"socks", "--config", profile, "--bind", socksAddr,
			"--endpoint", srv.Listener.Addr().String(), "--transport", "h2", "--sni", "www.google.com",
			"--attempt-timeout", "3s", "--max-attempts", "2", "--reconnect-budget", "0"})
	}()
	var fails []map[string]any
	deadline := time.After(30 * time.Second)
wait:
	for {
		select {
		case ev, ok := <-evs:
			if !ok {
				t.Fatal("event stream ended before ready")
			}
			switch ev["ev"] {
			case "fail":
				fails = append(fails, ev)
			case "exit":
				t.Fatalf("exit before ready: %v (fails %v)", ev, fails)
			case "ready":
				if ev["reconnect"] != false {
					t.Fatalf("ready = %v", ev)
				}
				break wait
			}
		case <-deadline:
			t.Fatalf("no ready (fails %v)", fails)
		}
	}
	if len(fails) != 0 {
		t.Fatalf("the slow but working tunnel failed attempts first: %v", fails)
	}
	// Take the endpoint away; the helper gives up on its own and frees the port.
	_ = srv.Listener.Close()
	srv.CloseClientConnections()
	waitEvent(t, evs, "exit", nil)
	select {
	case <-exitCode:
	case <-time.After(15 * time.Second):
		t.Fatal("runtime did not return")
	}
}
