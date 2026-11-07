// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
)

const fixtureUUID = "00000000-0000-4000-8000-000000000001"

func TestImportCompatibility(t *testing.T) {
	vmess, _ := json.Marshal(map[string]any{"v": "2", "add": "127.0.0.1", "port": 443, "id": fixtureUUID, "aid": 0, "net": "ws", "path": "/test", "tls": true})
	ss := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:p%40ss@word@127.0.0.1:8388"))
	lines := []string{"vmess://" + base64.RawURLEncoding.EncodeToString(vmess) + "#Name%20With%20Spaces",
		"ss://" + ss + "#SS", "hy2://p%40ss%3Aword@127.0.0.1:443?obfs=salamander&obfs-password=test&insecure=1#Hy2",
		"trojan://fixture@127.0.0.1:443?sni=localhost#Trojan", "anytls://fixture@127.0.0.1:443?insecure=1#AnyTLS",
		"tuic://" + fixtureUUID + ":fixture@127.0.0.1:443?alpn=h3#TUIC"}
	for _, line := range lines {
		result, err := importProfiles([]byte(line))
		if err != nil || len(result.Proxies) != 1 {
			t.Fatalf("fixture type %q rejected, skipped=%d", line[:5], result.Skipped)
		}
		p := result.Proxies[0]
		if p["type"] == "hysteria2" && p["password"] != "p@ss:word" {
			t.Fatal("escaped Hysteria auth changed")
		}
		if p["type"] == "ss" && p["password"] != "p%40ss@word" {
			t.Fatal("legacy Shadowsocks password changed")
		}
	}
}

func TestRuntimeCannotImportSystemRouting(t *testing.T) {
	runtime := Runtime{Proxies: []map[string]any{{"type": "http", "name": "label,REJECT", "server": "127.0.0.1", "port": 80}}, Selected: "label,REJECT", SocksPort: 19999}
	data, err := runtimeConfig(runtime)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if json.Unmarshal(data, &config) != nil {
		t.Fatal("invalid runtime JSON")
	}
	if config["bind-address"] != "127.0.0.1" || config["allow-lan"] != false || config["tun"].(map[string]any)["enable"] != false {
		t.Fatal("runtime is not isolated")
	}
	if config["rules"].([]any)[0] != "MATCH,nova-node-0" {
		t.Fatal("label reached rule syntax")
	}
}

func TestDirectCannotPassForAWorkingVPNProfile(t *testing.T) {
	_, err := runtimeConfig(Runtime{Proxies: []map[string]any{{"name": "bypass", "type": "direct"}}, Selected: "bypass", SocksPort: 19999})
	if err == nil {
		t.Fatal("DIRECT could masquerade as a working VPN profile")
	}
}

func TestAnyTLSBooleanAliasesAndHysteriaCase(t *testing.T) {
	for _, line := range []string{"anytls://fixture@127.0.0.1:443?allowInsecure=true#test", "HY2://p%40ss@127.0.0.1:443?insecure=true#test", "vless://" + fixtureUUID + "@127.0.0.1:443?security=tls&allowInsecure=1#test", "trojan://fixture@127.0.0.1:443?insecure=true#test"} {
		result, err := importProfiles([]byte(line))
		if err != nil || len(result.Proxies) != 1 {
			t.Fatal("fixture rejected")
		}
		if result.Proxies[0]["skip-cert-verify"] != true {
			t.Fatal("explicit insecure flag lost")
		}
		if result.Proxies[0]["type"] == "hysteria2" && result.Proxies[0]["password"] != "p@ss" {
			t.Fatal("escaped password lost")
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("write fixture")
	}
}

// This server entry point exists only in the test executable, never in the shipped helper.
func TestPrivateServerProcess(t *testing.T) {
	path := os.Getenv("NOVA_FIXTURE_SERVER")
	if path == "" {
		return
	}
	log.SetLevel(log.SILENT)
	C.SetHomeDir(filepath.Dir(path))
	data, err := os.ReadFile(path)
	if err != nil {
		os.Exit(3)
	}
	cfg, err := executor.ParseWithBytes(data)
	if err != nil {
		os.Exit(4)
	}
	executor.ApplyConfig(cfg, true)
	os.WriteFile(path+".ready", []byte("ready"), 0600)
	for {
		time.Sleep(time.Second)
	}
}
func TestPrivateClientProcess(t *testing.T) {
	path := os.Getenv("NOVA_FIXTURE_CLIENT")
	if path == "" {
		return
	}
	log.SetLevel(log.SILENT)
	if command([]string{"run", "--config", path, "--ready-file", path + ".ready"}) != nil {
		os.Exit(5)
	}
}
func child(t *testing.T, mode, path string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	test := "TestPrivateServerProcess"
	if mode == "CLIENT" {
		test = "TestPrivateClientProcess"
	}
	cmd := exec.Command(exe, "-test.run=^"+test+"$")
	output, err := os.Create(path + ".diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.Env = append(os.Environ(), "NOVA_FIXTURE_"+mode+"="+path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		output.Close()
		if t.Failed() {
			data, _ := os.ReadFile(path + ".diagnostics")
			t.Log(string(data))
		}
	})
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path + ".ready"); err == nil {
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatal("private fixture did not become ready")
}

func TestProtocolsCarryAuthenticatedHTTPS204(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/generate_204" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	cert := target.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"vmess", "vmess-ws", "vless", "trojan", "ss", "ss-obfs", "hysteria2", "tuic", "anytls"} {
		t.Run(kind, func(t *testing.T) {
			work := t.TempDir()
			certPath := filepath.Join(work, "cert.pem")
			keyPath := filepath.Join(work, "key.pem")
			os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600)
			os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600)
			serverPort := freePort(t)
			clientPort := freePort(t)
			server := map[string]any{"name": "fixture", "listen": "127.0.0.1", "port": serverPort, "type": kind}
			proxy := map[string]any{"name": "fixture", "server": "127.0.0.1", "port": serverPort, "type": kind}
			switch kind {
			case "vmess", "vmess-ws", "vless":
				if kind == "vless" {
					server["allow-insecure"] = true
				}
				base := kind
				if kind == "vmess-ws" {
					base = "vmess"
					server["ws-path"] = "/fixture"
					proxy["network"] = "ws"
					proxy["ws-opts"] = map[string]any{"path": "/fixture"}
				}
				server["type"] = base
				proxy["type"] = base
				server["users"] = []any{map[string]any{"uuid": fixtureUUID, "alterId": 0}}
				proxy["uuid"] = fixtureUUID
				proxy["alterId"] = 0
				proxy["cipher"] = "auto"
			case "ss", "ss-obfs":
				server["type"] = "shadowsocks"
				proxy["type"] = "ss"
				server["cipher"] = "aes-128-gcm"
				proxy["cipher"] = "aes-128-gcm"
				server["password"] = "fixture"
				proxy["password"] = "fixture"
				if kind == "ss-obfs" {
					server["simple-obfs"] = map[string]any{"enable": true, "mode": "http"}
					proxy["plugin"] = "obfs"
					proxy["plugin-opts"] = map[string]any{"mode": "http", "host": "example.org"}
				}
			default:
				server["certificate"] = certPath
				server["private-key"] = keyPath
				proxy["skip-cert-verify"] = true
				proxy["password"] = "fixture"
				if kind == "trojan" {
					server["users"] = []any{map[string]any{"username": "test", "password": "fixture"}}
				} else {
					server["users"] = map[string]any{"test": "fixture"}
				}
				if kind == "hysteria2" {
					server["obfs"] = "salamander"
					server["obfs-password"] = "padding"
					proxy["obfs"] = "salamander"
					proxy["obfs-password"] = "padding"
				}
				if kind == "tuic" {
					server["users"] = map[string]any{fixtureUUID: "fixture"}
					proxy["uuid"] = fixtureUUID
					proxy["congestion-controller"] = "bbr"
					server["alpn"] = []string{"h3"}
					proxy["alpn"] = []string{"h3"}
				}
			}
			serverPath := filepath.Join(work, "server.json")
			writeJSON(t, serverPath, map[string]any{"listeners": []any{server}, "mode": "rule", "rules": []string{"MATCH,DIRECT"}, "log-level": "debug", "tun": map[string]any{"enable": false}, "dns": map[string]any{"enable": false}})
			child(t, "SERVER", serverPath)
			clientPath := filepath.Join(work, "client.json")
			writeJSON(t, clientPath, Runtime{Proxies: []map[string]any{proxy}, Selected: "fixture", SocksPort: clientPort})
			child(t, "CLIENT", clientPath)
			proxyURL, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(clientPort))
			roots := x509.NewCertPool()
			roots.AddCert(target.Certificate())
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}
			defer transport.CloseIdleConnections()
			client := http.Client{Transport: transport, Timeout: 10 * time.Second}
			response, err := client.Get(target.URL + "/generate_204")
			if err != nil {
				t.Fatal(fmt.Errorf("HTTPS through %s: %w", kind, err))
			}
			response.Body.Close()
			if response.StatusCode != 204 {
				t.Fatal("wrong HTTPS status")
			}
			batchResult := probeNode(proxy, []string{target.URL + "/generate_204"}, 10*time.Second, &tls.Config{RootCAs: roots})
			if !batchResult.OK {
				t.Fatalf("batch HTTPS204 failed for %s: %s", kind, batchResult.Stage)
			}
			if kind == "ss" {
				if probeNode(proxy, []string{target.URL + "/generate_204"}, 2*time.Second, nil).OK {
					t.Fatal("batch accepted untrusted target TLS")
				}
				if probeNode(proxy, []string{target.URL + "/missing"}, 2*time.Second, &tls.Config{RootCAs: roots}).OK {
					t.Fatal("batch accepted non-204 HTTP status")
				}
			}
		})
	}
}
