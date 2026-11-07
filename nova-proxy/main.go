// SPDX-License-Identifier: GPL-3.0-only
// nova-proxy embeds the pinned Mihomo client core behind Nova's loopback-only helper contract.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"go.yaml.in/yaml/v3"
)

var version = "dev"

const coreVersion = "1.19.33"
const maxInput = 8 * 1024 * 1024

type ImportResult struct {
	Proxies []map[string]any `json:"proxies"`
	Skipped int              `json:"skipped"`
	Errors  map[string]int   `json:"errors,omitempty"`
}
type Runtime struct {
	Proxies   []map[string]any `json:"proxies"`
	Selected  string           `json:"selected"`
	SocksPort int              `json:"socks_port"`
	HTTPPort  int              `json:"http_port"`
}

func main() {
	log.SetLevel(log.SILENT)
	if err := command(os.Args[1:]); err != nil {
		// Core errors may contain credentials or complete share links. Never print them.
		fmt.Fprintln(os.Stderr, "nova-proxy: "+err.Error())
		os.Exit(2)
	}
}

func command(args []string) error {
	if len(args) == 0 {
		return errors.New("expected import, check, run or version")
	}
	switch args[0] {
	case "version":
		fmt.Printf("nova-proxy %s (mihomo %s)\n", version, coreVersion)
		return nil
	case "probe-list":
		return probeList(args[1:])
	case "import":
		data, err := io.ReadAll(io.LimitReader(os.Stdin, maxInput+1))
		if err != nil || len(data) > maxInput {
			return errors.New("import exceeds size limit")
		}
		result, err := importProfiles(data)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "check", "run":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		path := flags.String("config", "", "private runtime request")
		ready := flags.String("ready-file", "", "readiness witness")
		parent := flags.Int("parent-pid", 0, "owner process")
		_ = flags.String("log", "", "reserved; sensitive core logging stays disabled")
		if flags.Parse(args[1:]) != nil {
			return errors.New("invalid arguments")
		}
		data, err := os.ReadFile(*path)
		if err != nil || len(data) > maxInput {
			return errors.New("cannot read private runtime request")
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return errors.New("invalid runtime path")
		}
		var request Runtime
		if json.Unmarshal(data, &request) != nil {
			return errors.New("invalid runtime JSON")
		}
		config, err := runtimeConfig(request)
		if err != nil {
			return err
		}
		stateKey := sha256.Sum256(config)
		stateHome := filepath.Join(filepath.Dir(absolute), fmt.Sprintf(".core-%x", stateKey[:12]))
		C.SetHomeDir(stateHome)
		if args[0] == "check" {
			for _, proxy := range request.Proxies {
				if err := validateProxy(proxy); err != nil {
					return errors.New("core rejected proxy configuration")
				}
			}
			fmt.Println("ok")
			return nil
		}
		if os.MkdirAll(stateHome, 0700) != nil {
			return errors.New("cannot create private core state")
		}
		cfg, err := executor.ParseWithBytes(config)
		if err != nil {
			return errors.New("core rejected runtime configuration")
		}
		if args[0] == "check" {
			fmt.Println("ok")
			return nil
		}
		if *ready != "" {
			if err := os.Remove(*ready); err != nil && !os.IsNotExist(err) {
				return errors.New("cannot remove old readiness witness")
			}
		}
		for _, port := range []int{request.SocksPort, request.HTTPPort} {
			if port == 0 {
				continue
			}
			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				return errors.New("loopback port is already occupied")
			}
			listener.Close()
		}
		executor.ApplyConfig(cfg, true)
		defer executor.Shutdown()
		// A bind failure is not readiness, and an unrelated pre-existing listener must not be adopted.
		for _, port := range []int{request.SocksPort, request.HTTPPort} {
			if port == 0 {
				continue
			}
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err != nil {
				return errors.New("loopback listener failed to bind")
			}
			c.Close()
		}
		if *ready != "" {
			body, _ := json.Marshal(map[string]any{"pid": os.Getpid(), "socks_port": request.SocksPort, "http_port": request.HTTPPort})
			if os.MkdirAll(filepath.Dir(*ready), 0700) != nil || os.WriteFile(*ready, body, 0600) != nil {
				return errors.New("cannot write readiness witness")
			}
			defer os.Remove(*ready)
		}
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(signals)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-signals:
				return nil
			case <-ticker.C:
				if *parent > 0 && !processAlive(*parent) {
					return nil
				}
			}
		}
	default:
		return errors.New("unsupported command")
	}
}

func importProfiles(data []byte) (ImportResult, error) {
	data = convert.DecodeBase64(data)
	var document struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	var proxies []map[string]any
	parseSkipped := 0
	if yaml.Unmarshal(data, &document) == nil && len(document.Proxies) > 0 {
		proxies = document.Proxies
	} else if yaml.Unmarshal(data, &proxies) != nil || len(proxies) == 0 {
		var single map[string]any
		if yaml.Unmarshal(data, &single) == nil && single["type"] != nil {
			proxies = []map[string]any{single}
		} else {
			proxies = make([]map[string]any, 0)
			for _, raw := range strings.Split(string(convert.DecodeBase64(data)), "\n") {
				line := strings.TrimSpace(raw)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				items := convertLine(line)
				if len(items) == 0 {
					parseSkipped++
				}
				proxies = append(proxies, items...)
			}
		}
	}
	if len(proxies) > 20000 {
		return ImportResult{}, errors.New("too many profiles")
	}
	result := ImportResult{Proxies: make([]map[string]any, 0, len(proxies)), Skipped: parseSkipped, Errors: map[string]int{}}
	if parseSkipped > 0 {
		result.Errors["unrecognized_link"] = parseSkipped
	}
	for _, proxy := range proxies {
		// Keep complete protocol/transport options. Validation errors are local and never include secrets.
		err := validateProxy(proxy)
		if err != nil {
			result.Skipped++
			reason := "invalid_configuration"
			lower := strings.ToLower(err.Error())
			for _, category := range []string{"cipher", "password", "uuid", "network", "tls", "port", "type"} {
				if strings.Contains(lower, category) {
					reason = "invalid_" + category
					break
				}
			}
			result.Errors[reason]++
			continue
		}
		result.Proxies = append(result.Proxies, proxy)
	}
	return result, nil
}

func validateProxy(proxy map[string]any) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("invalid configuration")
		}
	}()
	if _, err = json.Marshal(proxy); err != nil {
		return err
	}
	// Stateful constructors must not contact a control plane or start a peer while importing.
	switch proxy["type"] {
	case "tailscale", "zerotier", "easytier", "wireguard", "openvpn":
		return nil
	}
	client, err := adapter.ParseProxy(proxy)
	if err == nil {
		client.Close()
	}
	return err
}

func convertLine(line string) (proxies []map[string]any) {
	// One broken share link must not abort unrelated profiles or expose its credentials.
	defer func() {
		if recover() != nil {
			proxies = nil
		}
	}()
	if strings.HasPrefix(strings.ToLower(line), "vmess://") {
		body, fragment, hasFragment := strings.Cut(line[8:], "#")
		decoded, ok := decodeBase64(body)
		var fields map[string]any
		if ok && json.Unmarshal(decoded, &fields) == nil {
			if _, ok := fields["ps"].(string); !ok {
				fields["ps"] = "VMess"
			}
			if hasFragment {
				if name, err := url.PathUnescape(fragment); err == nil {
					fields["ps"] = name
				}
			}
			if tls, ok := fields["tls"].(bool); ok {
				if tls {
					fields["tls"] = "tls"
				} else {
					fields["tls"] = ""
				}
			}
			encoded, _ := json.Marshal(fields)
			line = "vmess://" + base64.StdEncoding.EncodeToString(encoded)
		}
	}
	if strings.HasPrefix(strings.ToLower(line), "ss://") {
		body, fragment, _ := strings.Cut(line[5:], "#")
		authority, query, _ := strings.Cut(body, "?")
		decodedCredentials := false
		if !strings.Contains(authority, "@") {
			if decoded, ok := decodeBase64(authority); ok {
				authority = string(decoded)
				decodedCredentials = true
			}
		}
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			credentials, server := authority[:at], authority[at+1:]
			if decoded, ok := decodeBase64(credentials); ok && strings.Contains(string(decoded), ":") {
				credentials = string(decoded)
				decodedCredentials = true
			}
			if cipher, password, ok := strings.Cut(credentials, ":"); ok {
				if !decodedCredentials {
					if decoded, err := url.PathUnescape(cipher); err == nil {
						cipher = decoded
					}
					if decoded, err := url.PathUnescape(password); err == nil {
						password = decoded
					}
				}
				line = "ss://" + url.UserPassword(cipher, password).String() + "@" + server
				if query != "" {
					line += "?" + query
				}
				if fragment != "" {
					line += "#" + fragment
				}
			}
		}
	}
	u, err := url.Parse(line)
	if err == nil && u.Scheme == "wireguard" {
		q := u.Query()
		key := u.User.Username()
		name := u.Fragment
		if name == "" {
			name = "WireGuard"
		}
		proxy := map[string]any{"name": name, "type": "wireguard", "server": u.Hostname(), "port": u.Port(), "private-key": key, "public-key": q.Get("publickey"), "udp": true}
		if proxy["public-key"] == "" {
			proxy["public-key"] = q.Get("public-key")
		}
		for _, address := range strings.Split(q.Get("address"), ",") {
			address = strings.Split(address, "/")[0]
			if strings.Contains(address, ":") {
				proxy["ipv6"] = address
			} else if address != "" {
				proxy["ip"] = address
			}
		}
		if psk := q.Get("presharedkey"); psk != "" {
			proxy["pre-shared-key"] = psk
		}
		if mtu := q.Get("mtu"); mtu != "" {
			proxy["mtu"] = mtu
		}
		if value := q.Get("reserved"); value != "" {
			var reserved []int
			for _, part := range strings.Split(strings.Trim(value, "[]"), ",") {
				n, err := strconv.Atoi(part)
				if err != nil {
					return nil
				}
				reserved = append(reserved, n)
			}
			proxy["reserved"] = reserved
		}
		return []map[string]any{proxy}
	}
	if err == nil && u.RawQuery != "" {
		q := u.Query()
		for key, values := range q {
			lower := strings.ToLower(key)
			if (lower == "allowinsecure" || lower == "skip-cert-verify") && q.Get("insecure") == "" {
				q.Set("insecure", values[0])
			}
			if lower == "obfspassword" && q.Get("obfs-password") == "" {
				q.Set("obfs-password", values[0])
			}
			if (lower == "peer" || lower == "servername") && q.Get("sni") == "" {
				q.Set("sni", values[0])
			}
		}
		if value, err := strconv.ParseBool(q.Get("insecure")); err == nil {
			if value {
				q.Set("insecure", "1")
			} else {
				q.Set("insecure", "0")
			}
		}
		u.RawQuery = q.Encode()
		line = u.String()
	}
	proxies, _ = convert.ConvertsV2Ray([]byte(line))
	if err == nil {
		if insecure, parseError := strconv.ParseBool(u.Query().Get("insecure")); parseError == nil {
			for _, proxy := range proxies {
				proxy["skip-cert-verify"] = insecure
			}
		}
	}
	if err == nil && u.User != nil && (strings.HasPrefix(strings.ToLower(u.Scheme), "hy2") || strings.HasPrefix(strings.ToLower(u.Scheme), "hysteria2")) {
		password, decodeError := url.PathUnescape(u.User.String())
		if decodeError == nil {
			for _, proxy := range proxies {
				proxy["password"] = password
			}
		}
	}
	return proxies
}

func decodeBase64(value string) ([]byte, bool) {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, true
		}
	}
	return nil, false
}

func runtimeConfig(request Runtime) ([]byte, error) {
	if len(request.Proxies) == 0 || len(request.Proxies) > 512 || request.SocksPort < 1 || request.SocksPort > 65535 || request.HTTPPort < 0 || request.HTTPPort > 65535 || request.HTTPPort == request.SocksPort {
		return nil, errors.New("invalid loopback runtime bounds")
	}
	names := make(map[string]string, len(request.Proxies))
	for i, proxy := range request.Proxies {
		name, _ := proxy["name"].(string)
		if name == request.Selected {
			switch proxy["type"] {
			case "direct", "reject", "dns", "block", "compatible":
				return nil, errors.New("selected profile is not a VPN/proxy endpoint")
			}
		}
		if name == "" || names[name] != "" {
			return nil, errors.New("missing or duplicate proxy name")
		}
		names[name] = fmt.Sprintf("nova-node-%d", i)
	}
	selected := names[request.Selected]
	if selected == "" {
		return nil, errors.New("selected proxy not found")
	}
	// Rename only graph references; subscription labels cannot inject rule syntax.
	for _, proxy := range request.Proxies {
		proxy["name"] = names[proxy["name"].(string)]
		if parent, ok := proxy["dialer-proxy"].(string); ok && parent != "" {
			if strings.EqualFold(parent, "DIRECT") {
				delete(proxy, "dialer-proxy")
			} else if names[parent] != "" {
				proxy["dialer-proxy"] = names[parent]
			} else {
				return nil, errors.New("proxy dependency not found")
			}
		}
	}
	// No imported routing, listeners, controllers, providers, TUN, system DNS or auto-downloads.
	return json.Marshal(map[string]any{
		"socks-port": request.SocksPort, "port": request.HTTPPort, "allow-lan": false, "bind-address": "127.0.0.1",
		"mode": "rule", "log-level": "silent", "ipv6": true, "unified-delay": true,
		"proxies": request.Proxies, "rules": []string{"MATCH," + selected},
		"tun": map[string]any{"enable": false}, "dns": map[string]any{"enable": false},
		"profile": map[string]any{"store-selected": false, "store-fake-ip": false},
	})
}
