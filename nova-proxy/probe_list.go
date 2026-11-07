// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
)

type probeResult struct {
	Index int    `json:"index"`
	OK    bool   `json:"ok"`
	MS    int64  `json:"ms"`
	Stage string `json:"stage"`
}

var probeTargets = []string{"https://www.google.com/generate_204", "https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"}

// No executor, listener, TUN, DNS manager, environment proxy or DIRECT fallback.
// The adapter carries only this request; target TLS always validates certificates.
func probeNode(proxy map[string]any, targets []string, budget time.Duration, roots *tls.Config) (result probeResult) {
	result.Stage = "invalid"
	defer func() {
		if recover() != nil {
			result.OK = false
			result.Stage = "invalid"
		}
	}()
	kind, _ := proxy["type"].(string)
	switch kind {
	case "", "direct", "reject", "dns", "block", "compatible", "tailscale", "zerotier", "easytier", "openvpn":
		return
	}
	if parent, _ := proxy["dialer-proxy"].(string); parent != "" && !strings.EqualFold(parent, "DIRECT") {
		result.Stage = "dependency"
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	// A refused/blackholed TCP endpoint cannot carry HTTPS. Avoid spending the full
	// multi-target TLS budget on it; the collector repeats failures in a separate pass.
	if kind != "hysteria" && kind != "hysteria2" && kind != "tuic" && kind != "wireguard" {
		host, _ := proxy["server"].(string)
		port := fmt.Sprint(proxy["port"])
		preflight, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
		connection, err := (&net.Dialer{}).DialContext(preflight, "tcp", net.JoinHostPort(host, port))
		stop()
		if err != nil {
			result.Stage = "tcp"
			return
		}
		connection.Close()
	}
	clientProxy, err := adapter.ParseProxy(proxy)
	if err != nil {
		return
	}
	defer clientProxy.Close()
	transport := &http.Transport{
		TLSClientConfig:   roots,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			p, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, err
			}
			metadata := &C.Metadata{NetWork: C.TCP, Host: host, DstPort: uint16(p)}
			if ip, err := netip.ParseAddr(host); err == nil {
				metadata.DstIP, metadata.Host = ip, ""
			}
			return clientProxy.DialContext(ctx, metadata)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	result.Stage = "https"
	for i, target := range targets {
		u, err := url.Parse(target)
		if err != nil || u.Scheme != "https" {
			continue
		}
		deadline, _ := ctx.Deadline()
		attempt, done := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(targets)-i))
		request, err := http.NewRequestWithContext(attempt, http.MethodGet, target, nil)
		if err != nil {
			done()
			continue
		}
		request.Header.Set("User-Agent", "NovaList/1")
		started := time.Now()
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				result.OK, result.MS, result.Stage = true, time.Since(started).Milliseconds(), "ok"
				done()
				return
			}
		}
		done()
	}
	return
}

func probeList(args []string) error {
	flags := flag.NewFlagSet("probe-list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	workers := flags.Int("workers", 32, "bounded concurrency")
	seconds := flags.Int("timeout", 9, "per-node total budget")
	if flags.Parse(args) != nil || *workers < 1 || *workers > 64 || *seconds < 1 || *seconds > 60 {
		return errors.New("invalid probe bounds")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxInput+1))
	var request ImportResult
	if err != nil || len(data) > maxInput || json.Unmarshal(data, &request) != nil || len(request.Proxies) > 20000 {
		return errors.New("invalid probe request")
	}
	jobs := make(chan int)
	var wait sync.WaitGroup
	var output sync.Mutex
	encoder := json.NewEncoder(os.Stdout)
	var outputError error
	for n := 0; n < *workers; n++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := range jobs {
				result := probeNode(request.Proxies[index], probeTargets, time.Duration(*seconds)*time.Second, nil)
				result.Index = index
				output.Lock()
				if err := encoder.Encode(result); err != nil {
					outputError = err
				}
				output.Unlock()
			}
		}()
	}
	for index := range request.Proxies {
		jobs <- index
	}
	close(jobs)
	wait.Wait()
	if outputError != nil {
		return errors.New("cannot write probe results")
	}
	return nil
}
