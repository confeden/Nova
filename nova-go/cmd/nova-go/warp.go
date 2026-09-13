//go:build !nowarp

package main

// The warp group: `nova-go warp register` and `nova-go warp scan`, the Go half of Nova PC's own-WARP
// generator (resources/nova_warp_generator.py drives both).
//
// register — stdout: exactly one JSON line, {"ok":true,"via":…,"response":{…}} or
//            {"ok":false,"error":…}; exit 0 ok, 20 unreachable, 21 API non-200 / unusable answer,
//            2 usage, 1 internal.
// scan     — the base64 private key is the first line of stdin (never argv); stdout: verified hits
//            only, "addr:port|rtt_ms" per line sorted by RTT; exit 0 (also with zero hits), 2 usage.
// stderr carries the human log of both.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"nova-pc/nova-go/warp"
)

const (
	warpExitOK          = 0
	warpExitInternal    = 1
	warpExitUsage       = 2
	warpExitUnreachable = 20
	warpExitAPIStatus   = 21

	// warpProxyEnv is read when --api-proxy is not given, so a proxy URL with credentials (the relay)
	// need not appear on a command line.
	warpProxyEnv = "NOVA_API_PROXY"
	// stdinKeyWait bounds waiting for the private key line.
	stdinKeyWait = 15 * time.Second
)

func init() {
	register(group{name: "warp", help: "WARP device registration and endpoint scan (register, scan)", run: runWarp})
}

func runWarp(args []string) int {
	if len(args) == 0 {
		warpUsage()
		return warpExitUsage
	}
	switch args[0] {
	case "register":
		return warpRegister(args[1:], os.Stdout)
	case "scan":
		return warpScan(args[1:], os.Stdin, os.Stdout)
	case "help", "-h", "--help":
		warpUsage()
		return warpExitOK
	}
	fmt.Fprintf(os.Stderr, "nova-go warp: unknown command %q\n", args[0])
	warpUsage()
	return warpExitUsage
}

func warpUsage() {
	fmt.Fprintln(os.Stderr, "usage: nova-go warp register --public-key <b64> [--model PC] [--locale en-US] [--api-proxy URL] [--api-mode auto|direct|proxy|plain] [--timeout 60s]")
	fmt.Fprintln(os.Stderr, "       nova-go warp scan --peer-public-key <b64> [--v4] [--v6] [--timeout 45s] [--limit 50] [--rtt-max 1500ms] [--workers 16]  (private key: first line of stdin)")
}

var warpLogMu sync.Mutex

// warpLog writes "2026-09-13T10:00:00.123Z INF warp: message" lines to stderr.
func warpLog(format string, args ...any) {
	line := time.Now().UTC().Format("2006-01-02T15:04:05.000Z") + " INF warp: " + fmt.Sprintf(format, args...)
	line = strings.ReplaceAll(line, "\n", " ")
	warpLogMu.Lock()
	defer warpLogMu.Unlock()
	fmt.Fprintln(os.Stderr, line)
}

type registerOutput struct {
	OK       bool            `json:"ok"`
	Via      string          `json:"via,omitempty"`
	Status   int             `json:"status,omitempty"`
	Error    string          `json:"error,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
}

func writeRegisterOutput(stdout io.Writer, out registerOutput) {
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		warpLog("register: cannot write result: %v", err)
	}
}

func warpRegister(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("nova-go warp register", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	publicKey := fs.String("public-key", "", "base64 X25519 public key of the device (required)")
	model := fs.String("model", "PC", "registration model")
	locale := fs.String("locale", "en-US", "registration locale")
	apiProxy := fs.String("api-proxy", "", "HTTP CONNECT proxy, e.g. http://127.0.0.1:1371 (default: $"+warpProxyEnv+")")
	apiMode := fs.String("api-mode", "auto", "auto (direct, then proxy) | direct | proxy | plain")
	timeout := fs.Duration("timeout", 60*time.Second, "whole operation")

	usageFail := func(msg string) int {
		warpLog("register: %s", msg)
		writeRegisterOutput(stdout, registerOutput{OK: false, Error: msg})
		return warpExitUsage
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return warpExitOK
		}
		return usageFail("bad flags: " + err.Error())
	}
	if fs.NArg() > 0 {
		return usageFail(fmt.Sprintf("%d unexpected positional argument(s)", fs.NArg()))
	}
	if strings.TrimSpace(*publicKey) == "" {
		return usageFail("--public-key is required")
	}
	if *timeout <= 0 {
		return usageFail("--timeout must be positive")
	}
	mode, err := warp.ParseMode(*apiMode)
	if err != nil {
		return usageFail(err.Error())
	}
	proxyURL := strings.TrimSpace(*apiProxy)
	if proxyURL == "" {
		proxyURL = strings.TrimSpace(os.Getenv(warpProxyEnv))
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stopSignals := signal.NotifyContext(ctx, os.Interrupt)
	defer stopSignals()

	started := time.Now()
	warpLog("register: mode=%s proxy=%t timeout=%s", mode, proxyURL != "", *timeout)
	resp, err := warp.Register(ctx, warp.RegisterOptions{
		PublicKey: *publicKey,
		Model:     *model,
		Locale:    *locale,
		API:       warp.APIOptions{Mode: mode, ProxyURL: proxyURL, Logf: warpLog},
	})
	if err != nil {
		var statusErr *warp.StatusError
		switch {
		case errors.Is(err, warp.ErrUsage):
			return usageFail(err.Error())
		case errors.As(err, &statusErr):
			warpLog("register: failed after %s: %v", time.Since(started).Round(time.Millisecond), err)
			writeRegisterOutput(stdout, registerOutput{OK: false, Via: statusErr.Via, Status: statusErr.StatusCode, Error: err.Error()})
			return warpExitAPIStatus
		case errors.Is(err, warp.ErrUnreachable):
			warpLog("register: failed after %s: %v", time.Since(started).Round(time.Millisecond), err)
			writeRegisterOutput(stdout, registerOutput{OK: false, Error: err.Error()})
			return warpExitUnreachable
		default:
			warpLog("register: internal error: %v", err)
			writeRegisterOutput(stdout, registerOutput{OK: false, Error: err.Error()})
			return warpExitInternal
		}
	}

	reg, err := warp.ParseRegistration(resp.Body)
	if err != nil {
		warpLog("register: HTTP 200 via %s but the answer is unusable: %v", resp.Via, err)
		writeRegisterOutput(stdout, registerOutput{OK: false, Via: resp.Via, Status: resp.StatusCode, Error: "unusable registration response: " + err.Error()})
		return warpExitAPIStatus
	}
	warpLog("register: ok via %s in %s; %s", resp.Via, time.Since(started).Round(time.Millisecond), reg.Summary())
	writeRegisterOutput(stdout, registerOutput{OK: true, Via: resp.Via, Response: json.RawMessage(resp.Body)})
	return warpExitOK
}

func warpScan(args []string, stdin io.Reader, stdout io.Writer) int {
	fs := flag.NewFlagSet("nova-go warp scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	peerKey := fs.String("peer-public-key", "", "base64 peer public key from the registration (required)")
	useV4 := fs.Bool("v4", false, "scan IPv4 prefixes")
	useV6 := fs.Bool("v6", false, "scan IPv6 prefixes (neither flag: both)")
	timeout := fs.Duration("timeout", 45*time.Second, "scan duration ceiling")
	limit := fs.Int("limit", warp.DefaultScanLimit, "stop after this many verified endpoints")
	rttMax := fs.Duration("rtt-max", warp.DefaultScanMaxRTT, "drop endpoints slower than this")
	workers := fs.Int("workers", warp.DefaultScanWorkers, "concurrent handshake probes")

	usageFail := func(msg string) int {
		warpLog("scan: %s", msg)
		return warpExitUsage
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return warpExitOK
		}
		return usageFail("bad flags: " + err.Error())
	}
	switch {
	case fs.NArg() > 0:
		// The value is not echoed: a misplaced private key must not reach the log.
		return usageFail(fmt.Sprintf("%d unexpected positional argument(s); the private key goes to stdin", fs.NArg()))
	case strings.TrimSpace(*peerKey) == "":
		return usageFail("--peer-public-key is required")
	case *timeout <= 0:
		return usageFail("--timeout must be positive")
	case *limit <= 0:
		return usageFail("--limit must be positive")
	case *rttMax <= 0:
		return usageFail("--rtt-max must be positive")
	case *workers <= 0 || *workers > warp.MaxScanWorkers:
		return usageFail(fmt.Sprintf("--workers must be 1..%d", warp.MaxScanWorkers))
	}

	privateKey, err := readKeyLine(stdin, stdinKeyWait)
	if err != nil {
		return usageFail(err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stopSignals := signal.NotifyContext(ctx, os.Interrupt)
	defer stopSignals()

	hits, _, err := warp.Scan(ctx, warp.ScanOptions{
		PrivateKey:    privateKey,
		PeerPublicKey: *peerKey,
		IPv4:          *useV4,
		IPv6:          *useV6,
		Limit:         *limit,
		MaxRTT:        *rttMax,
		Workers:       *workers,
		Logf:          warpLog,
	})
	if err != nil {
		if errors.Is(err, warp.ErrUsage) {
			return usageFail(err.Error())
		}
		warpLog("scan: internal error: %v", err)
		return warpExitInternal
	}
	if _, err := io.WriteString(stdout, warp.FormatHits(hits)); err != nil {
		warpLog("scan: cannot write hits: %v", err)
		return warpExitInternal
	}
	return warpExitOK
}

// readKeyLine reads the first stdin line (BOM, CR and spaces trimmed). It gives up after wait so a
// caller that forgot to write or close stdin gets exit 2 instead of a hung helper.
func readKeyLine(stdin io.Reader, wait time.Duration) (string, error) {
	type lineResult struct {
		line string
		err  error
	}
	done := make(chan lineResult, 1)
	go func() {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err == io.EOF && line != "" {
			err = nil
		}
		done <- lineResult{line: line, err: err}
	}()
	select {
	case res := <-done:
		if res.err != nil && res.err != io.EOF {
			return "", fmt.Errorf("cannot read the private key from stdin: %v", res.err)
		}
		key := strings.TrimSpace(strings.TrimPrefix(res.line, "\ufeff"))
		if key == "" {
			return "", errors.New("no private key on the first line of stdin")
		}
		return key, nil
	case <-time.After(wait):
		return "", fmt.Errorf("no private key on stdin within %s", wait)
	}
}
