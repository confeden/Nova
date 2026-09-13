package masque

// `nova-go masque probe` (port of masque_probe.go ProbeMasqueHandshake and `masqueprobe -sweep`):
// the same dial as `socks` up to the CONNECT-IP status, then close. No data plane, no SOCKS.
// `nova-go masque check`: parse, normalize and summarize a profile without secrets.

import (
	"context"
	"errors"
	"flag"
	"net/netip"
	"strings"
	"time"

	"nova-pc/nova-go/internal/events"
)

func runProbe(args []string, env *cliEnv) int {
	var (
		common           commonOptions
		configPath       string
		endpoint         string
		sni              string
		transport        string
		sweep            string
		timeout          time.Duration
		connectIPTimeout time.Duration
		cidLen           int
		noWrap           bool
		allowCF          bool
	)
	fs := flag.NewFlagSet("masque probe", flag.ContinueOnError)
	common.register(fs)
	fs.StringVar(&configPath, "config", "", "MASQUE profile")
	fs.StringVar(&endpoint, "endpoint", "", "ip:port (default: first IPv4 candidate, first profile port)")
	fs.StringVar(&sni, "sni", "", "TLS server name (required)")
	fs.StringVar(&transport, "transport", transportH3, "h3|h2")
	fs.StringVar(&sweep, "sweep", "", "comma list of ports probed one after another on the endpoint address")
	fs.DurationVar(&timeout, "timeout", 6*time.Second, "per probe")
	fs.DurationVar(&connectIPTimeout, "connect-ip-timeout", 4500*time.Millisecond, "SETTINGS + CONNECT-IP budget")
	fs.IntVar(&cidLen, "cid-len", 20, "QUIC connection ID length")
	fs.BoolVar(&noWrap, "no-wrap-socket", false, "hand quic-go the raw UDP socket (diagnostic)")
	fs.BoolVar(&allowCF, "allow-cloudflare-sni", false, "permit *.cloudflareclient.com server names")
	if ok, code := env.parseFlags(fs, args); !ok {
		return code
	}
	log, em, cleanup, code := env.setup(common, "probe")
	if code != 0 {
		return code
	}
	defer cleanup()

	usage := func(err error) int {
		log.Error("bad flags", "err", err)
		return emitExit(em, ExitUsage, "usage", 0, err)
	}
	if strings.TrimSpace(configPath) == "" {
		return usage(errors.New("--config is required"))
	}
	if strings.TrimSpace(sni) == "" {
		return usage(errors.New("--sni is required"))
	}
	if transport != transportH3 && transport != transportH2 {
		return usage(errors.New("--transport must be h3 or h2"))
	}
	if timeout < time.Second || cidLen < 4 || cidLen > 20 || connectIPTimeout < 500*time.Millisecond {
		return usage(errors.New("--timeout >= 1s, --connect-ip-timeout >= 500ms, --cid-len 4..20"))
	}
	snis, err := BuildSNIOrder([]string{sni}, "", allowCF)
	if err != nil {
		return usage(err)
	}
	id, _, err := LoadIdentityFile(configPath)
	if err != nil {
		log.Error("profile rejected", "err", err)
		return emitExit(em, ExitConfig, ClassConfig, 0, err)
	}
	crypto, err := PrepareCrypto(id)
	if err != nil {
		log.Error("profile keys rejected", "err", err)
		return emitExit(em, ExitConfig, ClassConfig, 0, err)
	}

	var base netip.AddrPort
	if strings.TrimSpace(endpoint) != "" {
		targets, err := parseEndpoints([]string{endpoint})
		if err != nil {
			return usage(err)
		}
		port := targets[0].port
		if port == 0 {
			port = id.Ports[0]
		}
		base = netip.AddrPortFrom(targets[0].addr, uint16(port))
	} else {
		host := id.EndpointV4
		if host == "" {
			host = id.EndpointV6
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return emitExit(em, ExitConfig, ClassConfig, 0, err)
		}
		base = netip.AddrPortFrom(addr, uint16(id.Ports[0]))
	}
	ports := []int{int(base.Port())}
	if strings.TrimSpace(sweep) != "" {
		if ports, err = parsePorts(sweep); err != nil {
			return usage(err)
		}
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	if code, stop := env.startStopWatch(ctx, cancel, common.parentPID, log); stop {
		return emitExit(em, code, stopClass(code), 0, nil)
	}

	opts := dialOptions{connectIPTimeout: connectIPTimeout, cidLen: cidLen, wrapSocket: !noWrap,
		initialPacketSize: 1242, keepAlive: 5 * time.Second, idleTimeout: 90 * time.Second}
	t := newTally()
	okCount := 0
	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		spec := dialSpec{endpoint: netip.AddrPortFrom(base.Addr(), uint16(port)), transport: transport, sni: snis[0]}
		tlsConf, err := NewTLSConfig(crypto, spec.sni, allowCF)
		if err != nil {
			return usage(err)
		}
		pctx, pcancel := context.WithTimeout(ctx, timeout)
		started := time.Now()
		var (
			s    *session
			fail *dialOutcome
		)
		if transport == transportH2 {
			s, fail = dialH2(pctx, spec, tlsConf, opts, log)
		} else {
			s, fail = dialH3(pctx, spec, tlsConf, opts, log)
		}
		pcancel()
		t.attempts++
		fields := []events.Field{events.F("endpoint", spec.endpoint.String()), events.F("transport", transport),
			events.F("sni", spec.sni), events.F("ok", s != nil), events.F("ms", time.Since(started).Milliseconds())}
		if s != nil {
			okCount++
			sent, recv := s.sentPackets()
			fields = append(fields, events.F("status", s.status), events.F("sent", sent), events.F("recv", recv),
				events.F("connect_ms", s.handshakeMs), events.F("settings_ms", s.settingsMs), events.F("connectip_ms", s.connectIPMs))
			s.close()
		} else {
			t.add(fail.class)
			errText := ""
			if fail.err != nil {
				errText = truncate(fail.err.Error(), 300)
			}
			fields = append(fields, events.F("status", fail.status), events.F("class", fail.class), events.F("stage", fail.stage),
				events.F("sent", fail.sent), events.F("recv", fail.recv), events.F("err", errText))
		}
		em.Emit("probe", fields...)
	}
	if ctx.Err() != nil {
		return emitExit(em, ExitOK, stopClass(ExitOK), t.attempts, nil)
	}
	if okCount > 0 {
		return emitExit(em, ExitOK, "", t.attempts, nil)
	}
	code, class := t.exit()
	return emitExit(em, code, class, t.attempts, nil)
}

func runCheck(args []string, env *cliEnv) int {
	var (
		common     commonOptions
		configPath string
	)
	fs := flag.NewFlagSet("masque check", flag.ContinueOnError)
	common.register(fs)
	fs.StringVar(&configPath, "config", "", "MASQUE profile")
	if ok, code := env.parseFlags(fs, args); !ok {
		return code
	}
	log, em, cleanup, code := env.setup(common, "check")
	if code != 0 {
		return code
	}
	defer cleanup()
	if strings.TrimSpace(configPath) == "" {
		log.Error("bad flags", "err", "--config is required")
		em.Emit("check", events.F("ok", false), events.F("err", "--config is required"))
		return ExitUsage
	}
	id, _, err := LoadIdentityFile(configPath)
	if err == nil {
		_, err = PrepareCrypto(id)
	}
	if err != nil {
		log.Error("profile rejected", "config", configPath, "err", err)
		em.Emit("check", events.F("ok", false), events.F("err", truncate(err.Error(), 300)))
		return ExitConfig
	}
	em.Emit("check", checkFields(id)...)
	return ExitOK
}

// checkFields is the secrets-free profile summary (and-masque.md §8.2 check).
func checkFields(id Identity) []events.Field {
	return []events.Field{
		events.F("ok", true),
		events.F("device_id_prefix", DeviceIDPrefix(id.DeviceID)),
		events.F("endpoint_v4", id.EndpointV4),
		events.F("ports", id.Ports),
		events.F("issued_at", id.IssuedAt),
		events.F("has_ipv6", id.IPv6 != ""),
	}
}
