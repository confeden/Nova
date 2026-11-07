# Nova protocol helper

Standalone GPL-3.0 helper embedding **Mihomo v1.19.33**, pinned in `go.mod`/`go.sum`.
The Nova host uses process IPC; the helper has its own license in this directory.

`import` reads a bounded Clash YAML/JSON or URI/base64 subscription on stdin and returns
validated proxy maps as JSON. Credentials belong only in private profile files, never logs.
VMess optional fragments, legacy Shadowsocks base64, Hysteria authentication escaping and
common TLS/obfuscation aliases are normalized before the upstream converter.

`run --config <private request> --ready-file <path> --parent-pid <pid>` starts one profile
and its dependency graph, exposing SOCKS5/UDP and optional HTTP CONNECT on loopback.
Requests contain only `proxies`, `selected`, `socks_port`, `http_port`. Imported routing,
TUN, system DNS, providers and controllers cannot enter the runtime configuration.
The core's home/cache is private and isolated by runtime config. Parent death stops the helper.

`check --config <path>` validates without starting listeners. Stateful endpoint constructors are
deferred until an explicit run; import never enrolls a Tailscale/ZeroTier/EasyTier node.
`version` reports both versions.
The installer builds this module locally with `CGO_ENABLED=0`, `GOAMD64=v1`.

Tests exercise real authenticated HTTPS 204 through local VMess TCP/WS, VLESS, Trojan,
Shadowsocks (including HTTP obfuscation), Hysteria2 + Salamander, TUIC and AnyTLS servers.
All servers and clients bind loopback; no test installs a system tunnel or DNS setting.

Existing Nova VLESS links and Xray-native JSON retain Xray for their transport-specific options. AWG stays
on wireproxy-awg. All imported kinds share the `Custom profiles` view; old file ids survive.
