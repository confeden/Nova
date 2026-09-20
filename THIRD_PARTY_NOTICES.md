# Third-Party Notices

Nova bundles or interoperates with third-party software components. Those
components are not relicensed by Nova and remain subject to their own licenses
or vendor terms.

This file is a notice summary for distribution convenience. Where a local copy
of a third-party license text is included, it is stored under
`licenses/third_party/`.

## Open-source components with bundled notice texts

`bin/WinDivert.dll`, `bin/WinDivert64.sys`
Upstream: `https://github.com/basil00/WinDivert`
License family used for notice purposes: LGPL-3.0
Local notice text: `licenses/third_party/LGPL-3.0.txt`

`bin/wireproxy-awg.exe`
Upstream: `https://github.com/artem-russkikh/wireproxy-awg`
License: ISC
Local notice text: `licenses/third_party/wireproxy-awg-ISC.txt`

AWG support includes code or compatibility work based on AmneziaWG /
`amneziawg-go`
Upstream: `https://github.com/amnezia-vpn/amneziawg-go`
License: MIT
Local notice text: `licenses/third_party/amneziawg-go-MIT.txt`

`bin/nova-go.exe`
Nova's Go helper (WARP registration and endpoint scanning, MASQUE), built by
Nova from `nova-go/`. It links the following open-source components:
- usque — `https://github.com/Diniboy1123/usque` — MIT —
  `licenses/third_party/usque-MIT.txt`
- connect-ip-go (fork) — `https://github.com/Diniboy1123/connect-ip-go` — MIT —
  `licenses/third_party/connect-ip-go-MIT.txt`
- warp-plus (`ipscanner`, `warp`) — `https://github.com/bepass-org/warp-plus` —
  MIT — `licenses/third_party/warp-plus-MIT.txt`
- quic-go — `https://github.com/quic-go/quic-go` — MIT —
  `licenses/third_party/quic-go-MIT.txt`
- uTLS — `https://github.com/refraction-networking/utls` — BSD-3-Clause —
  `licenses/third_party/utls-BSD-3-Clause.txt`
- wireguard-go (`tun/netstack`) — `https://git.zx2c4.com/wireguard-go` — MIT —
  `licenses/third_party/wireguard-go-MIT.txt`
- gVisor — `https://github.com/google/gvisor` — Apache-2.0 —
  `licenses/third_party/gvisor-Apache-2.0.txt`
- go-socks5 — `https://github.com/things-go/go-socks5` — MIT —
  `licenses/third_party/go-socks5-MIT.txt`
- Go standard library and `golang.org/x/*` — BSD-3-Clause —
  `licenses/third_party/golang-x-BSD-3-Clause.txt`

`bin/nova-xray.exe`
Nova's Xray helper (VLESS profiles), built by Nova from `nova-xray/`. It is a
separate module and a separate binary from `bin/nova-go.exe` because Xray-core
and the MASQUE helper require incompatible versions of the same QUIC library.
- Xray-core — `https://github.com/XTLS/Xray-core` — MPL-2.0 —
  `licenses/third_party/MPL-2.0.txt`
- REALITY — `https://github.com/XTLS/REALITY` — MPL-2.0 —
  `licenses/third_party/MPL-2.0.txt`
- uTLS — `https://github.com/refraction-networking/utls` — BSD-3-Clause —
  `licenses/third_party/utls-BSD-3-Clause.txt`
- quic-go (fork) — `https://github.com/apernet/quic-go` — MIT —
  `licenses/third_party/quic-go-MIT.txt`
- CIRCL — `https://github.com/cloudflare/circl` — BSD-3-Clause —
  `licenses/third_party/circl-BSD-3-Clause.txt`
- gVisor — `https://github.com/google/gvisor` — Apache-2.0 —
  `licenses/third_party/gvisor-Apache-2.0.txt`
- sing, sing-shadowsocks — `https://github.com/SagerNet/sing`,
  `https://github.com/SagerNet/sing-shadowsocks` — GPL-3.0-or-later —
  `licenses/third_party/GPL-3.0.txt`,
  `licenses/third_party/sing-GPL-3.0-notice.txt`
- Go standard library and `golang.org/x/*` — BSD-3-Clause —
  `licenses/third_party/golang-x-BSD-3-Clause.txt`

Note on the two components above that are GPL-3.0-or-later: Nova does not use
Shadowsocks and does not register its proxy, but Xray-core's JSON configuration
loader (`infra/conf`) knows every protocol it supports, so linking the loader
links the Shadowsocks configuration code with it. The sources of every part of
this binary are public: Nova's own wrapper in `nova-xray/` in this repository,
and each upstream at the address listed above.

`bin/tor/nova-tor.exe`, `bin/tor/nova-lyrebird.exe`, `bin/tor/geoip`,
`bin/tor/geoip6`, `bin/tor/pt_config.json`
Unmodified files from the official Tor Expert Bundle 15.0.22 (tor 0.4.9.12,
lyrebird 0.8.1), renamed from `tor.exe` and `lyrebird.exe` so that Nova never
stops a Tor installation that belongs to the user. They run as separate
programs.
Upstream: `https://www.torproject.org/download/tor/`
Licenses: Tor — BSD-3-Clause with bundled components
(`licenses/third_party/tor-BSD-3-Clause.txt`, OpenSSL
`licenses/third_party/openssl-Apache-2.0.txt`, Libevent
`licenses/third_party/libevent-BSD-3-Clause.txt`, zlib
`licenses/third_party/zlib.txt`); this build of Tor states that it is covered
by the GNU GPL (`licenses/third_party/GPL-3.0.txt`); lyrebird — BSD-3-Clause
and GPL-3.0-or-later parts, with the texts of all its dependencies in
`licenses/third_party/lyrebird.txt`. Source code:
`https://gitlab.torproject.org/tpo/core/tor` and
`https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird`.

`tgrelay/*`
Telegram relay support includes vendored or adapted code derived from
`Flowseal/tg-ws-proxy`
Upstream: `https://github.com/Flowseal/tg-ws-proxy`
License: MIT
Local notice text: `licenses/third_party/Flowseal-tg-ws-proxy-MIT.txt`

## Other bundled third-party components

`bin/opera-proxy.windows-amd64.exe`
Third-party Opera proxy component used by Nova. This component remains subject
to the terms and license conditions of its upstream project and its own
dependencies.

`bin/warp-cli.exe`, `bin/warp-svc.exe`,
`bin/aws_lc_fips_0_13_14_crypto.dll`, `bin/wintun.dll`
Files taken from the official Cloudflare WARP distribution (client version
2026.7.1210.1). These files remain subject to Cloudflare's terms and to any
upstream component licenses applicable to the shipped runtime.
Reference links:
- https://developers.cloudflare.com/warp-client/
- https://www.wintun.net/

`bin/concrt140.dll`, `bin/msvcp140*.dll`, `bin/vccorlib140.dll`,
`bin/vcruntime140*.dll`
Microsoft Visual C++ runtime components. These files remain subject to the
Microsoft Visual C++ Redistributable terms.
Reference link:
- https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist

`bin/winws.exe`, `bin/winws_test.exe`
Derived from the `zapret` / `winws` project, version v72.13
(commit `87e058624c72863db53bdaf7fb6f16576dddb6ab`):
`https://github.com/bol-van/zapret`
Redistribution or license status should be verified against upstream before
shipping outside the current project workflow.

## Scope

These notices apply only to the listed third-party components. All Nova-authored
code and materials remain governed by `LICENSE`.
