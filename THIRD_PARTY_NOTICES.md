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

`bin/warp-cli.exe`, `bin/warp-svc.exe`, `bin/rust_bridge.dll`,
`bin/aws_lc_fips_0_13_7_crypto.dll`,
`bin/aws_lc_fips_0_13_7_rust_wrapper.dll`, `bin/wintun.dll`
Files taken from the official Cloudflare WARP distribution. These files remain
subject to Cloudflare's terms and to any upstream component licenses applicable
to the shipped runtime.
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
Derived from the `zapret` / `winws` project:
`https://github.com/bol-van/zapret`
Redistribution or license status should be verified against upstream before
shipping outside the current project workflow.

## Scope

These notices apply only to the listed third-party components. All Nova-authored
code and materials remain governed by `LICENSE`.
