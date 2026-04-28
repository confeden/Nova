# NovaWFP

`NovaWFP` is the long-term per-app routing path for Nova.

Current objective:
- transparently intercept selected app traffic
- keep Telegram / AyuGram on a deterministic `WARP -> Opera -> direct` path
- reduce CPU and routing churn caused by the current user-space TUN pipeline

This directory is intentionally isolated from the active Nova runtime. Nothing here is enabled by default yet.

## Layout

- `shared/`
  Shared protocol and data structures for the future kernel driver and user-mode controller.
- `service/`
  User-mode WFP controller. This will own provider / sublayer registration, policy loading, diagnostics, and future driver IPC.
- `driver/`
  Kernel-mode skeleton for the future WFP callout / redirect driver.
- `config/`
  Example policy files for observer and redirect mode.

## Planned phases

1. Observer mode
   Register `NovaWFP` provider and sublayer, then collect per-app flow metadata for Telegram / AyuGram without redirecting traffic.

   Current practical state:
   - user-mode observer already works and shows real Telegram tuples
   - `nova.pyw` now starts the observer automatically and rotates `temp\NovaWfpObserver.log`
   - kernel driver now compiles into `build\driver\NovaWfpDriver.sys`
   - current driver logic is still observer-only: classify hook + event queue, no redirect yet
   - the remaining integration step is user-mode installation of matching callout/filter objects through the filter engine and then driver loading

2. TCP redirect mode
   Redirect selected TCP flows for Telegram / AyuGram into the preferred egress chain without relying on a legacy user-mode TUN path.

   Current practical state:
   - kernel decision preview already marks Telegram / AyuGram TCP as `would-redirect-warp`
   - a first local user-mode endpoint exists in `proxy/tcp_proxy.py`
   - the proxy already listens locally and reuses the existing `warp -> opera -> direct` transport chain
   - real WFP connect redirection into that proxy is the next integration step

3. UDP / calls mode
   Move voice and media UDP handling onto the `NovaWFP` path, removing the last heavy dependency on the current TUN strategy.

   Current engineering direction:
   - do not clone the TCP ALE local-proxy model for calls
   - for connected UDP flows, move toward packet modification / reinject
   - outbound UDP observation now also exists on `OUTBOUND_TRANSPORT_V4/V6`
   - keep a lightweight user-mode UDP transport for `warp-socks -> direct`
   - a first local UDP backend now exists in `proxy/udp_proxy.py`
   - the driver now also tracks recent Telegram/AyuGram UDP tuples and exposes lookup through `resolve-udp-flow`

4. Generalized app routing
   Extend the same model to Discord / WhatsApp only after Telegram is stable.

## Near-term integration plan

- keep the current Nova runtime unchanged
- build and validate `NovaWfpService` separately
- add observer-only startup from `nova.pyw`
- only after observer logs are correct, enable redirect mode behind a feature flag

## Observer usage

The observer can still be started manually:

`NovaWfpService observe`

Default observer log file:

`D:\Desktop\nova\temp\NovaWfpObserver.log`

Current observer filter:

- `Telegram.exe`
- `AyuGram.exe`
- their updater processes

## Build notes

`service/` is designed to build with the regular Windows SDK and MSVC / CMake.

`driver/` is a WDK target. The first local build path is now scripted:

`powershell -ExecutionPolicy Bypass -File .\NovaWFP\build_driver.ps1`

Current output:

- `NovaWFP\build\driver\NovaWfpDriver_v7.sys`
- `NovaWFP\build\driver\NovaWfpDriver_v7.pdb`

Current driver build assumptions:

- Visual Studio with MSVC tools
- Windows SDK
- WDK with kernel headers/libs
- x64 target
- `NDIS630` generic kernel-mode profile for `fwpsk.h`

Current load status:

- build works
- load is not wired into Nova yet
- this machine still has `testsigning = No`
- an unsigned/test driver will not load until the signing path is prepared and test-signing policy is enabled as needed

Development note:

- local development can use a machine that is already booted with relaxed driver-signature enforcement
- this is acceptable only for development and local diagnostics
- release builds must use a properly signed driver and a normal install path that does not require users to boot into a special mode

## Current dev tools

- kernel observer log: `D:\Desktop\nova\temp\NovaWfpObserver.log`
- session log: `D:\Desktop\nova\temp\nova_console.log`
- TCP proxy log: `D:\Desktop\nova\temp\NovaWfpTcpProxy.log`

Manual proxy start:

`py -3 .\NovaWFP\proxy\tcp_proxy.py`

Manual UDP backend start:

`py -3 .\NovaWFP\proxy\udp_proxy.py`

Manual UDP flow lookup:

`.\NovaWFP\build\service\Release\NovaWfpService_v7.exe resolve-udp-flow 127.0.0.1 50000`

Resolve tracked UDP flows for active Telegram / AyuGram sockets:

`.\NovaWFP\build\service\Release\NovaWfpService_v7.exe resolve-udp-app-flows`
