# Nova Public Routing Plan

## Goal

Build a public Windows 10+ release that:

- does not require test mode;
- does not require buying EV signing for a custom kernel driver;
- gradually removes heavy `sing-box` usage;
- keeps transparent acceleration for selected apps;
- can later expand to games and other programs.

## Decision

Public release must not depend on `NovaWFP.sys`.

Public routing stack will be based on:

- signed third-party kernel components only;
- user-mode Nova routing/relay services;
- app profiles for Telegram, WhatsApp, and later other apps/games.

## Chosen Architecture

### Public release path

- `WinDivert` official signed driver:
  transparent interception/classification layer;
  process/flow/socket tracking for targeted apps.
- `Wintun` official signed driver:
  lightweight packet transport/TUN path where needed.
- `NovaRouter` user-mode service:
  owns policy, PID/app mapping, flow table, route decisions.
- `NovaTcpRelay` user-mode service:
  handles transparent TCP redirection and app-specific acceleration.
- `NovaUdpRelay` user-mode service:
  handles transparent UDP redirection for calls/media.

### Development / experimental path

- `NovaWFP` stays available as an internal R&D branch.
- It is not required for public releases.
- It remains useful for experiments, diagnostics, and future comparison.

## Why This Variant

### Why not ship `NovaWFP`

- A new custom kernel driver is the blocking point for public release.
- Without Microsoft driver signing, regular users cannot load it safely on normal Windows 10/11 systems.

### Why not DLL injection as the main core

- Injection is useful as an accelerator or fallback.
- It is too brittle as the primary routing architecture for Store apps, WebView2 apps, games, and future expansion.

### Why not keep `sing-box` as the permanent core

- It works, but it is heavier than necessary for the narrow app-routing problem.
- We already have app-specific acceleration logic that should live in smaller dedicated relays.

### Why `WinDivert + Wintun`

- Both can be shipped as signed third-party components.
- `WinDivert` gives transparent interception without requiring our own signed kernel driver.
- `Wintun` gives a lightweight transport/TUN building block when packet-mode routing is needed.
- This combination keeps the release compatible with normal Windows installs.

## System Model

### Routing layers

1. `NovaRouter`
   Watches app/process/flow activity and decides where traffic should go.

2. `NovaTcpRelay`
   Handles transparent TCP redirection for Telegram, WhatsApp, and later other apps.

3. `NovaUdpRelay`
   Handles transparent UDP voice/media flows.

4. `WARP/Wintun transport`
   Carries accelerated traffic when policy says traffic should use WARP.

### App profiles

Each app profile should declare:

- process names;
- path regexes;
- known CIDRs/domains;
- TCP strategy;
- UDP strategy;
- optional media/call special handling.

This profile model must later support:

- Telegram;
- WhatsApp;
- Discord;
- games;
- arbitrary user-added apps.

## Migration Phases

### Phase 1

Reduce `sing-box` to fallback/orchestration only.

- Keep current working Telegram/WhatsApp behavior.
- Move app-specific TCP logic into Nova relays.
- Move app-specific UDP logic into Nova relays where stable.

### Phase 2

Introduce `WinDivert` public path.

- Build a `NovaRouter` backend on top of `WinDivert`.
- Track per-app flows in user mode.
- Redirect selected TCP/UDP flows to local relays.

### Phase 3

Shrink `sing-box` to optional compatibility mode.

- Keep it only for fallback and unsupported scenarios.
- Default path for supported apps should no longer depend on it.

### Phase 4

Expose generic app/game routing in settings.

- Add user-defined profiles.
- Add selectable route modes:
  `direct`, `warp`, `opera`, `relay`, `auto`.

## Release Rule

If a feature requires `NovaWFP.sys`, it is not part of the default public release path.

Public release features must work with:

- standard Windows 10/11 x64;
- no test mode;
- no custom driver signing requirement from Nova.
