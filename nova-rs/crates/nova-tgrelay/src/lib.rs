//! Protocol core of the Telegram transparent relay (port 1372).
//!
//! This is the decision half of the port out of `tgrelay/transparent_relay.py`
//! (3941 lines). It carries only what needs no I/O: what a connecting client is,
//! where a `CONNECT` line points, which health bucket a WSS route belongs to,
//! where MTProto frame boundaries fall, and when a tunnel that has gone quiet
//! should be cut.
//!
//! Nothing here is wired into the running program yet, and that is on purpose.
//! The Python relay owns an asyncio event loop whose `IocpProactor` throws
//! `InvalidStateError` for reasons three investigations failed to establish
//! (`kb/open-issues.md#o2`); it is mitigated by resuming the loop, not fixed.
//! Removing that loop is the point of the port, but the data path has to be
//! moved in one piece to remove it, and this layer is the foundation that piece
//! stands on — parsers first, with tests, then the tokio listener and bridge,
//! then a flag to switch over.
//!
//! Behaviour is ported deliberately, not approximately: every rule below has a
//! matching test, and the ones that came from a real incident say so.

#![forbid(unsafe_code)]

pub mod authority;
pub mod bridge;
pub mod cfdomains;
pub mod dc;
pub mod divert;
pub mod egress;
pub mod frame;
pub mod handshake;
pub mod http;
pub mod persona;
pub mod pool;
pub mod prober;
pub mod race;
pub mod retry;
pub mod route;
pub mod sni;
pub mod sniff;
pub mod socks;
pub mod socks_addr;
pub mod supervisor;
pub mod udp;
pub mod wsbridge;
pub mod wsframe;
pub mod wsroute;
pub mod wss;

pub use authority::{split_http_authority, Authority};
pub use bridge::{BridgeEnd, BridgeOutcome, Counters, FirstDown, FirstDownGuard, Side, TrafficStats};
pub use cfdomains::CfDomainHealth;
pub use dc::{domain_dc, likely_media_target, preferred_ws_target, target_dc_hint};
pub use divert::{match_entry, DivertEntry, Peer};
pub use egress::{Dc, Egress, NativeHealth, PenaltyBox, ProxyProtocol, RoutePreference};
pub use frame::{KeyStream, MsgSplitter, ProtoType, SplitterError};
pub use handshake::{HandshakeLimits, Input};
pub use persona::{judge, upgrade_request, Persona, UpgradeResponse, UpgradeVerdict};
pub use pool::{PoolKey, Warm, WarmPool};
pub use prober::{pending as pending_probes, Probe, SeenDcs};
pub use race::{plan as race_plan, RacePlan};
pub use route::WssRouteKind;
pub use sni::{retires_substitution, NeutralSni, SniFailure};
pub use sniff::{classify_client, looks_like_http_request, looks_like_tls_client_hello, ClientProtocol};
pub use socks_addr::{decode_authority, encode_target, AddrError};
pub use supervisor::{Restart, RestartPolicy};
pub use wsbridge::{FirstDownWatchdog, ReplayBuffer, WatchdogStep, WsBridgeOutcome, WsProgress};
pub use wsframe::{build_frame, parse_header, FrameError, Incoming, MessageReader, Opcode};
pub use wss::{CircuitContext, FirstByteCircuit, RecentGood};
