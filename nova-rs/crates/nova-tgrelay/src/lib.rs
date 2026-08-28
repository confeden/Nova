//! Protocol core of the Telegram transparent relay (port 1372).
//!
//! This is the first slice of the port out of `tgrelay/transparent_relay.py`
//! (3941 lines). It carries only the decisions that need no I/O: what a
//! connecting client is, where a `CONNECT` line points, which health bucket a
//! WSS route belongs to, and where MTProto frame boundaries fall.
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
pub mod frame;
pub mod handshake;
pub mod http;
pub mod route;
pub mod sniff;
pub mod socks;

pub use authority::{split_http_authority, Authority};
pub use frame::{KeyStream, MsgSplitter, ProtoType, SplitterError};
pub use handshake::{HandshakeLimits, Input};
pub use route::WssRouteKind;
pub use sniff::{classify_client, looks_like_http_request, looks_like_tls_client_hello, ClientProtocol};
