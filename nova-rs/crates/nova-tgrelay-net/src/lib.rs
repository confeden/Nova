//! I/O layer for the Telegram transparent relay's port 1372 listener.
//!
//! Layers 3-4 of the port out of `tgrelay/transparent_relay.py`. Layers 1-2
//! decided *what* a client is and *where* it wants to go without touching a
//! socket; this crate drives those state machines over real ones.
//!
//! - [`listener`] takes a connection as far as "your tunnel is open".
//! - [`dial`] opens the far half through the first egress that works.
//! - [`bridge`] carries bytes between the two until one of them stops.
//!
//! That is the whole TCP path. What is still Python is the WSS one — route
//! selection over Cloudflare, the WebSocket upgrade and `_bridge_ws` — and the
//! supervisor that owns the listening socket.
//!
//! Nothing here is wired into the running program yet. See `kb/tgrelay.md`.

#![forbid(unsafe_code)]

pub mod attempt;
pub mod bridge;
pub mod connect;
pub mod cf_token;
pub mod dial;
pub mod health_cache;
pub mod keystream;
pub mod listener;
pub mod probe;
pub mod racer;
pub mod supervisor;
pub mod terminator;
pub mod upgrade;
pub mod wsbridge;
pub mod wsconn;

pub use attempt::{attempt_budget, charge, connect_first_working, Charge, Failure, Opened, WalkError};
pub use bridge::{bridge_streams, BridgeOptions};
pub use connect::{connect_once, Candidate, OsWsKey, Tunnel};
pub use cf_token::{build_token, subprotocol_header};
pub use dial::{dial, DialError, Dialled};
pub use terminator::{open_shaped_stream, Shaped, TerminatorConfig, TerminatorError};
pub use upgrade::{check_accept, expected_accept, AcceptCheck};
pub use probe::{build_native_probe, ProbeRandom};
pub use racer::{race, Candidates, RaceOutcome, Won};
pub use supervisor::{serve, supervise, RunOutcome, ServeOutcome};
pub use wsbridge::{bridge_ws, WsBridgeOptions};
pub use wsconn::{WsConnection, WsError};
pub use health_cache::{restore, snapshot, HealthCache};
pub use keystream::{splitter_from_init, AesCtrKeyStream};
pub use listener::{accept_client, AcceptedClient, ClientMode, Rejected};
