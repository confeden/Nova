//! I/O layer for the Telegram transparent relay's port 1372 listener.
//!
//! Layer 3 of the port out of `tgrelay/transparent_relay.py`. Layers 1-2 decided
//! *what* a client is and *where* it wants to go without touching a socket; this
//! crate drives those state machines over real ones.
//!
//! It stops at the moment the tunnel is agreed. Choosing an egress, dialling it
//! and pumping bytes is layer 4 — kept out so this layer can be tested end to end
//! against a loopback socket with no upstream in the picture, and so the piece
//! that still has to grow (egress selection, WSS routes, the health table) does
//! not drag the listener's tests along with it.
//!
//! Nothing here is wired into the running program yet. See `kb/tgrelay.md`.

#![forbid(unsafe_code)]

pub mod listener;

pub use listener::{accept_client, AcceptedClient, ClientMode, Rejected};
