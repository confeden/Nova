//! Backend-independent representation of a DPI-bypass strategy.
//!
//! # Why an IR instead of argv strings
//!
//! Nova's strategy files currently store raw `winws` command lines. That works
//! exactly as long as there is one winws. There are now two, and their command
//! lines are not compatible: of the twenty options Nova uses, six survive
//! into zapret2 unchanged and fourteen are renamed, restructured, or replaced
//! by Lua function calls. Storing argv means the strategy corpus is welded to
//! one binary generation.
//!
//! So strategies are modelled by *intent* — "split the ClientHello at the SNI
//! marker, send a fake with a bad TCP checksum first, TTL 4" — and each backend
//! renders that intent into its own syntax. Adding zapret2 becomes a new
//! [`Emitter`] rather than a rewrite of the corpus, and the two can be compared
//! on the same machine by rendering one IR twice.
//!
//! # Current backend decision
//!
//! zapret v1 (`winws.exe`, bundled v72.12) remains the default. zapret2 is
//! genuinely better in places — notably CPU, where its payload-level WinDivert
//! filters and `--wf-tcp-empty=0` default cut usage substantially during heavy
//! downloads — but it is eight months old, has had critical dissection and
//! driver-teardown bugs recently, moves its Lua ABI, and would require
//! re-validating every strategy against real DPI because ported strategies do
//! not emit byte-identical packets. See `docs/adr/0001-zapret-backend.md`.
//!
//! The abstraction is being built now precisely because it is cheapest now, and
//! because it is what makes the decision reversible later.

#![forbid(unsafe_code)]

pub mod diversity;
mod emit;
pub mod evolve;
mod ir;

pub use diversity::{Archive, Deniability, Elite, Niche, Reach, Technique, niche_distance};
pub use emit::{Emitter, V1Emitter};
pub use evolve::{Mutator, Offspring, Operator, Palette};
pub use ir::{DesyncMode, Filter, Fooling, L3, L7, Payload, SplitPosition, Strategy, StrategyError, TtlPolicy};
