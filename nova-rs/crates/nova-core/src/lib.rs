//! Domain vocabulary shared by every Nova crate.
//!
//! Nothing here performs I/O. Every type is `Serialize`/`Deserialize` so that
//! persisted learner state, routing decisions and IPC payloads all speak the
//! same language without per-crate conversion shims.

#![forbid(unsafe_code)]

mod domain;
mod group;
mod transport;
mod verdict;

pub use domain::{Domain, DomainParseError};
pub use group::{Group, GroupId};
pub use transport::{Transport, TransportKind};
pub use verdict::{BlockSignature, Countermeasure, ProbeOutcome, Verdict};

/// Monotonic tick used across the crates instead of wall-clock time.
///
/// Wall-clock is unusable for decay maths: a laptop resuming from sleep would
/// otherwise expire every learned arm at once. All schedulers count elapsed
/// seconds of *process uptime* and persist that alongside a wall-clock stamp
/// used only for display.
pub type Seconds = u64;

/// Identifier for one DPI-bypass strategy candidate.
///
/// The string is the strategy's stable name from `strat/*.json` (e.g.
/// `hard_7_M65A`). It is used as a persistence key, so it must never be
/// rewritten for cosmetic reasons.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct StrategyId(pub String);

impl StrategyId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for StrategyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for StrategyId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}
