//! Autonomous strategy selection for Nova.
//!
//! # Why this replaces the sweep
//!
//! The Python `StrategyLearner` evaluated candidates by sweeping: for each
//! group it walked the strategy pool, launched a probe against a live site for
//! every candidate, and kept whichever scored best. Cost grows with
//! `pool_size × groups × re-check_interval`, and because the sweep was
//! scheduled on a timer it paid that cost again on a network that had not
//! changed at all.
//!
//! This module inverts the design on four axes, and each one *removes* work:
//!
//! 1. **Evidence is mostly passive.** Every real connection the user makes is
//!    an observation of the arm currently in force. [`Learner::record`] accepts
//!    those for free. Synthetic probes exist only to break ties the passive
//!    stream cannot.
//! 2. **Exploration is event-driven, not periodic.** A Page–Hinkley detector
//!    ([`change::ChangePoint`]) watches the success rate of the arm in force.
//!    On a healthy network it never fires, so the steady-state probe budget is
//!    zero. The old timer-driven sweep could not express "nothing changed".
//! 3. **Selection is Thompson sampling, not enumeration.** One posterior draw
//!    per arm picks a winner in `O(pool)` cheap arithmetic and *zero* network.
//!    Only the winner is exercised. Regret is logarithmic in the number of
//!    trials rather than linear in the pool size.
//! 4. **Cold start is successive halving, and mostly skipped.** A brand-new
//!    context inherits priors from the closest known context
//!    ([`Learner::seed_from`]), so the usual case starts warm. When there is
//!    genuinely nothing to inherit, [`halving::Schedule`] spends
//!    `O(n log n)` probes instead of the sweep's `O(n × repeats)`.
//!
//! Non-stationarity — an ISP changing its DPI ruleset overnight — is handled by
//! exponential discounting of the posteriors, so old evidence fades without any
//! bookkeeping pass over the state.
//!
//! # CPU and memory
//!
//! State is `(context, group, arm) -> (α, β, last_tick)`, four bytes each for
//! the floats. A user with 12 groups, a 200-strategy pool and 4 remembered
//! networks costs under 120 KB. Selection touches only the arms of one group.

#![forbid(unsafe_code)]

pub mod change;
pub mod governor;
pub mod halving;
pub mod import;
pub mod posterior;

mod context;
mod learner;

pub use context::{NetworkContext, NetworkFingerprint};
pub use governor::{Activity, Governor, GovernorConfig};
pub use import::{GeneEvidence, ImportReport, PythonHistory};
pub use learner::{Decision, Learner, LearnerConfig, LearnerState};
pub use posterior::Posterior;
