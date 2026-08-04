//! Generating new strategies rather than only ranking the shipped ones.
//!
//! # Why generate at all
//!
//! Nova ships ~101 hand-written strategies. When an ISP deploys a DPI rule that
//! none of them defeats, the learner's honest answer is "nothing works" and it
//! stays there until a human authors a new one and ships an update. That is the
//! ceiling the corpus imposes, and it is the reason a purely selective learner
//! eventually stops improving.
//!
//! The parameter space, on the other hand, is enormous: seventeen desync modes,
//! seven fooling variants, split positions at seven protocol markers plus
//! arbitrary offsets, TTL fixed or auto with a delta and a clamp, ~105 fake
//! payload blobs, repeats, sequence overlap. The shipped corpus is a tiny,
//! human-chosen sample of it.
//!
//! # Why this is not a naive genetic algorithm
//!
//! Random recombination of zapret arguments overwhelmingly produces command
//! lines that are either rejected outright or semantically inert — `seqovl` on a
//! mode that never splits, `hostfakesplit-mod` on a mode that has no host fake.
//! Probing those costs exactly as much as probing a good candidate and teaches
//! nothing.
//!
//! So generation is constrained three ways, in increasing cost order:
//!
//! 1. **Structural validity** — [`Mutator`] only emits parameter combinations
//!    that the mode in force actually reads. Free, and it removes most of the
//!    garbage.
//! 2. **Novelty** — a candidate that is structurally identical to something
//!    already scored is discarded before it costs anything. Free.
//! 3. **Binary validation** — the caller runs `winws --dry-run` on the rendered
//!    argv. One process spawn, no network, and it is the ground truth for
//!    "would this even start". See `Validator` in the `nova-cli` crate.
//!
//! Only what survives all three is worth a network probe.
//!
//! # Where the parents come from
//!
//! Not from a random population. Parents are the arms the bandit already has
//! evidence for, weighted by their posterior mean — so evolution explores
//! *outward from what currently works on this network*, which is a far better
//! prior than the corpus average. A strategy that beats this ISP's DPI is
//! usually one parameter away from another that does too.

use nova_core::StrategyId;
use rand::Rng;
use rand::seq::{IndexedRandom, IteratorRandom};

use crate::ir::{AutoTtl, DesyncMode, FakeKind, Fooling, Payload, SplitPosition, Strategy};

/// Which knob a mutation turned. Recorded on the offspring so the learner can
/// credit or blame the operator, not just the individual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Ttl,
    AutoTtlRange,
    Fooling,
    SplitPosition,
    Seqovl,
    Repeats,
    FakePayload,
    Mode,
    Crossover,
}

impl Operator {
    pub const ALL: [Operator; 9] = [
        Operator::Ttl,
        Operator::AutoTtlRange,
        Operator::Fooling,
        Operator::SplitPosition,
        Operator::Seqovl,
        Operator::Repeats,
        Operator::FakePayload,
        Operator::Mode,
        Operator::Crossover,
    ];
}

/// A generated candidate together with its provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct Offspring {
    pub strategy: Strategy,
    pub operator: Operator,
    /// Ids of the strategies it was derived from.
    pub parents: Vec<StrategyId>,
}

/// Materials the generator is allowed to draw on.
///
/// Populated from what actually ships, so a generated strategy can never
/// reference a fake payload that is not on disk — a failure mode that would
/// only surface as an unexplained winws exit code.
#[derive(Debug, Clone, Default)]
pub struct Palette {
    /// TLS fake payloads available in `fake/`.
    pub tls_fakes: Vec<String>,
    /// QUIC fake payloads available in `fake/`.
    pub quic_fakes: Vec<String>,
    /// Subset of `tls_fakes` that winws can apply `--dpi-desync-fake-tls-mod`
    /// to, when this has been measured.
    ///
    /// Not every ClientHello can be modified. Four of Nova's sixty-nine are
    /// refused with *"could not mod tls"*, and it is not a size rule — a 208
    /// byte blob fails where a 517 byte one succeeds, so it depends on internal
    /// structure the generator cannot see. Hard-coding the four names would rot
    /// the moment the blob set changes, so the set is measured against the real
    /// binary instead; see `nova-cli`'s palette probe.
    ///
    /// `None` means "not measured", and the generator then imposes no
    /// constraint — an unmeasured palette must not silently shrink the search
    /// space.
    pub moddable_tls: Option<std::collections::BTreeSet<String>>,
    /// Relative selection weight per blob filename, from measured evidence.
    ///
    /// Empty means uniform. This is where the historical record earns its keep:
    /// Nova's own tallies score `tls_clienthello_www_google_com.bin` at 0.518
    /// over 2506 uses against `tls_clienthello_yandex_kz.bin` at 0.420 over
    /// 5949 — a two-proportion z of 8.3 — and yet every one of the 36 shipped
    /// `general` strategies carries the yandex blob, because uniform sampling
    /// gave the evidence no way to act. Weighting the draw is the whole fix.
    ///
    /// Weights bias, they do not exclude: [`Palette::weight_of`] floors every
    /// entry, so a payload can lose but never disappear. A blob that fails
    /// against today's DPI may be the one that works after the next ruleset
    /// update, and a search space that only shrinks cannot recover.
    pub blob_weights: std::collections::BTreeMap<String, f32>,
}

impl Palette {
    /// Split a directory listing of `fake/` into the payload classes the
    /// generator can substitute.
    ///
    /// Matching is on the filename because that is the only signal available
    /// without parsing the blobs, and zapret's own corpus follows the
    /// convention.
    pub fn from_fake_dir(names: impl IntoIterator<Item = String>) -> Self {
        let mut palette = Palette::default();
        for name in names {
            let lower = name.to_ascii_lowercase();
            if !lower.ends_with(".bin") {
                continue;
            }
            if lower.contains("quic") {
                palette.quic_fakes.push(name);
            } else if lower.contains("tls") || lower.contains("clienthello") {
                palette.tls_fakes.push(name);
            }
        }
        palette.tls_fakes.sort();
        palette.quic_fakes.sort();
        palette
    }

    pub fn is_empty(&self) -> bool {
        self.tls_fakes.is_empty() && self.quic_fakes.is_empty()
    }

    /// Minimum share any payload keeps, however badly it has scored.
    ///
    /// One in twenty draws is enough to notice a blob coming back into favour
    /// within a few hundred candidates, and little enough that a known-good one
    /// still dominates.
    const WEIGHT_FLOOR: f32 = 0.05;

    /// Selection weight for one blob: measured if known, neutral if not.
    ///
    /// Unmeasured returns 0.5 rather than the floor, so a newly shipped payload
    /// is explored on its merits instead of being suppressed for having no
    /// history — the failure mode that would let the palette ossify.
    pub fn weight_of(&self, name: &str) -> f32 {
        self.blob_weights.get(name).copied().unwrap_or(0.5).max(Self::WEIGHT_FLOOR)
    }
}

/// Produces new strategies from existing ones.
pub struct Mutator<R: Rng> {
    rng: R,
    palette: Palette,
    /// Serial number for generated names, so ids stay unique and sortable.
    counter: u64,
}

/// Split markers zapret understands, in the order the manual lists them.
const MARKERS: [&str; 7] = ["method", "host", "endhost", "sld", "endsld", "midsld", "sniext"];

/// Modes that consume `--dpi-desync-split-pos` and `--dpi-desync-split-seqovl`.
///
/// Emitting either on a mode outside this set produces an argument winws parses
/// and then ignores, which is worse than an error because it silently wastes a
/// probe.
const SPLITTING_MODES: [DesyncMode; 6] = [
    DesyncMode::MultiSplit,
    DesyncMode::MultiDisorder,
    DesyncMode::FakedSplit,
    DesyncMode::FakedDisorder,
    DesyncMode::HostFakeSplit,
    DesyncMode::Tamper,
];

impl<R: Rng> Mutator<R> {
    pub fn new(rng: R, palette: Palette) -> Self {
        Self { rng, palette, counter: 0 }
    }

    fn next_id(&mut self, prefix: &str) -> StrategyId {
        self.counter += 1;
        StrategyId::new(format!("evo_{prefix}_{:04}", self.counter))
    }

    /// Whether a strategy splits, and therefore whether split parameters mean
    /// anything for it.
    fn splits(strategy: &Strategy) -> bool {
        strategy.modes.iter().any(|m| SPLITTING_MODES.contains(m))
    }

    /// Produce one offspring from one or two parents.
    ///
    /// Returns `None` when the chosen operator has nothing to act on for this
    /// parent — e.g. a fake-payload mutation on a strategy carrying no fakes.
    /// The caller simply asks again; failing cheaply beats emitting a candidate
    /// identical to its parent.
    pub fn breed(&mut self, parents: &[&Strategy]) -> Option<Offspring> {
        let primary = *parents.first()?;
        let operator = if parents.len() >= 2 && self.rng.random_bool(0.25) {
            Operator::Crossover
        } else {
            *Operator::ALL[..8].choose(&mut self.rng)?
        };

        let mut child = primary.clone();
        let mut lineage = vec![primary.id.clone()];

        match operator {
            Operator::Ttl => {
                // Upper bound of 11 is inherited from the Python mutator
                // (`mutate_strategy`, nova.pyw:15354), which documents it as a
                // hard constraint alongside "do not change wssize" and "at most
                // two bin files". It is an empirical bound, not a protocol one:
                // above it the fake starts surviving past the DPI and reaching
                // the server, which breaks the connection instead of the
                // inspection. Worth keeping rather than rediscovering.
                let ttl = self.rng.random_range(1u8..=11);
                child.ttl.fixed = Some(ttl);
            }
            Operator::AutoTtlRange => {
                let delta = self.rng.random_range(-3i8..=3);
                let min = self.rng.random_range(2u8..=6);
                let max = self.rng.random_range(12u8..=32);
                child.ttl.auto = Some(AutoTtl { delta, min, max });
            }
            Operator::Fooling => {
                child.fooling = self.random_fooling();
            }
            Operator::SplitPosition => {
                if !Self::splits(&child) {
                    return None;
                }
                child.split_positions = self.random_split_positions();
            }
            Operator::Seqovl => {
                if !Self::splits(&child) {
                    return None;
                }
                child.seqovl = Some(self.random_seqovl());
            }
            Operator::Repeats => {
                child.repeats = Some(self.rng.random_range(1u32..=8));
            }
            Operator::FakePayload => {
                if child.fakes.is_empty() || self.palette.is_empty() {
                    return None;
                }
                let index = self.rng.random_range(0..child.fakes.len());
                let (kind, _) = child.fakes[index].clone();
                // A strategy carrying a TLS mod may only take a blob that winws
                // can actually modify, or it will refuse to start.
                let needs_moddable = kind == FakeKind::Tls
                    && child
                        .mods
                        .iter()
                        .any(|(target, value)| *target == crate::ir::ModTarget::TlsFake && value != "none");
                let moddable: Vec<String>;
                let pool = match (kind, needs_moddable, &self.palette.moddable_tls) {
                    (FakeKind::Quic, _, _) => &self.palette.quic_fakes,
                    (_, true, Some(allowed)) => {
                        moddable =
                            self.palette.tls_fakes.iter().filter(|n| allowed.contains(*n)).cloned().collect();
                        &moddable
                    }
                    _ => &self.palette.tls_fakes,
                };
                // Split-borrow deliberately: `pool` points into `self.palette`,
                // so the draw takes the rng and the palette as separate fields
                // rather than through `&mut self`.
                let pick = choose_weighted(&self.palette, &mut self.rng, pool)?;
                child.fakes[index] = (kind, Payload::File { path: format!("fake/{pick}"), offset: None });

                // If the palette has not been measured there is no safe way to
                // keep a mod paired with an arbitrary blob, so drop the mod
                // rather than emit a strategy that cannot start.
                if kind == FakeKind::Tls && needs_moddable && self.palette.moddable_tls.is_none() {
                    for (target, value) in &mut child.mods {
                        if *target == crate::ir::ModTarget::TlsFake {
                            *value = "none".to_owned();
                        }
                    }
                }
            }
            Operator::Mode => {
                // Substituting the primary mode is the most disruptive operator,
                // so parameters that belonged to the old mode are dropped rather
                // than carried over into a context that would ignore them.
                let mode = *SPLITTING_MODES.choose(&mut self.rng)?;
                child.modes = vec![mode];
                if mode != DesyncMode::HostFakeSplit {
                    child.mods.retain(|(target, _)| *target != crate::ir::ModTarget::HostFakeSplit);
                }
            }
            Operator::Crossover => {
                let other = parents[1];
                lineage.push(other.id.clone());
                // Filters stay with the primary: they decide *what traffic this
                // applies to*, and mixing them would change the meaning of the
                // comparison rather than the technique being compared.
                child.fooling = other.fooling.clone();
                child.ttl = other.ttl;
                if Self::splits(&child) && Self::splits(other) {
                    child.split_positions = other.split_positions.clone();
                    child.seqovl = other.seqovl.clone();
                }
            }
        }

        if !Self::splits(&child) {
            // Enforce the invariant unconditionally: an inherited or pre-existing
            // split parameter on a non-splitting mode is just as inert as a
            // freshly generated one.
            child.split_positions.clear();
            child.seqovl = None;
        }

        // Compare before renaming: the id is assigned last, so an equality test
        // afterwards would always pass and let through offspring identical to
        // the parent — a probe spent to re-learn something already known.
        if child == *primary {
            return None;
        }
        child.id = self.next_id(short_name(operator));
        Some(Offspring { strategy: child, operator, parents: lineage })
    }

    fn random_fooling(&mut self) -> Vec<Fooling> {
        const POOL: [Fooling; 5] = [
            Fooling::BadSum,
            Fooling::Md5Sig,
            Fooling::BadSeq { seq_delta: Fooling::DEFAULT_SEQ_DELTA, ack_delta: Fooling::DEFAULT_ACK_DELTA },
            Fooling::Timestamp { delta: Fooling::DEFAULT_TS_DELTA },
            Fooling::DataNoAck,
        ];
        // One or two. Zapret accepts more, but every added fooling mode is
        // another way for the fake to be rejected by something other than the
        // DPI, and the shipped corpus never uses more than two.
        let count = self.rng.random_range(1..=2usize);
        POOL.iter().copied().choose_multiple(&mut self.rng, count)
    }

    fn random_position(&mut self) -> SplitPosition {
        if self.rng.random_bool(0.6) {
            let marker = MARKERS.choose(&mut self.rng).copied().unwrap_or("host");
            SplitPosition::Marker { marker: marker.to_owned(), offset: self.rng.random_range(-4i32..=4) }
        } else {
            SplitPosition::Absolute(self.rng.random_range(1i32..=8))
        }
    }

    /// Sequence overlap accepts a narrower grammar than a split position.
    ///
    /// Learned from the binary rather than the manual: a generated candidate
    /// using a marker here was rejected with *"split seqovl supports only
    /// absolute positive positions"*. Encoding the constraint costs nothing and
    /// removes a whole class of candidates that could never start.
    fn random_seqovl(&mut self) -> SplitPosition {
        SplitPosition::Absolute(self.rng.random_range(1i32..=8))
    }

    fn random_split_positions(&mut self) -> Vec<SplitPosition> {
        let count = self.rng.random_range(1..=3usize);
        (0..count).map(|_| self.random_position()).collect()
    }
}

/// Draw a payload with probability proportional to its measured weight.
///
/// Linear scan over a cumulative sum. The palette is ~105 entries and this runs
/// once per generated candidate, so the O(n) is invisible next to the process
/// spawn that validates the result — and it avoids depending on a distribution
/// type for six lines of arithmetic.
///
/// A free function rather than a method so the caller can hand it the palette
/// and the rng as separate borrows; the candidate pool it draws from is itself
/// a slice of the palette.
fn choose_weighted<'a, R: Rng>(palette: &Palette, rng: &mut R, pool: &'a [String]) -> Option<&'a String> {
    if pool.is_empty() {
        return None;
    }
    let total: f32 = pool.iter().map(|n| palette.weight_of(n)).sum();
    if !total.is_finite() || total <= 0.0 {
        // No usable weights: fall back to uniform rather than refusing to
        // generate. A broken weight table must degrade the search, not stop it.
        return pool.choose(rng);
    }
    let mut point = rng.random_range(0.0..total);
    for name in pool {
        point -= palette.weight_of(name);
        if point <= 0.0 {
            return Some(name);
        }
    }
    // Only reachable through float accumulation error at the very end.
    pool.last()
}

fn short_name(op: Operator) -> &'static str {
    match op {
        Operator::Ttl => "ttl",
        Operator::AutoTtlRange => "att",
        Operator::Fooling => "foo",
        Operator::SplitPosition => "pos",
        Operator::Seqovl => "ovl",
        Operator::Repeats => "rep",
        Operator::FakePayload => "fak",
        Operator::Mode => "mod",
        Operator::Crossover => "crx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::{Emitter, V1Emitter};
    use rand::SeedableRng;

    fn palette() -> Palette {
        Palette::from_fake_dir(
            [
                "tls_clienthello_yandex_kz.bin",
                "tls_clienthello_www_google_com.bin",
                "quic_initial_www_google_com.bin",
                "quic_2.bin",
                "notes.txt",
            ]
            .into_iter()
            .map(str::to_owned),
        )
    }

    fn mutator(seed: u64) -> Mutator<rand::rngs::StdRng> {
        Mutator::new(rand::rngs::StdRng::seed_from_u64(seed), palette())
    }

    fn parent() -> Strategy {
        V1Emitter::parse_profile(
            StrategyId::new("hard_7_M65A"),
            &[
                "--filter-tcp=80,443",
                "--dpi-desync=hostfakesplit",
                "--dpi-desync-fake-tls-mod=rndsni",
                "--dpi-desync-hostfakesplit-mod=host=ya.ru,altorder=1",
                "--dpi-desync-fooling=badsum",
                "--dpi-desync-split-seqovl=1",
                "--dpi-desync-fake-tls=fake/tls_clienthello_yandex_kz.bin",
                "--dpi-desync-autottl=1",
                "--dpi-desync-ttl=8",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn other_parent() -> Strategy {
        V1Emitter::parse_profile(
            StrategyId::new("hard_12_M741"),
            &[
                "--filter-tcp=80,443",
                "--dpi-desync=multisplit",
                "--dpi-desync-fooling=ts,md5sig",
                "--dpi-desync-ttl=3",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn palette_classifies_shipped_blob_names() {
        let p = palette();
        assert_eq!(p.quic_fakes.len(), 2);
        assert_eq!(p.tls_fakes.len(), 2);
        assert!(!p.tls_fakes.iter().any(|n| n.contains("quic")), "quic blob leaked into the TLS pool");
        assert!(!p.tls_fakes.contains(&"notes.txt".to_owned()), "non-blob accepted");
    }

    #[test]
    fn every_offspring_renders_to_a_valid_looking_command_line() {
        let mut m = mutator(11);
        let (a, b) = (parent(), other_parent());
        let mut produced = 0;
        for _ in 0..400 {
            let Some(child) = m.breed(&[&a, &b]) else { continue };
            produced += 1;
            let argv = V1Emitter.emit_profile(&child.strategy).expect("offspring must be emittable");
            assert!(argv.iter().any(|x| x.starts_with("--filter-tcp")), "lost its filter: {argv:?}");
            assert!(argv.iter().any(|x| x.starts_with("--dpi-desync=")), "lost its mode: {argv:?}");
        }
        assert!(produced > 200, "generator produced only {produced} candidates in 400 attempts");
    }

    #[test]
    fn split_parameters_never_appear_on_a_non_splitting_mode() {
        // A `--dpi-desync-split-seqovl` on `fake` is parsed and then ignored,
        // which burns a probe to learn nothing. The invariant must hold no
        // matter which operator ran.
        let mut m = mutator(23);
        let fake_only = V1Emitter::parse_profile(
            StrategyId::new("boost_1"),
            &["--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-ttl=4"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();

        for _ in 0..500 {
            let Some(child) = m.breed(&[&fake_only]) else { continue };
            let argv = V1Emitter.emit_profile(&child.strategy).unwrap();
            let splits = SPLITTING_MODES.iter().any(|mode| child.strategy.modes.contains(mode));
            if !splits {
                assert!(
                    !argv.iter().any(|a| a.starts_with("--dpi-desync-split")),
                    "inert split parameter on {:?}: {argv:?}",
                    child.strategy.modes
                );
            }
        }
    }

    #[test]
    fn seqovl_is_always_an_absolute_positive_offset() {
        // winws rejects anything else: "split seqovl supports only absolute
        // positive positions". Discovered by validating generated candidates
        // against the real binary, so the test guards a fact rather than a guess.
        let mut m = mutator(83);
        let a = parent();
        let b = other_parent();
        let mut checked = 0;
        for _ in 0..600 {
            let Some(child) = m.breed(&[&a, &b]) else { continue };
            let Some(seqovl) = &child.strategy.seqovl else { continue };
            checked += 1;
            match seqovl {
                SplitPosition::Absolute(n) => assert!(*n > 0, "seqovl must be positive, got {n}"),
                SplitPosition::Marker { .. } => panic!("seqovl must not be a marker: {}", seqovl.render()),
            }
        }
        assert!(checked > 50, "only {checked} candidates carried a seqovl; test proves little");
    }

    #[test]
    fn generated_fake_payloads_only_reference_blobs_that_exist() {
        let mut m = mutator(31);
        let a = parent();
        let known: Vec<String> = palette().tls_fakes.iter().map(|n| format!("fake/{n}")).collect();
        for _ in 0..300 {
            let Some(child) = m.breed(&[&a]) else { continue };
            for (kind, payload) in &child.strategy.fakes {
                if *kind != FakeKind::Tls {
                    continue;
                }
                if let Payload::File { path, .. } = payload {
                    assert!(known.contains(path), "referenced a blob that is not on disk: {path}");
                }
            }
        }
    }

    #[test]
    fn a_measured_palette_keeps_mods_away_from_blobs_that_reject_them() {
        // winws answers "could not mod tls" for five of Nova's blobs. Once the
        // palette has been measured, a strategy carrying a mod must never be
        // given one of them.
        let mut palette = palette();
        let moddable: std::collections::BTreeSet<String> =
            ["tls_clienthello_yandex_kz.bin".to_owned()].into_iter().collect();
        palette.moddable_tls = Some(moddable.clone());

        let mut m = Mutator::new(rand::rngs::StdRng::seed_from_u64(97), palette);
        let a = parent(); // carries --dpi-desync-fake-tls-mod=rndsni
        let mut checked = 0;
        for _ in 0..400 {
            let Some(child) = m.breed(&[&a]) else { continue };
            let has_mod =
                child.strategy.mods.iter().any(|(t, v)| *t == crate::ir::ModTarget::TlsFake && v != "none");
            if !has_mod {
                continue;
            }
            for (kind, payload) in &child.strategy.fakes {
                if *kind != FakeKind::Tls {
                    continue;
                }
                if let Payload::File { path, .. } = payload {
                    let name = path.rsplit('/').next().unwrap_or(path);
                    checked += 1;
                    assert!(moddable.contains(name), "paired mod with unmoddable blob {name}");
                }
            }
        }
        assert!(checked > 20, "only {checked} modded candidates seen; test proves little");
    }

    #[test]
    fn an_unmeasured_palette_drops_the_mod_rather_than_risk_it() {
        // With no measurement there is no safe pairing, so the mod goes rather
        // than the strategy being emitted in a state that cannot start.
        let mut m = mutator(101);
        let a = parent();
        for _ in 0..400 {
            let Some(child) = m.breed(&[&a]) else { continue };
            if child.operator != Operator::FakePayload {
                continue;
            }
            for (target, value) in &child.strategy.mods {
                if *target == crate::ir::ModTarget::TlsFake {
                    assert_eq!(value, "none", "kept an unverifiable mod after swapping the blob");
                }
            }
        }
    }

    /// How often each TLS blob is chosen over `n` generated candidates.
    fn blob_histogram(palette: Palette, seed: u64, n: usize) -> std::collections::BTreeMap<String, usize> {
        let mut m = Mutator::new(rand::rngs::StdRng::seed_from_u64(seed), palette);
        let a = parent();
        let mut counts = std::collections::BTreeMap::new();
        for _ in 0..n {
            let Some(child) = m.breed(&[&a]) else { continue };
            if child.operator != Operator::FakePayload {
                continue;
            }
            for (kind, payload) in &child.strategy.fakes {
                if *kind != FakeKind::Tls {
                    continue;
                }
                if let Payload::File { path, .. } = payload {
                    let name = path.rsplit('/').next().unwrap_or(path).to_owned();
                    *counts.entry(name).or_insert(0) += 1;
                }
            }
        }
        counts
    }

    #[test]
    fn measured_evidence_shifts_which_payload_gets_generated() {
        // The concrete finding from Nova's own record: the google blob scores
        // 0.518 over 2506 uses, yandex 0.420 over 5949. With uniform sampling
        // that knowledge cannot reach the corpus at all.
        let mut weighted = palette();
        weighted.blob_weights = [
            ("tls_clienthello_www_google_com.bin".to_owned(), 0.518),
            ("tls_clienthello_yandex_kz.bin".to_owned(), 0.420),
        ]
        .into_iter()
        .collect();

        let uniform = blob_histogram(palette(), 5, 4000);
        let biased = blob_histogram(weighted, 5, 4000);
        let share = |h: &std::collections::BTreeMap<String, usize>| {
            let g = *h.get("tls_clienthello_www_google_com.bin").unwrap_or(&0) as f32;
            let y = *h.get("tls_clienthello_yandex_kz.bin").unwrap_or(&0) as f32;
            g / (g + y).max(1.0)
        };
        assert!((share(&uniform) - 0.5).abs() < 0.06, "unweighted draw was not uniform: {}", share(&uniform));
        assert!(share(&biased) > share(&uniform), "evidence did not move the generator");
    }

    #[test]
    fn a_badly_scored_payload_is_never_removed_from_the_search_space() {
        // Suppression must be a bias, not a ban: the blob that loses to today's
        // DPI may be the one that beats the next ruleset.
        let mut palette = palette();
        palette.blob_weights =
            [("tls_clienthello_yandex_kz.bin".to_owned(), 0.0)].into_iter().collect();
        assert!(palette.weight_of("tls_clienthello_yandex_kz.bin") > 0.0);
        let counts = blob_histogram(palette, 13, 6000);
        assert!(
            counts.get("tls_clienthello_yandex_kz.bin").copied().unwrap_or(0) > 0,
            "a zero-weighted payload fell out of the search space entirely"
        );
    }

    #[test]
    fn an_unmeasured_payload_outranks_a_measured_poor_one() {
        let mut palette = palette();
        palette.blob_weights =
            [("tls_clienthello_yandex_kz.bin".to_owned(), 0.10)].into_iter().collect();
        assert!(
            palette.weight_of("tls_clienthello_www_google_com.bin")
                > palette.weight_of("tls_clienthello_yandex_kz.bin"),
            "a blob with no history was ranked below one measured bad"
        );
    }

    #[test]
    fn offspring_is_never_identical_to_its_parent() {
        let mut m = mutator(47);
        let a = parent();
        for _ in 0..300 {
            if let Some(child) = m.breed(&[&a]) {
                let mut normalised = child.strategy.clone();
                normalised.id = a.id.clone();
                assert_ne!(normalised, a, "operator {:?} produced a clone", child.operator);
            }
        }
    }

    #[test]
    fn crossover_keeps_the_primary_parents_traffic_filter() {
        let mut m = mutator(59);
        let a = parent();
        let mut b = other_parent();
        b.filter.tcp_ports = vec!["8443".to_owned()];
        for _ in 0..400 {
            let Some(child) = m.breed(&[&a, &b]) else { continue };
            if child.operator == Operator::Crossover {
                assert_eq!(
                    child.strategy.filter.tcp_ports, a.filter.tcp_ports,
                    "crossover changed which traffic the strategy applies to"
                );
            }
        }
    }

    #[test]
    fn generation_is_reproducible_for_a_given_seed() {
        let a = parent();
        let run = |seed| {
            let mut m = mutator(seed);
            (0..50).filter_map(|_| m.breed(&[&a])).map(|c| c.strategy.id.to_string()).collect::<Vec<_>>()
        };
        assert_eq!(run(7), run(7), "same seed must replay identically");
        assert_ne!(run(7), run(8));
    }

    #[test]
    fn ids_are_unique_and_carry_their_operator() {
        let mut m = mutator(71);
        let a = parent();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let Some(child) = m.breed(&[&a]) else { continue };
            let id = child.strategy.id.to_string();
            assert!(seen.insert(id.clone()), "duplicate id {id}");
            assert!(id.starts_with(&format!("evo_{}_", short_name(child.operator))), "id {id} lost its provenance");
        }
    }
}
