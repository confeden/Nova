//! Keeping a strategy ladder behaviourally diverse instead of merely top-ranked.
//!
//! # The failure this exists to prevent
//!
//! Nova's Python evolver selects parents by taking the top N strategies by
//! score, mutates one gene of each, scores the offspring, and replaces the
//! corpus with the new top N. That is a hill climber with no diversity
//! pressure, and it does what hill climbers with no diversity pressure always
//! do: it converges.
//!
//! The shipped `strat/general.json` is the end state. Thirty-six strategies,
//! and only four genes vary across all of them — mode, fooling, TLS mod and
//! TTL. Every one carries the same `--dpi-desync-split-seqovl=1`, the same
//! `--dpi-desync-autottl=1`, the same `host=ya.ru,altorder=1`, and the same
//! fake payload. Thirty-six candidates sampling one small neighbourhood.
//!
//! The measured consequence: across 3316 scored `general` strategies the twelve
//! `hard_N` families average 30.4–36.9 with maxima 85–98, and the plain
//! `general` family averages 33.5 with a maximum of 98. The slots are
//! statistically indistinguishable, because they are all descendants of the
//! same twelve clones. A ladder of twelve rungs that are the same rung costs
//! twelve times the probes of one rung and finds twelve times nothing.
//!
//! # What replaces it
//!
//! An elite archive over a coarse behaviour space, in the MAP-Elites sense.
//! Each strategy is assigned a [`Niche`] describing *how it attacks the DPI*,
//! not how well it scored, and the archive keeps the single best occupant of
//! each niche. Selecting a ladder then means taking the best of each of the top
//! niches, so every rung is guaranteed to fail differently from the others.
//!
//! Diversity here is not an aesthetic preference. Two strategies in the same
//! niche fail to the same DPI rule, so testing the second after the first has
//! failed is a wasted probe. Two in different niches do not, which is the only
//! thing that makes a sequential ladder worth walking.

use std::collections::BTreeMap;

use nova_core::StrategyId;

use crate::ir::{DesyncMode, Fooling, Strategy};

/// How a strategy reaches (or fails to reach) the inspector.
///
/// Three coarse axes, chosen because they are the ones that decide *which* DPI
/// implementations a strategy defeats. Finer axes — exact split offset, exact
/// repeat count — change the odds against a given DPI but not the class of DPI,
/// so putting them in the descriptor would split the grid into cells that fail
/// identically and reintroduce the problem this module exists to solve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Niche {
    pub technique: Technique,
    pub reach: Reach,
    pub deniability: Deniability,
}

/// The structural trick, collapsed to the families that behave alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Technique {
    /// Inject a fabricated packet ahead of the real one.
    Inject,
    /// Cut the payload so the inspected field never appears whole.
    Segment,
    /// Cut it *and* put a decoy in the first piece.
    DecoySegment,
    /// Move the inspected bytes out of the first packet entirely.
    Relocate,
    /// Attack the IP layer rather than the payload.
    Fragment,
    /// Anything else the corpus carries.
    Other,
}

/// How far the desync packet is meant to travel.
///
/// The single most important axis: a fake that dies before the DPI does
/// nothing, and one that survives past it corrupts the real connection. Every
/// DPI sits at a different hop count, so this is where portability between
/// networks actually lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reach {
    /// Fixed TTL of 4 or less — dies early, defeats only close inspectors.
    Short,
    /// Fixed TTL 5–8, the common middle ground.
    Medium,
    /// Fixed TTL 9 or more.
    Long,
    /// Derived from the measured hop count rather than fixed. Behaviourally
    /// distinct from any fixed value because it re-targets per destination.
    Adaptive,
    /// No TTL control at all.
    Unbounded,
}

/// Why the destination ignores the fake while the DPI does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Deniability {
    /// Corrupt checksum or bogus MD5 option — dropped by the NIC or the stack.
    Malformed,
    /// Out-of-window sequence or a rewound timestamp — dropped by TCP.
    OutOfOrder,
    /// Both classes at once.
    Mixed,
    /// The fake is valid; only TTL keeps it from arriving.
    Ttl,
}

impl Niche {
    pub fn of(strategy: &Strategy) -> Self {
        Self {
            technique: Technique::of(strategy),
            reach: Reach::of(strategy),
            deniability: Deniability::of(strategy),
        }
    }
}

impl Technique {
    /// How far a technique goes in restructuring the connection.
    ///
    /// Declared explicitly rather than derived from the enum's `Ord`, which
    /// orders by declaration position and would make `Other` — the fallback —
    /// outrank every real technique.
    fn severity(self) -> u8 {
        match self {
            Technique::Other => 0,
            Technique::Inject => 1,
            Technique::Fragment => 2,
            Technique::Segment => 3,
            Technique::DecoySegment => 4,
            Technique::Relocate => 5,
        }
    }

    fn of(strategy: &Strategy) -> Self {
        // The most disruptive mode present wins, because that is the one whose
        // failure mode dominates: a profile that both fakes and splits is
        // defeated by whatever defeats its splitting.
        let mut best = Technique::Other;
        for mode in &strategy.modes {
            let t = match mode {
                DesyncMode::Fake | DesyncMode::FakeKnown | DesyncMode::Rst | DesyncMode::RstAck => {
                    Technique::Inject
                }
                DesyncMode::MultiSplit | DesyncMode::MultiDisorder | DesyncMode::Tamper => Technique::Segment,
                DesyncMode::FakedSplit | DesyncMode::FakedDisorder => Technique::DecoySegment,
                DesyncMode::HostFakeSplit | DesyncMode::SynData | DesyncMode::SynAck => Technique::Relocate,
                DesyncMode::IpFrag1
                | DesyncMode::IpFrag2
                | DesyncMode::HopByHop
                | DesyncMode::DestOpt
                | DesyncMode::UdpLen => Technique::Fragment,
            };
            if t.severity() > best.severity() {
                best = t;
            }
        }
        best
    }
}

impl Reach {
    fn of(strategy: &Strategy) -> Self {
        // Auto wins over fixed when both are present: v1 applies the measured
        // hop count and treats the fixed value as the fallback, so the
        // behaviour on any given connection is the adaptive one.
        if strategy.ttl.auto.is_some() || strategy.ttl.auto6.is_some() {
            return Reach::Adaptive;
        }
        match strategy.ttl.fixed.or(strategy.ttl.fixed6) {
            None => Reach::Unbounded,
            Some(n) if n <= 4 => Reach::Short,
            Some(n) if n <= 8 => Reach::Medium,
            Some(_) => Reach::Long,
        }
    }
}

impl Deniability {
    fn of(strategy: &Strategy) -> Self {
        let mut malformed = false;
        let mut out_of_order = false;
        for f in &strategy.fooling {
            match f {
                Fooling::BadSum | Fooling::Md5Sig | Fooling::HopByHop | Fooling::HopByHop2 => malformed = true,
                Fooling::BadSeq { .. } | Fooling::Timestamp { .. } | Fooling::DataNoAck => out_of_order = true,
            }
        }
        match (malformed, out_of_order) {
            (true, true) => Deniability::Mixed,
            (true, false) => Deniability::Malformed,
            (false, true) => Deniability::OutOfOrder,
            (false, false) => Deniability::Ttl,
        }
    }
}

/// The best-known strategy in each niche.
#[derive(Debug, Clone, Default)]
pub struct Archive {
    cells: BTreeMap<Niche, Elite>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Elite {
    pub id: StrategyId,
    pub fitness: f32,
}

impl Archive {
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer a strategy to the archive. Returns true if it took the cell.
    ///
    /// Ties go to the incumbent: swapping between equals costs a winws restart
    /// and buys nothing.
    pub fn insert(&mut self, strategy: &Strategy, fitness: f32) -> bool {
        let niche = Niche::of(strategy);
        match self.cells.get(&niche) {
            Some(existing) if existing.fitness >= fitness => false,
            _ => {
                self.cells.insert(niche, Elite { id: strategy.id.clone(), fitness });
                true
            }
        }
    }

    pub fn len(&self) -> usize {
        self.cells.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    pub fn occupied(&self) -> impl Iterator<Item = (&Niche, &Elite)> {
        self.cells.iter()
    }

    /// The ladder: up to `n` strategies, each from a different niche, best
    /// first.
    ///
    /// This is the replacement for "top 12 by score". The two agree only when
    /// the population is already diverse; when it has collapsed, this returns
    /// the handful of genuinely distinct options and says so by returning fewer
    /// than `n`, which is the honest answer and the one that stops the caller
    /// from spending twelve probes to test four ideas.
    pub fn ladder(&self, n: usize) -> Vec<Elite> {
        let mut elites: Vec<Elite> = self.cells.values().cloned().collect();
        elites.sort_by(|a, b| b.fitness.total_cmp(&a.fitness).then_with(|| a.id.cmp(&b.id)));
        elites.truncate(n);
        elites
    }

    /// Fraction of a population that survives niching, in `[0,1]`.
    ///
    /// A diagnostic for the collapse this module detects: the shipped
    /// `general` corpus scores about 0.4 (36 strategies, ~14 niches), and a
    /// healthy one stays near 1.
    pub fn coverage(&self, population: usize) -> f32 {
        if population == 0 {
            return 0.0;
        }
        self.cells.len() as f32 / population as f32
    }
}

/// Number of descriptor axes on which two strategies differ, 0–3.
///
/// Used when choosing a parent to mutate: breeding from two members of the same
/// niche re-explores ground already covered, so a generator that wants coverage
/// should prefer distant parents.
pub fn niche_distance(a: &Strategy, b: &Strategy) -> u8 {
    let (x, y) = (Niche::of(a), Niche::of(b));
    u8::from(x.technique != y.technique)
        + u8::from(x.reach != y.reach)
        + u8::from(x.deniability != y.deniability)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::V1Emitter;

    fn parse(id: &str, args: &[&str]) -> Strategy {
        V1Emitter::parse_profile(
            StrategyId::new(id),
            &args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        )
        .unwrap()
    }

    /// Two members of the collapsed shipped corpus, differing only in TLS mod.
    fn shipped_pair() -> (Strategy, Strategy) {
        let base = |id, m: &str| {
            parse(
                id,
                &[
                    "--filter-tcp=80,443",
                    "--dpi-desync=hostfakesplit",
                    m,
                    "--dpi-desync-hostfakesplit-mod=host=ya.ru,altorder=1",
                    "--dpi-desync-fooling=ts",
                    "--dpi-desync-split-seqovl=1",
                    "--dpi-desync-fake-tls=fake/tls_clienthello_yandex_kz.bin",
                    "--dpi-desync-autottl=1",
                    "--dpi-desync-ttl=6",
                ],
            )
        };
        (base("hard_10_MB90", "--dpi-desync-fake-tls-mod=rnd"), base("hard_10_M36E", "--dpi-desync-fake-tls-mod=rndsni"))
    }

    #[test]
    fn the_shipped_clones_land_in_one_niche() {
        // The whole point. These two are different rows in strat/general.json
        // and different arms in the score table, and they are the same idea.
        let (a, b) = shipped_pair();
        assert_eq!(Niche::of(&a), Niche::of(&b));
        assert_eq!(niche_distance(&a, &b), 0);
    }

    #[test]
    fn a_ladder_of_clones_collapses_to_one_rung() {
        let (a, b) = shipped_pair();
        let mut archive = Archive::new();
        archive.insert(&a, 90.0);
        archive.insert(&b, 88.0);
        assert_eq!(archive.len(), 1, "two clones occupied two cells");
        let ladder = archive.ladder(12);
        assert_eq!(ladder.len(), 1, "asked for 12 rungs, got {} — must not pad with clones", ladder.len());
        assert_eq!(ladder[0].id, a.id, "kept the weaker of the two");
    }

    #[test]
    fn genuinely_different_techniques_get_their_own_rungs() {
        let inject = parse("a", &["--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-ttl=4"]);
        let segment = parse("b", &["--filter-tcp=443", "--dpi-desync=multisplit", "--dpi-desync-ttl=4"]);
        let relocate = parse("c", &["--filter-tcp=443", "--dpi-desync=hostfakesplit", "--dpi-desync-ttl=4"]);
        let mut archive = Archive::new();
        for (s, f) in [(&inject, 50.0), (&segment, 70.0), (&relocate, 60.0)] {
            archive.insert(s, f);
        }
        assert_eq!(archive.len(), 3);
        let ladder = archive.ladder(12);
        assert_eq!(ladder.iter().map(|e| e.id.to_string()).collect::<Vec<_>>(), vec!["b", "c", "a"]);
    }

    #[test]
    fn the_dominant_technique_wins_over_a_co_present_weaker_one() {
        // A profile that both injects and relocates is defeated by whatever
        // defeats the relocation, so that is the failure mode it must be filed
        // under. Guards the severity ordering, which cannot come from the
        // enum's declaration order because the fallback is declared last.
        let mixed = parse(
            "m",
            &["--filter-tcp=443", "--dpi-desync=fake,hostfakesplit", "--dpi-desync-ttl=4"],
        );
        assert_eq!(Technique::of(&mixed), Technique::Relocate);
        let plain = parse("p", &["--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-ttl=4"]);
        assert_eq!(Technique::of(&plain), Technique::Inject);
    }

    #[test]
    fn ttl_buckets_separate_strategies_that_reach_different_hops() {
        let short = parse("s", &["--filter-tcp=443", "--dpi-desync=multisplit", "--dpi-desync-ttl=3"]);
        let medium = parse("m", &["--filter-tcp=443", "--dpi-desync=multisplit", "--dpi-desync-ttl=6"]);
        let long = parse("l", &["--filter-tcp=443", "--dpi-desync=multisplit", "--dpi-desync-ttl=11"]);
        assert_eq!(Reach::of(&short), Reach::Short);
        assert_eq!(Reach::of(&medium), Reach::Medium);
        assert_eq!(Reach::of(&long), Reach::Long);
        assert_eq!(niche_distance(&short, &long), 1);
    }

    #[test]
    fn adaptive_ttl_is_its_own_behaviour_not_a_bucket() {
        // autottl re-targets per destination, so it cannot be filed under any
        // fixed bucket even though a fixed value is also present.
        let auto = parse(
            "a",
            &["--filter-tcp=443", "--dpi-desync=multisplit", "--dpi-desync-autottl=1", "--dpi-desync-ttl=6"],
        );
        assert_eq!(Reach::of(&auto), Reach::Adaptive);
    }

    #[test]
    fn fooling_classes_split_by_what_drops_the_fake() {
        let checksum = parse("c", &["--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-fooling=badsum"]);
        let sequence = parse("s", &["--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-fooling=badseq"]);
        let both = parse("b", &["--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-fooling=badsum,badseq"]);
        let none = parse("n", &["--filter-tcp=443", "--dpi-desync=fake"]);
        assert_eq!(Deniability::of(&checksum), Deniability::Malformed);
        assert_eq!(Deniability::of(&sequence), Deniability::OutOfOrder);
        assert_eq!(Deniability::of(&both), Deniability::Mixed);
        assert_eq!(Deniability::of(&none), Deniability::Ttl);
    }

    #[test]
    fn a_better_occupant_takes_the_cell_but_an_equal_one_does_not() {
        let (a, b) = shipped_pair();
        let mut archive = Archive::new();
        assert!(archive.insert(&a, 50.0));
        assert!(archive.insert(&b, 80.0), "a clearly better strategy was refused");
        assert_eq!(archive.ladder(1)[0].id, b.id);
        assert!(!archive.insert(&a, 80.0), "tie must not cost a restart");
    }

    #[test]
    fn coverage_reports_the_collapse() {
        let (a, b) = shipped_pair();
        let mut archive = Archive::new();
        archive.insert(&a, 90.0);
        archive.insert(&b, 88.0);
        assert!((archive.coverage(2) - 0.5).abs() < 1e-6);
        assert_eq!(Archive::new().coverage(0), 0.0);
    }
}
