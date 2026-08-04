//! Beta posterior over one arm's success probability, with time discounting.

use nova_core::Seconds;
use rand::Rng;
use rand_distr::Distribution;

/// Beta(α, β) belief about "this strategy makes a connection work".
///
/// Discounting is applied lazily: instead of a background pass that decays every
/// arm on a timer, each arm records when it was last touched and folds the decay
/// in on the next read or write. An arm nobody has used for a week costs nothing
/// until someone asks about it.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Posterior {
    /// Successes + prior. Never below [`Posterior::PRIOR`].
    alpha: f32,
    /// Failures + prior. Never below [`Posterior::PRIOR`].
    beta: f32,
    /// Uptime tick at which `alpha`/`beta` were last brought up to date.
    updated_at: Seconds,
}

impl Posterior {
    /// Jeffreys prior. Beta(0.5, 0.5) is the reference prior for a Bernoulli
    /// parameter: it is far less committal near 0 and 1 than the uniform
    /// Beta(1,1), which matters because most arms here are genuinely near-zero
    /// or near-one and we want the first observation to move the belief hard.
    pub const PRIOR: f32 = 0.5;

    /// Evidence half-life in seconds. Six hours: long enough that a strategy
    /// proven this morning is still trusted this afternoon, short enough that an
    /// overnight DPI ruleset change is forgotten by the time the user wakes up.
    pub const HALF_LIFE: f32 = 6.0 * 3600.0;

    /// Ceiling on total evidence mass. Without it, an arm that has served a
    /// million successful connections becomes unfalsifiable and the learner can
    /// never react to it breaking. Capping at 200 pseudo-observations keeps the
    /// posterior responsive: ~15 consecutive failures visibly move it.
    pub const MAX_MASS: f32 = 200.0;

    pub fn new(at: Seconds) -> Self {
        Self { alpha: Self::PRIOR, beta: Self::PRIOR, updated_at: at }
    }

    /// Posterior seeded from another context's belief, deliberately weakened.
    ///
    /// Transfer is worth a lot at cold start and is actively harmful if trusted
    /// fully: a strategy that beats one ISP's DPI may be exactly the one the
    /// next ISP fingerprints. Keeping the mean but shrinking the mass to
    /// `TRANSFER_MASS` says "start here, but one bad result overrules me".
    pub fn transferred_from(source: &Posterior, at: Seconds) -> Self {
        const TRANSFER_MASS: f32 = 4.0;
        // Clamping before splitting the mass, rather than flooring alpha and
        // beta afterwards, is what preserves the mean: flooring the smaller of
        // the two silently drags the ratio back toward 0.5 by as much as 0.1,
        // which is enough to reorder two adjacent candidates.
        let mean = source.mean_at(at).clamp(0.02, 0.98);
        Self { alpha: mean * TRANSFER_MASS, beta: (1.0 - mean) * TRANSFER_MASS, updated_at: at }
    }

    /// Evidence mass granted to an imported historical record.
    ///
    /// Calibrated against [`crate::LearnerConfig::burst_budget`], which is 12:
    /// an arm imported at mean 0.98 carries α=11.76, β=0.24, so one full
    /// exploration burst of contrary results drags it to 0.49. That is the
    /// property worth having — the history ranks the pool on the first run and
    /// then loses every argument with today's measurements.
    pub const IMPORT_MASS: f32 = 12.0;

    /// Belief reconstructed from an aggregate historical record.
    ///
    /// `successes` need not be an integer: the Python record stores a sum of
    /// per-run success *rates* for some of its tables, which is the same
    /// quantity at a different scale.
    ///
    /// Returns `None` when `trials` is zero. That case is not a
    /// zero-information arm to be imported at the prior — it is a corrupt row,
    /// and in the shipped data there are 213 of them carrying a non-zero score
    /// with no denominator. Importing those as `score`-out-of-`score` would
    /// assert a perfect record for arms that were never measured.
    pub fn from_record(successes: f32, trials: f32, at: Seconds) -> Option<Self> {
        // Spelled out rather than as `!(trials > 0.0)` so the NaN case is
        // visibly handled: a NaN denominator fails `is_finite` and is refused,
        // where a bare comparison would silently fall through.
        if !trials.is_finite() || trials <= 0.0 || !successes.is_finite() {
            return None;
        }
        // Same clamp-then-split as `transferred_from`, for the same reason: it
        // preserves the mean, where flooring α and β afterwards would pull it
        // back toward 0.5 by enough to reorder adjacent candidates.
        let mean = (successes / trials).clamp(0.02, 0.98);
        let mass = trials.min(Self::IMPORT_MASS);
        Some(Self { alpha: mean * mass, beta: (1.0 - mean) * mass, updated_at: at })
    }

    /// Decay factor to apply for `elapsed` seconds of ageing.
    fn decay(elapsed: Seconds) -> f32 {
        if elapsed == 0 {
            return 1.0;
        }
        (-(elapsed as f32) * std::f32::consts::LN_2 / Self::HALF_LIFE).exp()
    }

    /// Bring `alpha`/`beta` forward to `now`, shrinking both toward the prior.
    fn age(&mut self, now: Seconds) {
        let elapsed = now.saturating_sub(self.updated_at);
        if elapsed == 0 {
            return;
        }
        let k = Self::decay(elapsed);
        self.alpha = Self::PRIOR + (self.alpha - Self::PRIOR) * k;
        self.beta = Self::PRIOR + (self.beta - Self::PRIOR) * k;
        self.updated_at = now;
    }

    /// Fold in one observation.
    ///
    /// `weight` lets a deliberate synthetic probe count for more than a single
    /// incidental page load, and lets a group with noisy passive traffic count
    /// for less.
    pub fn observe(&mut self, success: bool, weight: f32, now: Seconds) {
        debug_assert!(weight > 0.0);
        self.age(now);
        if success {
            self.alpha += weight;
        } else {
            self.beta += weight;
        }
        let mass = self.alpha + self.beta;
        if mass > Self::MAX_MASS {
            let scale = Self::MAX_MASS / mass;
            self.alpha = Self::PRIOR + (self.alpha - Self::PRIOR) * scale;
            self.beta = Self::PRIOR + (self.beta - Self::PRIOR) * scale;
        }
    }

    /// Expected success probability as of `now`.
    pub fn mean_at(&self, now: Seconds) -> f32 {
        let mut copy = *self;
        copy.age(now);
        copy.alpha / (copy.alpha + copy.beta)
    }

    /// Total evidence mass as of `now`; a proxy for confidence.
    pub fn mass_at(&self, now: Seconds) -> f32 {
        let mut copy = *self;
        copy.age(now);
        copy.alpha + copy.beta - 2.0 * Self::PRIOR
    }

    /// Draw a sample of the success probability — the Thompson sampling step.
    pub fn sample(&self, now: Seconds, rng: &mut impl Rng) -> f32 {
        let mut copy = *self;
        copy.age(now);
        // Beta::new only rejects non-positive parameters, which `age` cannot
        // produce because it shrinks toward PRIOR rather than through it.
        match rand_distr::Beta::new(copy.alpha as f64, copy.beta as f64) {
            Ok(dist) => dist.sample(rng) as f32,
            Err(_) => copy.mean_at(now),
        }
    }

    /// Lower confidence bound, used where a decision must be conservative
    /// (promoting an arm to the persisted default) rather than exploratory.
    ///
    /// Normal approximation to the Beta quantile; exact enough at the masses we
    /// carry and far cheaper than an incomplete-beta inverse.
    pub fn lower_bound(&self, now: Seconds, z: f32) -> f32 {
        let mut copy = *self;
        copy.age(now);
        let n = copy.alpha + copy.beta;
        let mean = copy.alpha / n;
        let variance = mean * (1.0 - mean) / (n + 1.0);
        (mean - z * variance.sqrt()).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(0x00C0_FFEE_5EED)
    }

    #[test]
    fn starts_at_one_half() {
        let p = Posterior::new(0);
        assert!((p.mean_at(0) - 0.5).abs() < 1e-6);
        assert!(p.mass_at(0).abs() < 1e-6);
    }

    #[test]
    fn successes_raise_the_mean_and_failures_lower_it() {
        let mut p = Posterior::new(0);
        for _ in 0..10 {
            p.observe(true, 1.0, 0);
        }
        assert!(p.mean_at(0) > 0.9, "mean was {}", p.mean_at(0));
        let mut q = Posterior::new(0);
        for _ in 0..10 {
            q.observe(false, 1.0, 0);
        }
        assert!(q.mean_at(0) < 0.1, "mean was {}", q.mean_at(0));
    }

    #[test]
    fn evidence_decays_toward_the_prior() {
        let mut p = Posterior::new(0);
        for _ in 0..20 {
            p.observe(true, 1.0, 0);
        }
        let fresh = p.mean_at(0);
        let one_half_life = p.mean_at(Posterior::HALF_LIFE as u64);
        let ten_half_lives = p.mean_at(10 * Posterior::HALF_LIFE as u64);
        assert!(one_half_life < fresh);
        assert!(ten_half_lives < one_half_life);
        assert!((ten_half_lives - 0.5).abs() < 0.05, "should have forgotten: {ten_half_lives}");
    }

    #[test]
    fn mass_is_capped_so_a_proven_arm_stays_falsifiable() {
        let mut p = Posterior::new(0);
        for _ in 0..5_000 {
            p.observe(true, 1.0, 0);
        }
        assert!(p.mass_at(0) <= Posterior::MAX_MASS);
        for _ in 0..20 {
            p.observe(false, 1.0, 0);
        }
        assert!(p.mean_at(0) < 0.95, "20 failures must dent it, got {}", p.mean_at(0));
    }

    #[test]
    fn transfer_keeps_the_mean_but_drops_the_confidence() {
        let mut source = Posterior::new(0);
        for _ in 0..100 {
            source.observe(true, 1.0, 0);
        }
        let derived = Posterior::transferred_from(&source, 0);
        assert!((derived.mean_at(0) - source.mean_at(0)).abs() < 0.1);
        assert!(derived.mass_at(0) < source.mass_at(0) / 5.0);
    }

    #[test]
    fn sampling_separates_a_good_arm_from_a_bad_one() {
        let mut good = Posterior::new(0);
        let mut bad = Posterior::new(0);
        for _ in 0..30 {
            good.observe(true, 1.0, 0);
            bad.observe(false, 1.0, 0);
        }
        let mut rng = rng();
        let wins = (0..200).filter(|_| good.sample(0, &mut rng) > bad.sample(0, &mut rng)).count();
        assert!(wins > 190, "good arm should nearly always win, won {wins}/200");
    }

    #[test]
    fn an_imported_record_keeps_its_ranking_but_not_its_certainty() {
        // 98 of 100 domains opened. The ranking must survive the import; the
        // hundred observations behind it must not.
        let p = Posterior::from_record(98.0, 100.0, 0).unwrap();
        assert!(p.mean_at(0) > 0.9, "import lost the ranking: {}", p.mean_at(0));
        assert!(p.mass_at(0) <= Posterior::IMPORT_MASS);
    }

    #[test]
    fn one_burst_of_failures_overturns_an_import() {
        // The calibration claim in IMPORT_MASS's docs, asserted rather than
        // asserted-in-prose: a single exploration burst must be able to
        // dethrone a historical favourite that no longer works.
        let mut p = Posterior::from_record(98.0, 100.0, 0).unwrap();
        for _ in 0..12 {
            p.observe(false, 1.0, 0);
        }
        assert!(p.mean_at(0) < 0.5, "history outvoted a full burst: {}", p.mean_at(0));
    }

    #[test]
    fn a_record_without_a_denominator_is_refused() {
        assert!(Posterior::from_record(9.0, 0.0, 0).is_none());
        assert!(Posterior::from_record(0.0, 0.0, 0).is_none());
        assert!(Posterior::from_record(f32::NAN, 10.0, 0).is_none());
    }

    #[test]
    fn a_thin_record_is_imported_at_its_own_weight_not_inflated() {
        // 2 of 3 is weak evidence and must stay weak: importing it at the full
        // mass would give three domain checks the authority of a hundred.
        let p = Posterior::from_record(2.0, 3.0, 0).unwrap();
        assert!(p.mass_at(0) < 4.0, "thin record inflated to {}", p.mass_at(0));
    }

    #[test]
    fn lower_bound_is_below_the_mean_and_tightens_with_evidence() {
        let mut p = Posterior::new(0);
        for _ in 0..5 {
            p.observe(true, 1.0, 0);
        }
        let narrow_early = p.mean_at(0) - p.lower_bound(0, 1.96);
        for _ in 0..80 {
            p.observe(true, 1.0, 0);
        }
        let narrow_late = p.mean_at(0) - p.lower_bound(0, 1.96);
        assert!(narrow_late < narrow_early);
        assert!(p.lower_bound(0, 1.96) <= p.mean_at(0));
    }
}
