//! Reading the Python learner's accumulated record into the Rust learner.
//!
//! # Why bother
//!
//! `temp/strategy_scores.json` holds 3759 scored strategies and
//! `temp/learning_data.json` holds argument- and blob-level tallies over ~11 000
//! checks. That is months of measurement on the user's own ISP, against the
//! user's own domain panel. Starting the new learner cold would throw it away
//! and pay for it again in probes.
//!
//! # What the record actually says
//!
//! Each row is `score` out of `total`: how many domains of a panel of `total`
//! opened while that strategy was in force. That is a binomial observation, so
//! it maps onto a Beta posterior directly — no modelling assumption needed
//! beyond the one the file already makes.
//!
//! Two things stop it being a straight copy:
//!
//! 1. **Rows without a denominator.** 213 of the shipped rows carry a non-zero
//!    `score` and `total = 0`. They come from code paths that saved a score
//!    before the panel size was known. There is no honest reading of them, so
//!    they are dropped rather than guessed at; see [`Posterior::from_record`].
//!
//! 2. **Confidence must not survive the trip.** A row of 98/100 is a hundred
//!    observations, and imported at face value it would take a hundred contrary
//!    ones to overturn — days, during which the user's sites stay broken. The
//!    ranking is what is worth keeping; the certainty is not. Mass is therefore
//!    capped at [`Posterior::IMPORT_MASS`].
//!
//! # What the record cannot say
//!
//! The Python side records argument statistics under a key that drops the
//! *value* for everything except `ttl` and `repeats` (`nova.pyw:10149`). So
//! `--dpi-desync=multisplit` and `--dpi-desync=fake` both land in one bucket
//! named `--dpi-desync`, and 30 693 observations collapse into a number that
//! says only "strategies contain a desync mode". [`GeneEvidence::collapsed`]
//! lists those keys instead of silently importing an average as if it were a
//! signal.
//!
//! The tables that *do* carry values — per-blob, per-TTL, per-repeats — are
//! usable, and they are where the useful findings turned out to be.

use std::collections::BTreeMap;

use nova_core::{GroupId, Seconds, StrategyId};

use crate::{LearnerState, NetworkContext, Posterior};

/// Per-gene beliefs recovered from the Python tallies.
///
/// Kept separate from [`LearnerState`] because it is evidence about *parts* of
/// strategies rather than about strategies, and it is consumed by the generator
/// choosing what to build next, not by the bandit choosing what to run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GeneEvidence {
    /// Fake payload filename → belief. The one table with both value-level keys
    /// and enough samples to separate its entries.
    pub blobs: BTreeMap<String, Posterior>,
    /// `--dpi-desync-ttl=N` → belief.
    pub ttl: BTreeMap<u8, Posterior>,
    /// `--dpi-desync-repeats=N` → belief.
    pub repeats: BTreeMap<u32, Posterior>,
    /// Keys the Python side recorded without their value, and the number of
    /// observations trapped in each. Not evidence — a list of what is being
    /// thrown away, so it can be recovered by changing the recorder.
    pub collapsed: BTreeMap<String, u64>,
}

impl GeneEvidence {
    /// Rank blobs by posterior mean, best first, with their evidence mass.
    pub fn blob_ranking(&self, now: Seconds) -> Vec<(&str, f32, f32)> {
        let mut out: Vec<(&str, f32, f32)> =
            self.blobs.iter().map(|(k, p)| (k.as_str(), p.mean_at(now), p.mass_at(now))).collect();
        out.sort_by(|a, b| b.1.total_cmp(&a.1));
        out
    }

    /// Relative selection weights over a set of candidate blob filenames.
    ///
    /// Unmeasured names get the neutral 0.5 rather than 0, so a newly shipped
    /// blob is still reachable. The floor matters: without it one bad early run
    /// could remove a payload from the search space permanently.
    pub fn blob_weights(&self, names: &[String], now: Seconds) -> Vec<f32> {
        names
            .iter()
            .map(|n| self.blobs.get(n).map_or(0.5, |p| p.mean_at(now)).max(0.05))
            .collect()
    }
}

/// What an import did, for the caller to log or show.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImportReport {
    /// Arms given a posterior, per group.
    pub arms_per_group: BTreeMap<GroupId, usize>,
    /// Rows refused because they had a score but no denominator.
    pub rows_without_denominator: usize,
    /// Rows refused because the name is a live-config placeholder rather than a
    /// strategy (`"Current general"` and friends).
    pub rows_that_were_placeholders: usize,
    /// Total observations behind the imported rows, before mass capping. Purely
    /// informational: it is the size of the record being inherited.
    pub observations_behind: u64,
}

impl ImportReport {
    pub fn arms(&self) -> usize {
        self.arms_per_group.values().sum()
    }
}

/// A row of `temp/strategy_scores.json`.
#[derive(serde::Deserialize)]
struct ScoreRow {
    #[serde(default)]
    score: f32,
    #[serde(default)]
    total: Option<f32>,
}

/// A row of any of `learning_data.json`'s tally tables.
#[derive(serde::Deserialize)]
struct TallyRow {
    #[serde(default)]
    uses: f32,
    /// Sum of per-check success *rates*, so `total_score / uses` is a mean in
    /// [0,1]. The sibling `successes` field sums raw scores across panels of
    /// differing sizes and is not comparable between rows, so it is not read.
    #[serde(default)]
    total_score: f32,
}

#[derive(serde::Deserialize)]
struct LearningData {
    #[serde(default)]
    argument_stats: BTreeMap<String, TallyRow>,
    #[serde(default)]
    bin_stats: BTreeMap<String, TallyRow>,
}

/// The historical record, parsed and ready to be folded into a learner.
pub struct PythonHistory {
    scores: BTreeMap<String, BTreeMap<String, ScoreRow>>,
    learning: LearningData,
}

impl PythonHistory {
    /// Parse both files. Either may be absent — an empty string stands in for a
    /// missing file, and yields an empty contribution rather than an error.
    pub fn parse(scores_json: &str, learning_json: &str) -> Result<Self, serde_json::Error> {
        let scores = if scores_json.trim().is_empty() {
            BTreeMap::new()
        } else {
            serde_json::from_str(scores_json)?
        };
        let learning = if learning_json.trim().is_empty() {
            LearningData { argument_stats: BTreeMap::new(), bin_stats: BTreeMap::new() }
        } else {
            serde_json::from_str(learning_json)?
        };
        Ok(Self { scores, learning })
    }

    /// Build a learner state for `context` from the score table.
    ///
    /// Everything lands under one context because the Python record has no
    /// notion of which network it was measured on. That is the honest
    /// placement: it is one ISP's worth of evidence, and labelling it as the
    /// current context means moving networks correctly re-derives it through
    /// [`crate::Learner::seed_from`] rather than inheriting it silently.
    pub fn into_state(&self, context: &NetworkContext, now: Seconds) -> (LearnerState, ImportReport) {
        let mut report = ImportReport::default();
        let mut arms: BTreeMap<GroupId, BTreeMap<StrategyId, Posterior>> = BTreeMap::new();

        for (pool, rows) in &self.scores {
            let group = GroupId::new(pool.clone());
            for (name, row) in rows {
                // "Current general" is the live config echoed into the table,
                // not a candidate. Importing it would create an arm whose name
                // no pool ever offers, and which therefore can never be chosen
                // or corrected.
                if name.starts_with("Current ") {
                    report.rows_that_were_placeholders += 1;
                    continue;
                }
                let Some(total) = row.total else {
                    report.rows_without_denominator += 1;
                    continue;
                };
                let Some(posterior) = Posterior::from_record(row.score, total, now) else {
                    report.rows_without_denominator += 1;
                    continue;
                };
                report.observations_behind += total as u64;
                arms.entry(group.clone()).or_default().insert(StrategyId::new(name.clone()), posterior);
            }
        }

        for (group, set) in &arms {
            report.arms_per_group.insert(group.clone(), set.len());
        }
        (LearnerState::from_arms(context.clone(), arms), report)
    }

    /// Strategies the record says are worth not trying again.
    ///
    /// A well-measured zero — no domain of a panel of at least `min_trials`
    /// opened — is the most reusable fact in the whole file. The generator
    /// names candidates deterministically from their arguments, so a name that
    /// failed comprehensively before will be produced again, and recognising it
    /// costs a hash lookup instead of a probe.
    ///
    /// Deliberately strict: only an exact zero counts. A strategy that scored 3
    /// of 100 is bad on this panel on that day, which is not the same as
    /// unusable.
    pub fn dead_ends(&self, min_trials: f32) -> BTreeMap<GroupId, Vec<StrategyId>> {
        let mut out: BTreeMap<GroupId, Vec<StrategyId>> = BTreeMap::new();
        for (pool, rows) in &self.scores {
            for (name, row) in rows {
                if name.starts_with("Current ") {
                    continue;
                }
                if row.score == 0.0 && row.total.is_some_and(|t| t >= min_trials) {
                    out.entry(GroupId::new(pool.clone())).or_default().push(StrategyId::new(name.clone()));
                }
            }
        }
        out
    }

    /// Extract the gene-level tables.
    pub fn gene_evidence(&self, now: Seconds) -> GeneEvidence {
        let mut evidence = GeneEvidence::default();

        for (name, row) in &self.learning.bin_stats {
            if let Some(p) = Posterior::from_record(row.total_score, row.uses, now) {
                evidence.blobs.insert(name.clone(), p);
            }
        }

        for (key, row) in &self.learning.argument_stats {
            let Some((flag, value)) = key.split_once('=') else {
                // No '=' at all: the recorder stripped the value. Record how
                // much is trapped there rather than importing the average.
                evidence.collapsed.insert(key.clone(), row.uses as u64);
                continue;
            };
            let Some(p) = Posterior::from_record(row.total_score, row.uses, now) else { continue };
            match flag {
                "--dpi-desync-ttl" => {
                    if let Ok(n) = value.parse::<u8>() {
                        evidence.ttl.insert(n, p);
                    }
                }
                "--dpi-desync-repeats" => {
                    if let Ok(n) = value.parse::<u32>() {
                        evidence.repeats.insert(n, p);
                    }
                }
                _ => {}
            }
        }

        evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCORES: &str = r#"{
        "general": {
            "Current general": {"score": 67, "total": 0},
            "hard_4_M391":     {"score": 98, "total": 100},
            "general_MC18":    {"score": 98, "total": 100},
            "hard_2_M819":     {"score": 93, "total": 100},
            "dud_M001":        {"score": 0,  "total": 100},
            "no_denominator":  {"score": 42, "total": 0},
            "null_total":      {"score": 12}
        },
        "youtube": {
            "youtube_M4E5": {"score": 9, "total": 100}
        }
    }"#;

    const LEARNING: &str = r#"{
        "argument_stats": {
            "--dpi-desync":            {"uses": 30693, "successes": 1, "total_score": 16267.0},
            "--dpi-desync-fooling":    {"uses": 15298, "successes": 1, "total_score": 8108.0},
            "--dpi-desync-ttl=11":     {"uses": 4170,  "successes": 1, "total_score": 2168.4},
            "--dpi-desync-ttl=4":      {"uses": 1466,  "successes": 1, "total_score": 645.0},
            "--dpi-desync-repeats=8":  {"uses": 608,   "successes": 1, "total_score": 474.2}
        },
        "bin_stats": {
            "tls_clienthello_www_google_com.bin": {"uses": 2506, "total_score": 1298.1},
            "tls_clienthello_yandex_kz.bin":      {"uses": 5949, "total_score": 2498.6},
            "quic_initial_www_google_com.bin":    {"uses": 8495, "total_score": 3814.3}
        }
    }"#;

    fn history() -> PythonHistory {
        PythonHistory::parse(SCORES, LEARNING).unwrap()
    }

    #[test]
    fn imports_scored_arms_into_their_pools() {
        let (state, report) = history().into_state(&NetworkContext::new("as12389"), 0);
        assert_eq!(report.arms_per_group[&GroupId::new("general")], 4);
        assert_eq!(report.arms_per_group[&GroupId::new("youtube")], 1);
        assert_eq!(report.arms(), 5);
        assert!(state.to_json().unwrap().contains("hard_4_M391"));
    }

    #[test]
    fn rows_without_a_denominator_are_refused_not_guessed() {
        // Two rows here: `total: 0` and a missing `total`. Both would otherwise
        // become perfect-record arms out of nothing.
        let (_, report) = history().into_state(&NetworkContext::new("x"), 0);
        assert_eq!(report.rows_without_denominator, 2);
        assert_eq!(report.rows_that_were_placeholders, 1);
    }

    #[test]
    fn the_live_config_placeholder_never_becomes_an_arm() {
        let (state, _) = history().into_state(&NetworkContext::new("x"), 0);
        assert!(!state.to_json().unwrap().contains("Current "), "placeholder imported as a strategy");
    }

    #[test]
    fn imported_ranking_matches_the_source_order() {
        let (state, _) = history().into_state(&NetworkContext::new("as1"), 0);
        let g = GroupId::new("general");
        let best = state.arm(&NetworkContext::new("as1"), &g, &StrategyId::new("hard_4_M391")).unwrap();
        let mid = state.arm(&NetworkContext::new("as1"), &g, &StrategyId::new("hard_2_M819")).unwrap();
        let dud = state.arm(&NetworkContext::new("as1"), &g, &StrategyId::new("dud_M001")).unwrap();
        assert!(best.mean_at(0) > mid.mean_at(0));
        assert!(mid.mean_at(0) > dud.mean_at(0));
    }

    #[test]
    fn blob_evidence_separates_the_shipped_payloads() {
        // The finding that motivated this whole import: the corpus converged on
        // yandex_kz, which the record scores materially below the google blob
        // over 8455 combined uses.
        let e = history().gene_evidence(0);
        let ranking = e.blob_ranking(0);
        assert_eq!(ranking[0].0, "tls_clienthello_www_google_com.bin");
        let google = e.blobs["tls_clienthello_www_google_com.bin"].mean_at(0);
        let yandex = e.blobs["tls_clienthello_yandex_kz.bin"].mean_at(0);
        assert!(google - yandex > 0.05, "google {google:.3} vs yandex {yandex:.3}");
    }

    #[test]
    fn collapsed_keys_are_reported_rather_than_imported_as_signal() {
        let e = history().gene_evidence(0);
        assert!(e.collapsed.contains_key("--dpi-desync"), "value-less key not flagged");
        assert_eq!(e.collapsed["--dpi-desync"], 30693);
        assert!(!e.collapsed.contains_key("--dpi-desync-ttl=11"), "usable key wrongly flagged");
    }

    #[test]
    fn value_level_keys_are_parsed_into_typed_tables() {
        let e = history().gene_evidence(0);
        assert!(e.ttl.contains_key(&11) && e.ttl.contains_key(&4));
        assert!(e.repeats.contains_key(&8));
        assert!(e.ttl[&11].mean_at(0) > e.ttl[&4].mean_at(0), "ttl ordering lost");
    }

    #[test]
    fn blob_weights_keep_an_unmeasured_payload_reachable() {
        let e = history().gene_evidence(0);
        let names = vec!["tls_clienthello_yandex_kz.bin".to_owned(), "brand_new_blob.bin".to_owned()];
        let w = e.blob_weights(&names, 0);
        assert!(w.iter().all(|x| *x > 0.0), "a blob was weighted out of existence");
        assert!(w[1] > w[0], "unmeasured blob should not rank below a measured-poor one");
    }

    #[test]
    fn a_well_measured_zero_is_recorded_as_a_dead_end() {
        let dead = history().dead_ends(50.0);
        assert_eq!(dead[&GroupId::new("general")], vec![StrategyId::new("dud_M001")]);
        // 98/100 is not a dead end, and neither is a zero with no denominator.
        assert_eq!(dead[&GroupId::new("general")].len(), 1);
        assert!(!dead.contains_key(&GroupId::new("youtube")));
    }

    #[test]
    fn a_thin_zero_is_not_strong_enough_to_blacklist() {
        let thin = r#"{"general":{"maybe_M1":{"score":0,"total":3}}}"#;
        let h = PythonHistory::parse(thin, "").unwrap();
        assert!(h.dead_ends(50.0).is_empty(), "three checks must not condemn a strategy");
        assert!(!h.dead_ends(2.0).is_empty(), "threshold is not being applied");
    }

    #[test]
    fn pruning_to_the_live_pools_shrinks_the_state() {
        let (mut state, _) = history().into_state(&NetworkContext::new("as1"), 0);
        let live = [StrategyId::new("hard_4_M391")];
        let dropped = state.retain_arms(|_, id| live.contains(id));
        assert_eq!(dropped, 4);
        let json = state.to_json().unwrap();
        assert!(json.contains("hard_4_M391"));
        assert!(!json.contains("general_MC18"));
        assert!(!json.contains("youtube"), "an emptied group was left behind");
    }

    #[test]
    fn missing_files_import_as_nothing_rather_than_failing() {
        let h = PythonHistory::parse("", "").unwrap();
        let (_, report) = h.into_state(&NetworkContext::new("x"), 0);
        assert_eq!(report.arms(), 0);
        assert_eq!(h.gene_evidence(0), GeneEvidence::default());
    }
}
