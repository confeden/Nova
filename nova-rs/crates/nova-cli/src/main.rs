//! Headless driver for the Nova engine.
//!
//! Run this instead of `nova.pyw` while developing the Rust side. It loads the
//! same `strat/*.json`, `fake/` and `bin/winws.exe` the shipping app uses, drives
//! the real engine crates, and prints what it decided and why. There is no GUI
//! and no driver interaction, so it is safe to run while Nova itself is running.
//!
//! ```text
//! cargo run -p nova-cli -- inspect     corpus and palette as the IR sees them
//! cargo run -p nova-cli -- import      read the Python learning record, report it
//! cargo run -p nova-cli -- evolve      generate strategies, validate on winws
//! cargo run -p nova-cli -- mine        breed across all pools, report new rules
//! cargo run -p nova-cli -- learn       watch the learner converge, offline
//! cargo run -p nova-cli -- budget      show the background exploration schedule
//! ```

mod corpus;
mod validate;

use std::time::Instant;

use corpus::Corpus;
use nova_core::{BlockSignature, GroupId, ProbeOutcome, StrategyId};
use nova_learn::{
    Activity, Decision, Governor, GovernorConfig, Learner, LearnerConfig, NetworkContext, PythonHistory,
};
use nova_zapret::{Archive, Emitter, Mutator, V1Emitter};
use rand::SeedableRng;
use validate::{Validator, Verdict};

fn main() {
    let command = std::env::args().nth(1).unwrap_or_else(|| "inspect".to_owned());

    let Some(root) = Corpus::find_root() else {
        eprintln!("error: run this from inside the Nova checkout (needs strat/ and bin/ above the cwd)");
        std::process::exit(2);
    };
    let corpus = match Corpus::load(&root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    println!("nova engine {}  root {}", env!("CARGO_PKG_VERSION"), root.display());
    println!();

    match command.as_str() {
        "inspect" => inspect(&corpus),
        "import" => import(&corpus),
        "evolve" => evolve(&corpus),
        "mine" => mine(&corpus),
        "learn" => learn(&corpus),
        "budget" => budget(),
        other => {
            eprintln!("unknown command {other:?}; try inspect | import | evolve | mine | learn | budget");
            std::process::exit(2);
        }
    }
}

/// Read the Python learner's record and report what it is worth.
///
/// Read-only: it does not write learner state, because the state file belongs
/// to a running engine that does not exist yet. What it does is prove the
/// import against the real data and surface the two things the record turned
/// out to be hiding — which payloads actually work, and how far the corpus has
/// collapsed.
fn import(corpus: &Corpus) {
    let temp = corpus.root.join("temp");
    let read = |name: &str| std::fs::read_to_string(temp.join(name)).unwrap_or_default();
    let (scores_raw, learning_raw) = (read("strategy_scores.json"), read("learning_data.json"));
    if scores_raw.is_empty() && learning_raw.is_empty() {
        println!("no learning record found in {}", temp.display());
        return;
    }

    let history = match PythonHistory::parse(&scores_raw, &learning_raw) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: cannot parse the learning record: {e}");
            std::process::exit(2);
        }
    };

    let context = NetworkContext::new("imported");
    let (mut state, report) = history.into_state(&context, 0);

    println!("HISTORICAL IMPORT");
    println!("  {} arm(s) across {} pool(s)", report.arms(), report.arms_per_group.len());
    for (group, count) in &report.arms_per_group {
        println!("    {group:<14} {count:>5}");
    }
    println!("  {} observations behind them", report.observations_behind);
    println!(
        "  refused: {} row(s) with no denominator, {} live-config placeholder(s)",
        report.rows_without_denominator, report.rows_that_were_placeholders
    );
    let full = state.to_json().map(|j| j.len()).unwrap_or(0);

    // Only arms some pool still offers can ever be selected. The rest are
    // write amplification on a file the engine rewrites as beliefs change.
    let live: std::collections::BTreeSet<(String, String)> = corpus
        .pools
        .iter()
        .flat_map(|p| p.strategies.iter().map(move |s| (p.name.clone(), s.id.to_string())))
        .collect();
    let dropped = state.retain_arms(|group, id| live.contains(&(group.to_string(), id.to_string())));
    let pruned = state.to_json().map(|j| j.len()).unwrap_or(0);
    println!(
        "  {:.1} KB whole; {:.1} KB after dropping {dropped} arm(s) no pool offers",
        full as f32 / 1024.0,
        pruned as f32 / 1024.0
    );

    let dead = history.dead_ends(50.0);
    let dead_total: usize = dead.values().map(Vec::len).sum();
    println!("  {dead_total} strategy name(s) scored a well-measured zero — reusable as a novelty filter");
    println!();

    let evidence = history.gene_evidence(0);
    println!("FAKE PAYLOAD EVIDENCE");
    println!("  {:>6} {:>7}  blob", "mean", "mass");
    for (name, mean, mass) in evidence.blob_ranking(0) {
        let shipped = corpus
            .pools
            .iter()
            .flat_map(|p| p.strategies.iter())
            .flat_map(|s| s.fakes.iter())
            .any(|(_, p)| matches!(p, nova_zapret::Payload::File { path, .. } if path.ends_with(name)));
        println!("  {mean:>6.3} {mass:>7.1}  {name}{}", if shipped { "   <- in use" } else { "" });
    }
    println!();

    if !evidence.collapsed.is_empty() {
        println!("EVIDENCE LOST TO THE RECORDER");
        println!("  These keys were stored without their value, so every setting of");
        println!("  each shares one bucket. nova.pyw:10149 decides this.");
        let mut rows: Vec<(&String, &u64)> = evidence.collapsed.iter().collect();
        rows.sort_by_key(|(_, uses)| std::cmp::Reverse(**uses));
        for (key, uses) in rows.iter().take(8) {
            println!("    {uses:>7} observations  {key}");
        }
        let total: u64 = evidence.collapsed.values().sum();
        println!("  {total} observations in {} unusable buckets", evidence.collapsed.len());
        println!();
    }

    // Diversity of what actually ships, measured the same way the ladder
    // selector would measure it.
    println!("CORPUS DIVERSITY");
    println!("  {:<14} {:>9} {:>7} {:>9}  ladder", "pool", "profiles", "niches", "coverage");
    for pool in &corpus.pools {
        let mut archive = Archive::new();
        for (rank, strategy) in pool.strategies.iter().enumerate() {
            // Absent a score for every arm, corpus order is the fitness the
            // Python sorter already imposed: it writes best-first.
            archive.insert(strategy, (pool.strategies.len() - rank) as f32);
        }
        let coverage = archive.coverage(pool.strategies.len());
        println!(
            "  {:<14} {:>9} {:>7} {:>8.0}% {:>7}",
            pool.name,
            pool.strategies.len(),
            archive.len(),
            coverage * 100.0,
            archive.ladder(12).len()
        );
    }
}

fn inspect(corpus: &Corpus) {
    println!("STRATEGY CORPUS");
    println!("  {:<14} {:>10}  modes in use", "pool", "profiles");
    for pool in &corpus.pools {
        let mut modes: Vec<String> =
            pool.strategies.iter().flat_map(|s| s.modes.iter().map(|m| m.as_v1().to_owned())).collect();
        modes.sort();
        modes.dedup();
        println!("  {:<14} {:>10}  {}", pool.name, pool.strategies.len(), modes.join(", "));
    }
    println!("  {:<14} {:>10}", "TOTAL", corpus.total_strategies());
    println!();

    println!("FAKE PAYLOAD PALETTE");
    println!("  tls  {:>4} blobs", corpus.palette.tls_fakes.len());
    println!("  quic {:>4} blobs", corpus.palette.quic_fakes.len());
    println!();

    // Options the IR carries verbatim because it has no concept for them. Each
    // one is a strategy the future zapret2 emitter would have to refuse, so the
    // count is a direct measure of migration debt.
    let mut unmodelled: Vec<String> = corpus
        .pools
        .iter()
        .flat_map(|p| p.strategies.iter())
        .flat_map(|s| s.passthrough.iter())
        .map(|o| o.split_once('=').map_or(o.clone(), |(f, _)| f.to_owned()))
        .collect();
    unmodelled.sort();
    unmodelled.dedup();
    println!("MIGRATION DEBT");
    println!("  {} option(s) pass through the IR unmodelled:", unmodelled.len());
    for chunk in unmodelled.chunks(4) {
        println!("    {}", chunk.join("  "));
    }
}

/// Load the Python learning record, if there is one.
fn history(corpus: &Corpus) -> Option<PythonHistory> {
    let temp = corpus.root.join("temp");
    let read = |name: &str| std::fs::read_to_string(temp.join(name)).unwrap_or_default();
    PythonHistory::parse(&read("strategy_scores.json"), &read("learning_data.json")).ok()
}

/// Measure the palette against the binary before breeding.
///
/// Shared by `evolve` and `mine`, so both generate under the same constraints
/// the shipping engine would. Two sources feed it: `--dry-run` decides what is
/// *possible*, and the historical record decides what is *worth trying*.
fn measured_palette(corpus: &Corpus, validator: &Validator) -> nova_zapret::Palette {
    let mut palette = corpus.palette.clone();

    if let Some(history) = history(corpus) {
        let evidence = history.gene_evidence(0);
        let ranking = evidence.blob_ranking(0);
        if !ranking.is_empty() {
            palette.blob_weights = ranking.iter().map(|(n, mean, _)| ((*n).to_owned(), *mean)).collect();
            let best = ranking.first().map(|(n, m, _)| format!("{n} {m:.3}")).unwrap_or_default();
            let worst = ranking.last().map(|(n, m, _)| format!("{n} {m:.3}")).unwrap_or_default();
            println!("  payload weights from {} measured blob(s): best {best}, worst {worst}", ranking.len());
        }
    }

    let started = Instant::now();
    let moddable = validator.measure_moddable_tls(&palette.tls_fakes);
    let rejected: Vec<&String> = palette.tls_fakes.iter().filter(|n| !moddable.contains(*n)).collect();
    println!(
        "  palette probe: {}/{} TLS blobs accept a mod ({:.1}s)",
        moddable.len(),
        palette.tls_fakes.len(),
        started.elapsed().as_secs_f32()
    );
    if !rejected.is_empty() {
        println!(
            "    winws refuses to mod: {}",
            rejected.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        );
    }
    palette.moddable_tls = Some(moddable);
    palette
}

fn evolve(corpus: &Corpus) {
    let validator = Validator::new(corpus.winws_path(), &corpus.root);
    if !validator.is_available() {
        eprintln!("error: {} not found", validator.winws_path().display());
        std::process::exit(2);
    }

    let Some(pool) = corpus.pool("general").or_else(|| corpus.pools.first()) else {
        eprintln!("error: no strategy pools loaded");
        std::process::exit(2);
    };
    println!("EVOLUTION  pool={} parents={}", pool.name, pool.strategies.len());
    println!("Generating candidates and validating each against the real winws.");
    println!();

    let palette = measured_palette(corpus, &validator);
    println!();
    let mut mutator = Mutator::new(rand::rngs::StdRng::seed_from_u64(0x00C0_FFEE), palette);
    let mut seen: std::collections::BTreeSet<Vec<String>> = std::collections::BTreeSet::new();
    for parent in &pool.strategies {
        if let Ok(argv) = V1Emitter.emit_profile(parent) {
            seen.insert(argv);
        }
    }

    const ATTEMPTS: usize = 120;
    let (mut generated, mut duplicate, mut accepted, mut rejected) = (0, 0, 0, 0);
    let mut reasons: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut survivors = Vec::new();
    let started = Instant::now();

    for i in 0..ATTEMPTS {
        let a = &pool.strategies[i % pool.strategies.len()];
        let b = &pool.strategies[(i * 7 + 3) % pool.strategies.len()];
        let Some(child) = mutator.breed(&[a, b]) else { continue };
        generated += 1;

        let Ok(argv) = V1Emitter.emit_profile(&child.strategy) else { continue };
        if !seen.insert(argv) {
            duplicate += 1;
            continue;
        }

        match validator.check(&child.strategy) {
            Verdict::Accepted => {
                accepted += 1;
                survivors.push(child);
            }
            Verdict::Rejected { reason } => {
                rejected += 1;
                *reasons.entry(reason).or_default() += 1;
            }
            Verdict::Unavailable { reason } => {
                eprintln!("winws unavailable: {reason}");
                break;
            }
        }
    }

    let elapsed = started.elapsed();
    println!("  generated       {generated:>5}");
    println!("  already known   {duplicate:>5}   (rejected free, before any cost)");
    println!("  winws accepted  {accepted:>5}");
    println!("  winws rejected  {rejected:>5}");
    if generated > 0 {
        println!("  survival rate   {:>4.0}%", 100.0 * accepted as f32 / generated as f32);
    }
    println!("  wall clock      {:>5.1}s for {} dry-runs", elapsed.as_secs_f32(), accepted + rejected);
    println!();

    if !reasons.is_empty() {
        println!("REJECTION REASONS");
        for (reason, count) in &reasons {
            println!("  {count:>4}x {reason}");
        }
        println!();
    }

    println!("SAMPLE SURVIVORS");
    for child in survivors.iter().take(5) {
        println!("  {} via {:?} from {}", child.strategy.id, child.operator, child.parents[0]);
        if let Ok(argv) = V1Emitter.emit_profile(&child.strategy) {
            println!("    {}", argv.join(" "));
        }
    }
}

/// Wide sweep across every pool, collecting the reasons winws rejects
/// generated candidates.
///
/// This is how the generator's constraint set grows. Each distinct rejection is
/// a rule the mutator does not yet know; encoding it turns a candidate that
/// would have been thrown away into one that never gets built, which is pure
/// saved cost. `evolve` samples one pool for a quick look — this one is the
/// deliberate hunt, and it is meant to be run after any change to the corpus or
/// to winws itself.
fn mine(corpus: &Corpus) {
    let validator = Validator::new(corpus.winws_path(), &corpus.root);
    if !validator.is_available() {
        eprintln!("error: {} not found", validator.winws_path().display());
        std::process::exit(2);
    }

    println!("RULE MINING  pools={}  parents={}", corpus.pools.len(), corpus.total_strategies());
    println!("Breeding across every pool and recording what winws refuses.");
    println!();

    let palette = measured_palette(corpus, &validator);
    println!();
    let mut mutator = Mutator::new(rand::rngs::StdRng::seed_from_u64(0x5EED_1234), palette);
    let mut seen: std::collections::BTreeSet<Vec<String>> = std::collections::BTreeSet::new();
    let mut reasons: std::collections::BTreeMap<String, (usize, String)> = std::collections::BTreeMap::new();
    let (mut checked, mut accepted) = (0usize, 0usize);
    let started = Instant::now();

    for pool in &corpus.pools {
        if pool.strategies.len() < 2 {
            continue;
        }
        let mut pool_checked = 0;
        let mut pool_accepted = 0;
        for i in 0..300 {
            let a = &pool.strategies[i % pool.strategies.len()];
            let b = &pool.strategies[(i * 5 + 1) % pool.strategies.len()];
            let Some(child) = mutator.breed(&[a, b]) else { continue };
            let Ok(argv) = V1Emitter.emit_profile(&child.strategy) else { continue };
            if !seen.insert(argv.clone()) {
                continue;
            }
            checked += 1;
            pool_checked += 1;
            match validator.check(&child.strategy) {
                Verdict::Accepted => {
                    accepted += 1;
                    pool_accepted += 1;
                }
                Verdict::Rejected { reason } => {
                    reasons.entry(reason).or_insert_with(|| (0, argv.join(" "))).0 += 1;
                }
                Verdict::Unavailable { reason } => {
                    eprintln!("winws unavailable: {reason}");
                    return;
                }
            }
        }
        println!(
            "  {:<12} {:>4} checked  {:>4} accepted  {:>3.0}%",
            pool.name,
            pool_checked,
            pool_accepted,
            if pool_checked == 0 { 0.0 } else { 100.0 * pool_accepted as f32 / pool_checked as f32 }
        );
    }

    println!();
    println!("  total {checked} candidates in {:.1}s, {accepted} accepted", started.elapsed().as_secs_f32());
    println!();

    if reasons.is_empty() {
        println!("NO NEW RULES: every generated candidate was accepted by winws.");
        return;
    }

    println!("RULES TO ENCODE  ({} distinct rejection(s))", reasons.len());
    let mut ranked: Vec<_> = reasons.iter().collect();
    ranked.sort_by_key(|(_, (count, _))| std::cmp::Reverse(*count));
    for (reason, (count, example)) in ranked {
        println!();
        println!("  {count:>4}x  {reason}");
        println!("        e.g. {example}");
    }
}

fn learn(corpus: &Corpus) {
    // Offline: no network, no winws. Demonstrates convergence and, more
    // importantly, the steady-state probe cost once converged.
    let Some(pool) = corpus.pool("general").or_else(|| corpus.pools.first()) else { return };
    let ids: Vec<StrategyId> = pool.strategies.iter().map(|s| s.id.clone()).collect();
    let winner = ids[ids.len() / 3].clone();

    println!("LEARNER  pool={} arms={}", pool.name, ids.len());
    println!("Simulated network where exactly one strategy works: {winner}");
    println!();

    let mut learner = Learner::new(Default::default(), LearnerConfig::default(), NetworkContext::new("as12389"));
    let group = GroupId::new(&pool.name);
    let (mut probes, mut swaps) = (0u32, 0u32);
    let mut now = 0;
    let mut settled = None;
    let mut converged_at = None;

    for step in 0..600 {
        now += 5;
        match learner.decide(&group, &ids, now) {
            Decision::Probe { candidates, reason } => {
                if probes == 0 {
                    println!("  [{now:>5}s] probing: {reason}");
                }
                for c in candidates {
                    probes += 1;
                    let outcome = outcome_for(&c, &winner);
                    learner.record(&group, &c, &outcome, true, now);
                }
            }
            Decision::Switch { to, reason, .. } => {
                swaps += 1;
                println!("  [{now:>5}s] switch -> {to}  ({reason})");
                let outcome = outcome_for(&to, &winner);
                learner.record(&group, &to, &outcome, false, now);
                settled = Some(to);
            }
            Decision::Hold { strategy } => {
                if settled.as_ref() == Some(&winner) && converged_at.is_none() {
                    converged_at = Some((step, probes));
                }
                let outcome = outcome_for(&strategy, &winner);
                learner.record(&group, &strategy, &outcome, false, now);
                settled = Some(strategy);
            }
            Decision::Escalate { signature } => {
                println!("  [{now:>5}s] escalate: {signature:?} is not fixable by any strategy");
            }
        }
    }

    println!();
    println!("  settled on      {}", settled.map_or("<none>".to_owned(), |s| s.to_string()));
    println!("  correct         {}", if converged_at.is_some() { "yes" } else { "no" });
    if let Some((step, at)) = converged_at {
        println!("  converged after {at} probes ({step} decision ticks)");
    }
    println!("  winws swaps     {swaps}");
    println!("  total probes    {probes}");

    // Now the property that matters most: a healthy network costs nothing.
    let before = probes;
    for _ in 0..2000 {
        now += 30;
        match learner.decide(&group, &ids, now) {
            Decision::Probe { candidates, .. } => probes += candidates.len() as u32,
            Decision::Hold { strategy } | Decision::Switch { to: strategy, .. } => {
                let outcome = outcome_for(&strategy, &winner);
                learner.record(&group, &strategy, &outcome, false, now);
            }
            Decision::Escalate { .. } => {}
        }
    }
    println!("  probes during a further 16h of a healthy network: {}", probes - before);
}

fn outcome_for(candidate: &StrategyId, winner: &StrategyId) -> ProbeOutcome {
    if candidate == winner {
        ProbeOutcome::Success { latency_ms: 48 }
    } else {
        ProbeOutcome::Failed { signature: BlockSignature::RstImmediate }
    }
}

fn budget() {
    println!("BACKGROUND EXPLORATION BUDGET");
    println!("Continuous trickle, not a periodic campaign. Rate by observed activity:");
    println!();
    println!("  {:<10} {:>12} {:>14} {:>12}", "activity", "probes/day", "traffic/day", "cpu/day");
    for activity in [Activity::Idle, Activity::Light, Activity::Heavy, Activity::Metered] {
        let mut g = Governor::new(GovernorConfig::default(), 0);
        g.set_activity(activity, 0);
        let mut granted = 0u64;
        for t in 1..=86_400 {
            granted += u64::from(g.claim(1, t));
        }
        // ~20 KB and ~30 ms per TLS probe, measured against the Python prober.
        println!(
            "  {:<10} {:>12} {:>11.1} MB {:>10.0} s",
            format!("{activity:?}"),
            granted,
            granted as f32 * 20.0 / 1024.0,
            granted as f32 * 0.03
        );
    }
    println!();
    let cfg = GovernorConfig::default();
    println!("  burst ceiling: {} probes - an idle night cannot buy a morning spike", cfg.burst);
    println!("  winws swaps:   at most one per {}s", cfg.min_seconds_between_swaps);
    println!();
    println!("For comparison, the Python sweep spent ~9500 probes and ~130 winws");
    println!("restarts in a single window, then nothing for days.");
}
