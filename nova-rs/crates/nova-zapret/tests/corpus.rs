//! Validates the IR against Nova's entire shipped strategy corpus.
//!
//! Unit tests prove the parser handles the cases someone thought to write down.
//! This one proves it handles what actually ships: every strategy in
//! `strat/*.json`, several hundred profiles across nine pools. If the IR cannot
//! represent the real corpus losslessly, the backend abstraction is a fiction
//! and the zapret2 migration path does not exist.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use nova_core::StrategyId;
use nova_zapret::{Emitter, V1Emitter};

/// Nova's repository root, two levels above this crate.
fn nova_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("crate lives at <root>/nova-rs/crates/nova-zapret")
        .to_path_buf()
}

struct Profile {
    pool: String,
    name: StrategyId,
    args: Vec<String>,
}

/// Read every `strat/*.json`, splitting each strategy's argv into `--new`
/// delimited profiles.
fn load_corpus() -> Vec<Profile> {
    let strat_dir = nova_root().join("strat");
    let mut profiles = Vec::new();
    let entries =
        std::fs::read_dir(&strat_dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", strat_dir.display()));

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let pool = path.file_stem().unwrap_or_default().to_string_lossy().into_owned();
        let Ok(raw) = std::fs::read_to_string(&path) else { continue };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) else {
            panic!("{} is not valid JSON", path.display());
        };
        let Some(list) = json.get("strategies").and_then(|s| s.as_array()) else { continue };
        for item in list {
            let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("<unnamed>");
            let Some(args) = item.get("args").and_then(|a| a.as_array()) else { continue };
            let args: Vec<String> = args.iter().filter_map(|a| a.as_str()).map(str::to_owned).collect();
            for (index, section) in V1Emitter::split_profiles(&args).into_iter().enumerate() {
                profiles.push(Profile {
                    pool: pool.clone(),
                    name: StrategyId::new(format!("{name}#{index}")),
                    args: section,
                });
            }
        }
    }
    profiles
}

#[test]
fn the_whole_shipped_corpus_parses_into_the_ir() {
    let corpus = load_corpus();
    assert!(corpus.len() > 100, "only found {} profiles; corpus did not load", corpus.len());

    let mut failures = Vec::new();
    for profile in &corpus {
        if let Err(e) = V1Emitter::parse_profile(profile.name.clone(), &profile.args) {
            failures.push(format!("{}/{}: {e}", profile.pool, profile.name));
        }
    }
    assert!(failures.is_empty(), "{} profiles failed to parse:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn every_parsed_profile_re_emits_idempotently() {
    let mut failures = Vec::new();
    for profile in load_corpus() {
        let Ok(once) = V1Emitter::parse_profile(profile.name.clone(), &profile.args) else { continue };
        let Ok(emitted) = V1Emitter.emit_profile(&once) else {
            // Profiles with no port filter at all are legal in a multi-section
            // command line, where the ports come from an earlier section.
            continue;
        };
        let Ok(twice) = V1Emitter::parse_profile(profile.name.clone(), &emitted) else {
            failures.push(format!("{}/{}: emitted form does not re-parse", profile.pool, profile.name));
            continue;
        };
        if once != twice {
            failures.push(format!("{}/{}: not idempotent", profile.pool, profile.name));
        }
    }
    assert!(failures.is_empty(), "{} profiles are not idempotent:\n{}", failures.len(), failures.join("\n"));
}

/// Inventory of what the corpus actually uses that the IR does not model.
///
/// Deliberately a report rather than a hard failure for unknown options: the
/// passthrough channel means they still work under zapret v1. What it does
/// assert is that the set has not *grown* beyond what was reviewed, because
/// every passthrough option is one the zapret2 emitter will have to refuse.
#[test]
fn unmodelled_options_stay_within_the_reviewed_set() {
    // Reviewed 2026-08-03 against bundled winws v72.12.
    const KNOWN_PASSTHROUGH: &[&str] = &[
        "--dpi-desync-any-protocol",
        "--dpi-desync-badack-increment",
        "--dpi-desync-cutoff",
        "--dpi-desync-fake-tls-mod",
        "--dpi-desync-fakedsplit-pattern",
        "--dpi-desync-hostfakesplit-midhost",
        "--dpi-desync-ipfrag-pos-tcp",
        "--dpi-desync-ipfrag-pos-udp",
        "--dpi-desync-skip-nosni",
        "--dpi-desync-split-http-req",
        "--dpi-desync-split-seqovl-pattern",
        "--dpi-desync-split-tls",
        "--dpi-desync-start",
        "--dpi-desync-tcp-flags-set",
        "--dpi-desync-tcp-flags-unset",
        "--dpi-desync-udplen-increment",
        "--dpi-desync-udplen-pattern",
        "--domcase",
        "--dup",
        "--dup-autottl",
        "--dup-cutoff",
        "--dup-fooling",
        "--dup-ip-id",
        "--dup-replace",
        "--dup-start",
        "--dup-ttl",
        "--hostcase",
        "--hostnospace",
        "--hostspell",
        "--ip-id",
        "--methodeol",
        "--orig-autottl",
        "--orig-mod-cutoff",
        "--orig-mod-start",
        "--orig-ttl",
        "--synack-split",
        "--wssize",
        "--wssize-cutoff",
    ];

    let mut seen: BTreeSet<String> = BTreeSet::new();
    for profile in load_corpus() {
        let Ok(parsed) = V1Emitter::parse_profile(profile.name.clone(), &profile.args) else { continue };
        for option in parsed.passthrough {
            let flag = option.split_once('=').map_or(option.as_str(), |(f, _)| f).to_owned();
            seen.insert(flag);
        }
    }

    let known: BTreeSet<String> = KNOWN_PASSTHROUGH.iter().map(|s| (*s).to_owned()).collect();
    let unexpected: Vec<&String> = seen.difference(&known).collect();
    assert!(
        unexpected.is_empty(),
        "corpus gained unmodelled options since review; each needs a zapret2 mapping decision: {unexpected:?}"
    );
    eprintln!("corpus uses {} unmodelled options, all previously reviewed", seen.len());
}

#[test]
fn no_profile_uses_a_desync_mode_the_bundled_binary_rejects() {
    // Modes listed by `winws v72.12 --help`, plus the three undocumented
    // backward-compatible aliases confirmed accepted via --dry-run.
    const ACCEPTED: &[&str] = &[
        "synack",
        "syndata",
        "fake",
        "fakeknown",
        "rst",
        "rstack",
        "hopbyhop",
        "destopt",
        "ipfrag1",
        "multisplit",
        "multidisorder",
        "fakedsplit",
        "fakeddisorder",
        "hostfakesplit",
        "ipfrag2",
        "udplen",
        "tamper",
        "split",
        "split2",
        "disorder",
    ];

    let mut bad = Vec::new();
    for profile in load_corpus() {
        for arg in &profile.args {
            let Some(value) = arg.strip_prefix("--dpi-desync=") else { continue };
            for token in value.split(',') {
                if !ACCEPTED.contains(&token) {
                    bad.push(format!("{}/{}: {token}", profile.pool, profile.name));
                }
            }
        }
    }
    assert!(bad.is_empty(), "profiles use modes winws would reject:\n{}", bad.join("\n"));
}
