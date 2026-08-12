//! The niche classifier, written down where both implementations can see it.
//!
//! Nova classifies every strategy into (technique, reach, deniability) twice:
//! here, in `nova-zapret::diversity`, and in Python, in
//! `resources/nova_strategy_niche.py`, which the shipping app uses to build its
//! alternatives ladder. Two copies of a decision table drift; the only question
//! is how long it takes and who finds out. So neither copy is the reference —
//! this file is. Rust generates it, Rust checks it, and the Python test suite
//! reads the same JSON and asserts its own answers against it.
//!
//! Same contract as `nova-probe/tests/table.rs` for the tunnel phases, and for
//! the same reason.
//!
//! The cases are hand-written rather than taken from `strat/*.json`: the corpus
//! is rewritten by the running app every time the learner evolves anything, so
//! a table generated from it would churn on every commit and pin nothing. These
//! cover each technique tier, each reach bucket, each deniability class, and the
//! three precedence rules that are easy to get wrong in one language and not the
//! other.
//!
//! Regenerate after an intentional change:
//!
//! ```text
//! NOVA_UPDATE_NICHE_TABLE=1 cargo test -p nova-zapret --test niche_table
//! ```
//!
//! Then run the Python side, which will fail until it is brought in step. That
//! failure is the feature.

use std::path::PathBuf;

use nova_core::StrategyId;
use nova_zapret::{Deniability, Niche, Reach, Technique, V1Emitter};

fn table_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../docs/reference/strategy-niche-table.json")
}

fn technique_label(t: Technique) -> &'static str {
    match t {
        Technique::Other => "other",
        Technique::Inject => "inject",
        Technique::Fragment => "fragment",
        Technique::Segment => "segment",
        Technique::DecoySegment => "decoy-segment",
        Technique::Relocate => "relocate",
    }
}

fn reach_label(r: Reach) -> &'static str {
    match r {
        Reach::Adaptive => "adaptive",
        Reach::Unbounded => "unbounded",
        Reach::Short => "short",
        Reach::Medium => "medium",
        Reach::Long => "long",
    }
}

fn deniability_label(d: Deniability) -> &'static str {
    match d {
        Deniability::Malformed => "malformed",
        Deniability::OutOfOrder => "out-of-order",
        Deniability::Mixed => "mixed",
        Deniability::Ttl => "ttl",
    }
}

/// `(why this case exists, the winws arguments)`.
fn cases() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("no desync at all falls back to other/unbounded/ttl", vec![]),
        ("inject", vec!["--dpi-desync=fake"]),
        ("inject via rst", vec!["--dpi-desync=rstack"]),
        ("fragment", vec!["--dpi-desync=ipfrag2"]),
        ("segment", vec!["--dpi-desync=multisplit"]),
        ("decoy-segment", vec!["--dpi-desync=fakedsplit"]),
        ("relocate", vec!["--dpi-desync=syndata"]),
        ("relocate via hostfakesplit", vec!["--dpi-desync=hostfakesplit"]),
        // Precedence 1: the most disruptive mode present wins, in both orders,
        // because a profile that both fakes and splits is defeated by whatever
        // defeats its splitting.
        ("most disruptive mode wins", vec!["--dpi-desync=fake,multisplit"]),
        ("most disruptive mode wins, reversed", vec!["--dpi-desync=multisplit,fake"]),
        ("relocate outranks segment", vec!["--dpi-desync=multisplit,syndata"]),
        // The deprecated v1 spellings must land in the same niche as the modern
        // ones, or a corpus written years apart splits into phantom niches.
        ("deprecated split is multisplit", vec!["--dpi-desync=split"]),
        ("deprecated split2 is multisplit", vec!["--dpi-desync=split2"]),
        ("deprecated disorder is multidisorder", vec!["--dpi-desync=disorder"]),
        // Reach buckets, on the boundaries.
        ("ttl 1 is short", vec!["--dpi-desync=fake", "--dpi-desync-ttl=1"]),
        ("ttl 4 is still short", vec!["--dpi-desync=fake", "--dpi-desync-ttl=4"]),
        ("ttl 5 is medium", vec!["--dpi-desync=fake", "--dpi-desync-ttl=5"]),
        ("ttl 8 is still medium", vec!["--dpi-desync=fake", "--dpi-desync-ttl=8"]),
        ("ttl 9 is long", vec!["--dpi-desync=fake", "--dpi-desync-ttl=9"]),
        // Precedence 2: autottl beats a fixed ttl, because v1 applies the
        // measured hop count and keeps the fixed value only as a fallback.
        ("autottl alone is adaptive", vec!["--dpi-desync=fake", "--dpi-desync-autottl=2"]),
        (
            "autottl overrides a fixed ttl",
            vec!["--dpi-desync=fake", "--dpi-desync-ttl=3", "--dpi-desync-autottl=2"],
        ),
        // Deniability classes.
        ("badsum is malformed", vec!["--dpi-desync=fake", "--dpi-desync-fooling=badsum"]),
        ("md5sig is malformed", vec!["--dpi-desync=fake", "--dpi-desync-fooling=md5sig"]),
        ("badseq is out-of-order", vec!["--dpi-desync=fake", "--dpi-desync-fooling=badseq"]),
        ("datanoack is out-of-order", vec!["--dpi-desync=fake", "--dpi-desync-fooling=datanoack"]),
        // Precedence 3: both classes at once is its own answer, not either one.
        ("both classes is mixed", vec!["--dpi-desync=fake", "--dpi-desync-fooling=badsum,badseq"]),
        ("no fooling is ttl", vec!["--dpi-desync=fake", "--dpi-desync-ttl=6"]),
        // The whole grid at once, which is what a real corpus entry looks like.
        (
            "a realistic combination",
            vec![
                "--dpi-desync=fake,fakedsplit",
                "--dpi-desync-ttl=6",
                "--dpi-desync-fooling=badsum,md5sig",
                "--dpi-desync-repeats=4",
            ],
        ),
    ]
}

fn classify(args: &[&str]) -> Niche {
    // Scaffold a filter so the arguments render as a standalone profile; the
    // classifier ignores it, but the parser will not accept a bare fragment.
    let mut full: Vec<String> = vec!["--filter-tcp=80,443".to_owned()];
    full.extend(args.iter().map(|a| (*a).to_owned()));
    let profile = V1Emitter::parse_profile(StrategyId::new("case"), &full)
        .unwrap_or_else(|e| panic!("case {args:?} did not parse: {e}"));
    Niche::of(&profile)
}

#[test]
fn the_table_matches_this_build() {
    let mut rows = Vec::new();
    for (why, args) in cases() {
        let niche = classify(&args);
        rows.push(serde_json::json!({
            "why": why,
            "args": args,
            "technique": technique_label(niche.technique),
            "reach": reach_label(niche.reach),
            "deniability": deniability_label(niche.deniability),
        }));
    }
    let generated = serde_json::json!({
        "note": "Generated by nova-zapret/tests/niche_table.rs. Do not edit by hand — \
                 regenerate with NOVA_UPDATE_NICHE_TABLE=1 cargo test -p nova-zapret --test niche_table",
        "cases": rows,
    });
    let rendered = serde_json::to_string_pretty(&generated).expect("serialise") + "\n";

    let path = table_path();
    if std::env::var("NOVA_UPDATE_NICHE_TABLE").is_ok() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create docs/reference");
        }
        std::fs::write(&path, &rendered).expect("write the table");
        return;
    }

    let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{} is missing ({e}). Generate it: \
             NOVA_UPDATE_NICHE_TABLE=1 cargo test -p nova-zapret --test niche_table",
            path.display()
        )
    });
    assert_eq!(
        on_disk.replace("\r\n", "\n"),
        rendered,
        "the classifier and the published table disagree; if the change was intended, \
         regenerate with NOVA_UPDATE_NICHE_TABLE=1 and bring resources/nova_strategy_niche.py in step"
    );
}

/// The axes are only useful if the cases actually exercise them.
#[test]
fn every_value_of_every_axis_is_covered() {
    let mut techniques = std::collections::BTreeSet::new();
    let mut reaches = std::collections::BTreeSet::new();
    let mut deniabilities = std::collections::BTreeSet::new();
    for (_, args) in cases() {
        let n = classify(&args);
        techniques.insert(technique_label(n.technique));
        reaches.insert(reach_label(n.reach));
        deniabilities.insert(deniability_label(n.deniability));
    }
    assert_eq!(techniques.len(), 6, "techniques covered: {techniques:?}");
    assert_eq!(reaches.len(), 5, "reaches covered: {reaches:?}");
    assert_eq!(deniabilities.len(), 4, "deniabilities covered: {deniabilities:?}");
}
