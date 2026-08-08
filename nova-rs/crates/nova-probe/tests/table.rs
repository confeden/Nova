//! The decision table, written down where both implementations can see it.
//!
//! The relay that runs on users' machines is Python, and it carries its own
//! copy of this classifier in `tgrelay/phase.py`. Two copies of a decision
//! table drift; the only question is how long it takes and who finds out. So
//! neither copy is the reference — this file is. Rust generates it, Rust
//! checks it, and the Python test suite reads the same JSON and asserts its
//! own answers against it.
//!
//! Regenerate after an intentional change:
//!
//! ```text
//! NOVA_UPDATE_PHASE_TABLE=1 cargo test -p nova-probe --test table
//! ```
//!
//! Then run the Python side, which will fail until it is brought in step. That
//! failure is the feature.

use std::path::PathBuf;

use nova_probe::{Ended, Reached, Thresholds, TunnelAttempt, classify};

fn table_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../docs/reference/tunnel-phase-table.json")
}

fn reached_label(reached: Reached) -> &'static str {
    match reached {
        Reached::Nothing => "nothing",
        Reached::Resolved => "resolved",
        Reached::Connected => "connected",
        Reached::HelloSent => "hello_sent",
        Reached::HandshakeDone => "handshake_done",
        Reached::Upgraded => "upgraded",
        Reached::Carrying => "carrying",
    }
}

fn ended_label(ended: Ended) -> &'static str {
    match ended {
        Ended::Ok => "ok",
        Ended::Timeout => "timeout",
        Ended::Reset => "reset",
        Ended::Refused => "refused",
        Ended::Closed => "closed",
        Ended::CertificateMismatch => "cert_mismatch",
        Ended::HttpStatus { .. } => "http_status",
        Ended::ResolverStub => "resolver_stub",
    }
}

fn signature_label(outcome: &nova_core::ProbeOutcome) -> String {
    match outcome.signature() {
        None => "success".to_owned(),
        Some(sig) => serde_json::to_value(sig)
            .expect("BlockSignature serialises")
            .as_str()
            .expect("as a bare string")
            .to_owned(),
    }
}

const ALL_REACHED: [Reached; 7] = [
    Reached::Nothing,
    Reached::Resolved,
    Reached::Connected,
    Reached::HelloSent,
    Reached::HandshakeDone,
    Reached::Upgraded,
    Reached::Carrying,
];

const ALL_ENDED: [Ended; 8] = [
    Ended::Ok,
    Ended::Timeout,
    Ended::Reset,
    Ended::Refused,
    Ended::Closed,
    Ended::CertificateMismatch,
    Ended::HttpStatus { code: 403 },
    Ended::ResolverStub,
];

/// Every case the table pins down, in a fixed order so the JSON is stable.
fn cases() -> Vec<TunnelAttempt> {
    let mut out = Vec::new();
    // The full cross product under one ordinary set of measurements. This is
    // the part that guarantees totality: no pair may go unanswered.
    for reached in ALL_REACHED {
        for ended in ALL_ENDED {
            out.push(TunnelAttempt::new(reached, ended).since_hello_ms(100).rtt_ms(50));
        }
    }
    // Then the cases where the numbers, not the milestones, decide.
    out.extend([
        // A reset far inside one round trip cannot have come from the peer…
        TunnelAttempt::new(Reached::HelloSent, Ended::Reset).since_hello_ms(5).rtt_ms(40),
        // …and one around a round trip had time to read the server's reply.
        TunnelAttempt::new(Reached::HelloSent, Ended::Reset).since_hello_ms(45).rtt_ms(40),
        // The same 30 ms means opposite things on a satellite and on fibre.
        TunnelAttempt::new(Reached::HelloSent, Ended::Reset).since_hello_ms(30).rtt_ms(300),
        TunnelAttempt::new(Reached::HelloSent, Ended::Reset).since_hello_ms(30).rtt_ms(12),
        // No timing at all: not guessed at.
        TunnelAttempt::new(Reached::HelloSent, Ended::Reset),
        // Short and light — interrupted.
        TunnelAttempt::new(Reached::Carrying, Ended::Reset).carried(2_048, 900),
        // Long and heavy — it did its job, whatever ended it.
        TunnelAttempt::new(Reached::Carrying, Ended::Reset).carried(8 << 20, 240_000),
        // Short but heavy — a completed download, not an interrupted one.
        TunnelAttempt::new(Reached::Carrying, Ended::Closed).carried(4 << 20, 800),
        // Long but light — a session that never really carried anything.
        TunnelAttempt::new(Reached::Carrying, Ended::Closed).carried(1_024, 60_000),
    ]);
    out
}

fn render() -> String {
    let rows: Vec<serde_json::Value> = cases()
        .iter()
        .map(|attempt| {
            let outcome = classify(attempt, &Thresholds::default());
            serde_json::json!({
                "reached": reached_label(attempt.reached),
                "ended": ended_label(attempt.ended),
                "since_hello_ms": attempt.since_hello_ms,
                "rtt_ms": attempt.rtt_ms,
                "bytes_down": attempt.bytes_down,
                "carried_ms": attempt.carried_ms,
                "signature": signature_label(&outcome),
            })
        })
        .collect();
    let doc = serde_json::json!({
        "//": "Generated by nova-probe's table test. Both nova-probe and \
               tgrelay/phase.py are checked against this file; edit the \
               classifier, not the table.",
        "thresholds": {
            "reset_is_immediate_pct_of_rtt": Thresholds::default().reset_is_immediate_pct_of_rtt,
            "reset_is_immediate_ms": Thresholds::default().reset_is_immediate_ms,
            "severed_within_ms": Thresholds::default().severed_within_ms,
            "severed_under_bytes": Thresholds::default().severed_under_bytes,
        },
        "cases": rows,
    });
    format!("{}\n", serde_json::to_string_pretty(&doc).expect("table serialises"))
}

#[test]
fn the_written_table_matches_the_classifier() {
    let rendered = render();
    let path = table_path();

    if std::env::var_os("NOVA_UPDATE_PHASE_TABLE").is_some() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("reference directory is creatable");
        }
        std::fs::write(&path, &rendered).expect("table is writable");
        return;
    }

    let stored = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "cannot read {}: {err}\nregenerate with NOVA_UPDATE_PHASE_TABLE=1 cargo test -p nova-probe --test table",
            path.display()
        )
    });
    assert_eq!(
        stored.replace("\r\n", "\n"),
        rendered,
        "the classifier and {} disagree; regenerate with \
         NOVA_UPDATE_PHASE_TABLE=1 cargo test -p nova-probe --test table, \
         then bring tgrelay/phase.py in step",
        path.display()
    );
}

#[test]
fn the_table_covers_every_pair() {
    // Cheap insurance that a future edit to `cases()` cannot quietly drop a
    // combination and take its guarantee of totality with it.
    let generated = cases();
    for reached in ALL_REACHED {
        for ended in ALL_ENDED {
            assert!(
                generated
                    .iter()
                    .any(|a| a.reached == reached && a.ended == ended),
                "{reached:?}/{ended:?} is not in the table"
            );
        }
    }
}
