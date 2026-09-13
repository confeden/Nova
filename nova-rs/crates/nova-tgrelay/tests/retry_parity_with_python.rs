//! The after-empty decisions, against the ones the shipped Python makes.
//!
//! Layer 29. Both tables were produced by **executing** expressions lifted from
//! `tgrelay/transparent_relay.py` by AST: the two `media_stalled` assignments and
//! the two `If` tests of the empty-response tail. Generator:
//! `temp/retry_oracle.py`.
//!
//! The same run answered a question the port's own comment makes a claim about:
//! the `media_stalled` formula in the main media path (`:2790`) and the one in
//! the retry (`:3671`) **disagree in 0 of 72 cases**. They are written
//! differently — only the retry spells the `0 <` — and they are equivalent
//! because the other one sits under `if down > 0`.

use nova_tgrelay::retry::{after_empty, verdict, AfterEmpty, Verdict};
use std::time::Duration;

/// `(target_port, recent_good, owned_zone_available, step)`
const TAIL: &[(u16, bool, bool, AfterEmpty)] = &[
    (80, true, true, AfterEmpty::CloseQuietly),
    (80, true, false, AfterEmpty::CloseQuietly),
    (80, false, true, AfterEmpty::SkipTcpFallback),
    (80, false, false, AfterEmpty::TcpFallback),
    (443, true, true, AfterEmpty::SkipTcpFallback),
    (443, true, false, AfterEmpty::TcpFallback),
    (443, false, true, AfterEmpty::SkipTcpFallback),
    (443, false, false, AfterEmpty::TcpFallback),
    (2053, true, true, AfterEmpty::SkipTcpFallback),
    (2053, true, false, AfterEmpty::TcpFallback),
    (2053, false, true, AfterEmpty::SkipTcpFallback),
    (2053, false, false, AfterEmpty::TcpFallback),
];

/// `(media, down, duration_ms, verdict)`
const VERDICTS: &[(bool, u64, u64, Verdict)] = &[
    (true, 0, 0, Verdict::Empty),
    (true, 0, 500, Verdict::Empty),
    (true, 0, 1799, Verdict::Empty),
    (true, 0, 1800, Verdict::Empty),
    (true, 0, 4018, Verdict::Empty),
    (true, 0, 30000, Verdict::Empty),
    (true, 1, 0, Verdict::Carried),
    (true, 1, 500, Verdict::Carried),
    (true, 1, 1799, Verdict::Carried),
    (true, 1, 1800, Verdict::MediaStalled),
    (true, 1, 4018, Verdict::MediaStalled),
    (true, 1, 30000, Verdict::MediaStalled),
    (true, 100, 0, Verdict::Carried),
    (true, 100, 500, Verdict::Carried),
    (true, 100, 1799, Verdict::Carried),
    (true, 100, 1800, Verdict::MediaStalled),
    (true, 100, 4018, Verdict::MediaStalled),
    (true, 100, 30000, Verdict::MediaStalled),
    (true, 4095, 0, Verdict::Carried),
    (true, 4095, 500, Verdict::Carried),
    (true, 4095, 1799, Verdict::Carried),
    (true, 4095, 1800, Verdict::MediaStalled),
    (true, 4095, 4018, Verdict::MediaStalled),
    (true, 4095, 30000, Verdict::MediaStalled),
    (true, 4096, 0, Verdict::Carried),
    (true, 4096, 500, Verdict::Carried),
    (true, 4096, 1799, Verdict::Carried),
    (true, 4096, 1800, Verdict::Carried),
    (true, 4096, 4018, Verdict::Carried),
    (true, 4096, 30000, Verdict::Carried),
    (true, 65536, 0, Verdict::Carried),
    (true, 65536, 500, Verdict::Carried),
    (true, 65536, 1799, Verdict::Carried),
    (true, 65536, 1800, Verdict::Carried),
    (true, 65536, 4018, Verdict::Carried),
    (true, 65536, 30000, Verdict::Carried),
    (false, 0, 0, Verdict::Empty),
    (false, 0, 500, Verdict::Empty),
    (false, 0, 1799, Verdict::Empty),
    (false, 0, 1800, Verdict::Empty),
    (false, 0, 4018, Verdict::Empty),
    (false, 0, 30000, Verdict::Empty),
    (false, 1, 0, Verdict::Carried),
    (false, 1, 500, Verdict::Carried),
    (false, 1, 1799, Verdict::Carried),
    (false, 1, 1800, Verdict::Carried),
    (false, 1, 4018, Verdict::Carried),
    (false, 1, 30000, Verdict::Carried),
    (false, 100, 0, Verdict::Carried),
    (false, 100, 500, Verdict::Carried),
    (false, 100, 1799, Verdict::Carried),
    (false, 100, 1800, Verdict::Carried),
    (false, 100, 4018, Verdict::Carried),
    (false, 100, 30000, Verdict::Carried),
    (false, 4095, 0, Verdict::Carried),
    (false, 4095, 500, Verdict::Carried),
    (false, 4095, 1799, Verdict::Carried),
    (false, 4095, 1800, Verdict::Carried),
    (false, 4095, 4018, Verdict::Carried),
    (false, 4095, 30000, Verdict::Carried),
    (false, 4096, 0, Verdict::Carried),
    (false, 4096, 500, Verdict::Carried),
    (false, 4096, 1799, Verdict::Carried),
    (false, 4096, 1800, Verdict::Carried),
    (false, 4096, 4018, Verdict::Carried),
    (false, 4096, 30000, Verdict::Carried),
    (false, 65536, 0, Verdict::Carried),
    (false, 65536, 500, Verdict::Carried),
    (false, 65536, 1799, Verdict::Carried),
    (false, 65536, 1800, Verdict::Carried),
    (false, 65536, 4018, Verdict::Carried),
    (false, 65536, 30000, Verdict::Carried),
];

#[test]
fn the_empty_response_tail_matches_the_python_for_every_combination() {
    for (port, recent, owned, expected) in TAIL {
        assert_eq!(
            after_empty(*port, *recent, *owned),
            *expected,
            "port={port} recent_good={recent} owned={owned}"
        );
    }
}

#[test]
fn every_tunnel_ending_is_judged_the_way_the_python_judges_it() {
    for (media, down, ms, expected) in VERDICTS {
        assert_eq!(
            verdict(*media, *down, Duration::from_millis(*ms)),
            *expected,
            "media={media} down={down} duration_ms={ms}"
        );
    }
}

#[test]
fn the_table_covers_both_sides_of_every_threshold() {
    // A table that lost a case would pass the comparisons above while testing
    // nothing about it.
    for want in [Verdict::Empty, Verdict::Carried, Verdict::MediaStalled] {
        assert!(VERDICTS.iter().any(|r| r.3 == want), "no row is {want:?}");
    }
    for want in [AfterEmpty::CloseQuietly, AfterEmpty::SkipTcpFallback, AfterEmpty::TcpFallback] {
        assert!(TAIL.iter().any(|r| r.3 == want), "no row is {want:?}");
    }
    assert!(VERDICTS.iter().any(|r| r.2 == 1799), "the millisecond below the stall threshold");
    assert!(VERDICTS.iter().any(|r| r.2 == 1800), "and the one at it");
}
