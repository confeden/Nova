//! Differential parity with the Python original this crate was ported from.
//!
//! The expectations below are not hand-written: they were produced by running
//! `_split_http_authority`, `_wss_route_kind`, `_ws_domains` and
//! `_cf_ws_domains_for_bases` out of `tgrelay/transparent_relay.py` over this
//! exact corpus and recording what they returned. The circuit-breaker table was
//! produced the same way, by pulling the two conditional expressions out of
//! `_note_wss_first_byte_result` **by AST** rather than retyping them and
//! evaluating both over all eight inputs. Anything that changes here changes
//! behaviour the running relay already depends on.
//!
//! The corpus deliberately includes the cases where two languages are most
//! likely to drift: bracketed IPv6, a colon inside the host, an empty port,
//! ports that are numeric but out of range, the Worker race order under a
//! scripted history, and DC 203 — which is DC 2 wearing a
//! different number and must never reach a formatted hostname.

use nova_tgrelay::supervisor::{Restart, RestartPolicy};
use nova_tgrelay::wsframe::{apply_mask, build_frame, Opcode};
use nova_tgrelay::cfdomains::{empty_route_ttl, score_gain, CfDomainHealth, EMPTY_TTL};
use nova_tgrelay::egress::Dc;
use nova_tgrelay::wss::{cf_domains, disable_ttl, trip_threshold, web_domains, CircuitContext};
use nova_tgrelay::{split_http_authority, WssRouteKind};
use std::time::Duration;

/// `(input, Some((host, port)))` or `(input, None)` when Python returned
/// `(None, None)`.
const AUTHORITY_CASES: &[(&str, Option<(&str, u16)>)] = &[
    ("example.com:8443", Some(("example.com", 8443))),
    ("example.com", Some(("example.com", 443))),
    ("example.com:", Some(("example.com", 443))),
    ("[2001:db8::1]:443", Some(("2001:db8::1", 443))),
    ("[2001:db8::1]", Some(("2001:db8::1", 443))),
    ("[::1]:80", Some(("::1", 80))),
    ("[2001:db8::1", None),
    ("[::1]x", None),
    ("[]:443", None),
    ("  example.com:443  ", Some(("example.com", 443))),
    ("example.com:0", None),
    ("example.com:65536", None),
    ("example.com:-1", None),
    ("example.com:https", None),
    ("example.com:0x10", None),
    ("example.com:1", Some(("example.com", 1))),
    ("example.com:65535", Some(("example.com", 65535))),
    ("", None),
    ("   ", None),
    (":443", None),
    // Split on the LAST colon: everything before it is the host, colons and all.
    ("a:b:c:443", Some(("a:b:c", 443))),
    ("host::443", Some(("host:", 443))),
    ("1.2.3.4:53", Some(("1.2.3.4", 53))),
];

const ROUTE_CASES: &[(&str, WssRouteKind)] = &[
    ("kws2.web.telegram.org via warp-socks", WssRouteKind::Web),
    ("kws5-1.web.telegram.org via opera-http", WssRouteKind::Web),
    ("kws2.web.telegram.org@149.154.167.99 via direct", WssRouteKind::Web),
    ("WEB.TELEGRAM.ORG via direct", WssRouteKind::Web),
    ("kws2.nova-app.eu via warp-socks", WssRouteKind::Cf),
    ("kws2-1.pclead.co.uk@104.21.0.1 via direct", WssRouteKind::Cf),
    ("", WssRouteKind::Cf),
    (" ", WssRouteKind::Cf),
    (" via ", WssRouteKind::Cf),
    ("@", WssRouteKind::Cf),
    ("garbage", WssRouteKind::Cf),
    ("notweb.telegram.org.evil.example via direct", WssRouteKind::Cf),
];

#[test]
fn connect_authority_matches_the_python_original() {
    for (input, expected) in AUTHORITY_CASES {
        let got = split_http_authority(input).map(|a| (a.host().to_string(), a.port()));
        let want = expected.map(|(h, p)| (h.to_string(), p));
        assert_eq!(got, want, "input {input:?}");
    }
}

#[test]
fn wss_route_kind_matches_the_python_original() {
    for (input, expected) in ROUTE_CASES {
        assert_eq!(WssRouteKind::from_label(input), *expected, "input {input:?}");
    }
}

#[test]
fn the_corpus_covers_both_outcomes_for_each_parser() {
    // A parity table that only ever expects one answer proves nothing.
    assert!(AUTHORITY_CASES.iter().any(|(_, e)| e.is_some()));
    assert!(AUTHORITY_CASES.iter().any(|(_, e)| e.is_none()));
    assert!(ROUTE_CASES.iter().any(|(_, k)| *k == WssRouteKind::Web));
    assert!(ROUTE_CASES.iter().any(|(_, k)| *k == WssRouteKind::Cf));
}

/// `(dc, media, domains)` — what `_ws_domains` returned.
const WEB_DOMAIN_CASES: &[(u16, bool, &[&str])] = &[
    (1, false, &["kws1.web.telegram.org"]),
    (1, true, &["kws1-1.web.telegram.org", "kws1.web.telegram.org"]),
    (2, false, &["kws2.web.telegram.org"]),
    (2, true, &["kws2-1.web.telegram.org", "kws2.web.telegram.org"]),
    (4, false, &["kws4.web.telegram.org"]),
    (4, true, &["kws4-1.web.telegram.org", "kws4.web.telegram.org"]),
    (5, false, &["kws5.web.telegram.org"]),
    (5, true, &["kws5-1.web.telegram.org", "kws5.web.telegram.org"]),
    (203, false, &["kws2.web.telegram.org"]),
    (203, true, &["kws2-1.web.telegram.org", "kws2.web.telegram.org"]),
];

const MESSY_BASES: &[&str] = &["nova-app.eu", "  PCLead.co.uk ", "nova-app.eu", "", "   "];

/// `(dc, bases, media, domains)` — what `_cf_ws_domains_for_bases` returned.
const CF_DOMAIN_CASES: &[(u16, &[&str], bool, &[&str])] = &[
    (2, &["nova-app.eu"], false, &["kws2.nova-app.eu"]),
    (2, &["nova-app.eu"], true, &["kws2-1.nova-app.eu"]),
    (4, MESSY_BASES, false, &["kws4.nova-app.eu", "kws4.pclead.co.uk"]),
    (4, MESSY_BASES, true, &["kws4-1.nova-app.eu", "kws4-1.pclead.co.uk"]),
    (203, &["nova-app.eu"], false, &["kws2.nova-app.eu"]),
    (203, &["nova-app.eu"], true, &["kws2-1.nova-app.eu"]),
    (2, &[], false, &[]),
    (2, &["", "  "], true, &[]),
];

/// `(media, has_custom_cf, has_recent_good, threshold, ttl_seconds)`.
const CIRCUIT_CASES: &[(bool, bool, bool, u32, u64)] = &[
    (true, true, true, 2, 3),
    (true, true, false, 2, 3),
    (true, false, true, 4, 3),
    (true, false, false, 2, 8),
    (false, true, true, 4, 3),
    (false, true, false, 3, 15),
    (false, false, true, 4, 3),
    (false, false, false, 2, 15),
];

#[test]
fn web_domains_match_the_python_original() {
    for (dc, media, expected) in WEB_DOMAIN_CASES {
        let got = web_domains(Dc::new(*dc).expect("dc"), *media);
        assert_eq!(got, *expected, "dc={dc} media={media}");
    }
}

#[test]
fn worker_domains_match_the_python_original() {
    for (dc, bases, media, expected) in CF_DOMAIN_CASES {
        let got = cf_domains(Dc::new(*dc).expect("dc"), bases, *media);
        assert_eq!(got, *expected, "dc={dc} media={media} bases={bases:?}");
    }
}

#[test]
fn the_first_byte_circuit_table_matches_the_python_original() {
    for (media, has_custom_cf, has_recent_good, threshold, ttl) in CIRCUIT_CASES {
        let ctx = CircuitContext { has_custom_cf: *has_custom_cf, has_recent_good: *has_recent_good };
        assert_eq!(trip_threshold(*media, ctx), *threshold, "threshold {media} {has_custom_cf} {has_recent_good}");
        assert_eq!(
            disable_ttl(*media, ctx),
            Duration::from_secs(*ttl),
            "ttl {media} {has_custom_cf} {has_recent_good}"
        );
    }
}

#[test]
fn the_domain_and_circuit_corpora_cover_more_than_one_answer_each() {
    assert!(WEB_DOMAIN_CASES.iter().any(|(_, _, d)| d.len() == 1));
    assert!(WEB_DOMAIN_CASES.iter().any(|(_, _, d)| d.len() == 2));
    assert!(CF_DOMAIN_CASES.iter().any(|(_, _, _, d)| d.is_empty()));
    assert!(CF_DOMAIN_CASES.iter().any(|(_, _, _, d)| d.len() == 2));
    // All eight inputs, and more than one answer on each axis.
    assert_eq!(CIRCUIT_CASES.len(), 8);
    assert_eq!(CIRCUIT_CASES.iter().map(|c| c.3).collect::<std::collections::BTreeSet<_>>().len(), 3);
    assert_eq!(CIRCUIT_CASES.iter().map(|c| c.4).collect::<std::collections::BTreeSet<_>>().len(), 3);
}

/// The three Worker zones in the order Nova configures them.
fn zones() -> Vec<String> {
    ["kws2.nova-app.eu", "kws2.pclead.co.uk", "kws2.offshor.co.uk"].iter().map(|s| s.to_string()).collect()
}

fn as_str(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// Produced by driving `_cf_order_domains`, `_cf_note_bad_domain` and
/// `_cf_note_good_route_label` — extracted from the relay class by AST and bound
/// to a stub holding only the three dictionaries they touch.
#[test]
fn the_worker_race_order_matches_the_python_original() {
    let now = std::time::Instant::now();

    let empty = CfDomainHealth::new();
    assert_eq!(empty.order(&zones(), None, now), zones(), "nothing measured");

    let mut benched = CfDomainHealth::new();
    benched.note_bad("kws2.pclead.co.uk", EMPTY_TTL, now);
    assert_eq!(
        as_str(&benched.order(&zones(), None, now)),
        ["kws2.nova-app.eu", "kws2.offshor.co.uk"],
        "pclead benched"
    );

    let mut scored = CfDomainHealth::new();
    scored.note_good("kws2.offshor.co.uk", 1_000_000, now);
    assert_eq!(
        as_str(&scored.order(&zones(), None, now)),
        ["kws2.offshor.co.uk", "kws2.nova-app.eu", "kws2.pclead.co.uk"],
        "offshor carried 1 MB"
    );

    let mut mixed = CfDomainHealth::new();
    mixed.note_good("kws2.offshor.co.uk", 10_000_000, now);
    mixed.note_good("kws2.pclead.co.uk", 1, now);
    assert_eq!(
        as_str(&mixed.order(&zones(), Some("kws2.pclead.co.uk"), now)),
        ["kws2.pclead.co.uk", "kws2.offshor.co.uk", "kws2.nova-app.eu"],
        "last-good outranks a better score"
    );

    let mut benched_last_good = CfDomainHealth::new();
    benched_last_good.note_bad("kws2.pclead.co.uk", EMPTY_TTL, now);
    assert_eq!(
        as_str(&benched_last_good.order(&zones(), Some("kws2.pclead.co.uk"), now)),
        ["kws2.nova-app.eu", "kws2.offshor.co.uk"],
        "a benched last-good does not come back through the side door"
    );
}

#[test]
fn the_worker_score_arithmetic_matches_the_python_original() {
    let now = std::time::Instant::now();
    let mut health = CfDomainHealth::new();
    health.note_good("kws2.nova-app.eu", 4096, now);
    assert_eq!(health.fresh_score("kws2.nova-app.eu", now), 8.5);
    health.note_bad("kws2.nova-app.eu", EMPTY_TTL, now);
    assert_eq!(health.fresh_score("kws2.nova-app.eu", now), 4.25);

    assert_eq!(score_gain(1), 2.5);
    assert_eq!(score_gain(10 * 1024 * 1024), 14.0);
    assert_eq!(score_gain(1u64 << 63), 25.0);

    // `_cf_empty_route_ttl`, same three inputs.
    assert_eq!(empty_route_ttl(false, false, false).as_secs(), 30);
    assert_eq!(empty_route_ttl(false, true, false).as_secs(), 60);
    assert_eq!(empty_route_ttl(true, true, true).as_secs(), 6);
}

/// The mask `os.urandom` was monkeypatched to return while the oracle ran.
const ORACLE_MASK: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// `(payload_len, first bytes of the frame as hex, total frame length)` —
/// printed by `RawWebSocket._build_frame(OP_BINARY, b"\xa5" * n, mask=True)`.
const FRAME_CASES: &[(usize, &str, usize)] = &[
    (0, "8280deadbeef", 6),
    (1, "8281deadbeef7b", 7),
    (125, "82fddeadbeef7b081b4a7b081b4a", 131),
    (126, "82fe007edeadbeef7b081b4a7b08", 134),
    (65535, "82feffffdeadbeef7b081b4a7b08", 65543),
    (65536, "82ff0000000000010000deadbeef", 65550),
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn websocket_frames_match_the_python_original_byte_for_byte() {
    for (len, prefix, total) in FRAME_CASES {
        let frame = build_frame(Opcode::Binary, &vec![0xA5u8; *len], Some(ORACLE_MASK));
        assert_eq!(frame.len(), *total, "total length for payload {len}");
        let want = prefix.len() / 2;
        assert_eq!(hex(&frame[..want.min(frame.len())]), *prefix, "header for payload {len}");
    }
}

#[test]
fn the_mask_matches_the_pythons_big_integer_xor() {
    // `_xor_mask` XORs the whole payload as one integer against a repeated key.
    // Byte-wise with the key cycling from index 0 is the same thing, and this is
    // the value the original printed for it.
    let mut data = b"telegram".to_vec();
    apply_mask(&mut data, ORACLE_MASK);
    assert_eq!(hex(&data), "aac8d28ab9dfdf82");
    apply_mask(&mut data, ORACLE_MASK);
    assert_eq!(data, b"telegram");
}

/// Produced by extracting `_thread_main` from the relay class by AST and running
/// it against a fake clock and a scripted `_run_once`, so the loop under test is
/// the one that ships.
#[test]
fn the_restart_schedule_matches_the_python_original() {
    // Eight one-second crashes: the Python slept 75 s in total.
    let mut policy = RestartPolicy::default();
    let mut total = 0u64;
    let mut announced = Vec::new();
    for _ in 0..8 {
        match policy.record(Duration::from_secs(1), true) {
            Restart::After { delay, attempt, announce } => {
                total += delay.as_secs();
                if announce {
                    announced.push(attempt);
                }
            }
            Restart::Stop => panic!("a crash does not stop the relay"),
        }
    }
    assert_eq!(total, 75);
    assert_eq!(announced, [1, 5]);

    // Twelve crashes: 135 s, announced at 1, 5 and 10.
    let mut policy = RestartPolicy::default();
    let mut total = 0u64;
    let mut announced = Vec::new();
    for _ in 0..12 {
        if let Restart::After { delay, attempt, announce } = policy.record(Duration::from_secs(1), true) {
            total += delay.as_secs();
            if announce {
                announced.push(attempt);
            }
        }
    }
    assert_eq!(total, 135);
    assert_eq!(announced, [1, 5, 10]);

    // Four crashes, a healthy run, then one more: 18 s, and the healthy run puts
    // the counter back to 1 so the next failure is news again.
    let mut policy = RestartPolicy::default();
    let mut total = 0u64;
    let mut announced = Vec::new();
    for uptime in [1u64, 1, 1, 1, 30, 1] {
        if let Restart::After { delay, attempt, announce } =
            policy.record(Duration::from_secs(uptime), true)
        {
            total += delay.as_secs();
            if announce {
                announced.push(attempt);
            }
        }
    }
    assert_eq!(total, 18);
    assert_eq!(announced, [1, 1]);

    // An ordered exit sleeps not at all.
    let mut policy = RestartPolicy::default();
    assert_eq!(policy.record(Duration::from_secs(5), false), Restart::Stop);
}

#[test]
fn the_restart_line_matches_the_python_original() {
    // Copied from the oracle's output, Cyrillic included: this is a search key.
    assert_eq!(
        RestartPolicy::restart_line(Duration::from_secs(1), 1, Duration::from_secs(1)),
        "[TgRelay] Релей упал после 1с (попытка 1); перезапуск через 1с."
    );
    assert_eq!(
        RestartPolicy::restart_line(Duration::from_secs(1), 5, Duration::from_secs(15)),
        "[TgRelay] Релей упал после 1с (попытка 5); перезапуск через 15с."
    );
    assert_eq!(
        RestartPolicy::restart_line(Duration::from_secs(30), 1, Duration::from_secs(1)),
        "[TgRelay] Релей упал после 30с (попытка 1); перезапуск через 1с."
    );
}
