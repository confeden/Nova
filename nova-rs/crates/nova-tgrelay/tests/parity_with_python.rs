//! Differential parity with the Python original this crate was ported from.
//!
//! The expectations below are not hand-written: they were produced by running
//! `_split_http_authority` and `_wss_route_kind` out of
//! `tgrelay/transparent_relay.py` over this exact corpus and recording what they
//! returned. Anything that changes here changes behaviour the running relay
//! already depends on.
//!
//! The corpus deliberately includes the cases where two languages are most
//! likely to drift: bracketed IPv6, a colon inside the host, an empty port, and
//! ports that are numeric but out of range.

use nova_tgrelay::{split_http_authority, WssRouteKind};

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
