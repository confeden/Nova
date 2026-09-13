//! Data-centre attribution, against the Python that ships.
//!
//! Every row below was produced by **executing** `_domain_dc`,
//! `_target_dc_hint`, `_likely_media_target` and `_preferred_ws_target` — the
//! functions extracted from `transparent_relay.py` by AST — over these exact
//! inputs. The corpus deliberately includes the boundaries of every network in
//! the table (`91.108.56.0/22`, `149.154.171.0/24`, `149.154.167.0/24`,
//! `149.154.175.48/28` and the three IPv6 /64s), one address just outside each,
//! and the addresses that are special-cased before the ranges are consulted.
//!
//! A misattributed DC does not fail. It files a working route under the wrong
//! health bucket and goes on doing so, which is why this is checked exhaustively
//! rather than at a few points.

use nova_tgrelay::dc::{domain_dc, likely_media_target, preferred_ws_target, target_dc_hint};
use nova_tgrelay::egress::Dc;

fn dc_number(dc: Option<Dc>) -> u16 {
    dc.map_or(0, Dc::get)
}

/// `(domain, dc)` — `0` where the Python returned `0`.
const DOMAIN_CASES: &[(&str, u16)] = &[
    ("pluto.web.telegram.org", 1),
    ("kws1.nova-app.eu", 1),
    ("venus", 2),
    ("kws2-1.x", 2),
    ("aurora1", 3),
    ("kws3.y", 3),
    ("vesta.z", 4),
    ("kws4-1.q", 4),
    ("flora", 5),
    ("kws5.web.telegram.org", 5),
    ("kws203.a", 2),
    ("KWS2.Upper", 2),
    ("other.example", 0),
    ("", 0),
];

/// `(address, media, dc)`.
const HINT_CASES: &[(&str, bool, u16)] = &[
    ("149.154.175.50", false, 1),
    ("149.154.175.50", true, 1),
    ("149.154.175.51", false, 1),
    ("149.154.175.51", true, 1),
    ("149.154.175.53", false, 1),
    ("149.154.175.53", true, 1),
    ("149.154.175.54", false, 1),
    ("149.154.175.54", true, 1),
    ("149.154.175.55", false, 1),
    ("149.154.175.55", true, 1),
    ("149.154.175.59", false, 1),
    ("149.154.175.59", true, 1),
    ("149.154.175.52", false, 1),
    ("149.154.175.52", true, 1),
    ("149.154.167.35", false, 2),
    ("149.154.167.35", true, 2),
    ("149.154.167.36", false, 2),
    ("149.154.167.36", true, 2),
    ("149.154.167.41", false, 2),
    ("149.154.167.41", true, 2),
    ("149.154.167.50", false, 2),
    ("149.154.167.50", true, 2),
    ("149.154.167.51", false, 2),
    ("149.154.167.51", true, 2),
    ("149.154.167.220", false, 2),
    ("149.154.167.220", true, 2),
    ("95.161.76.100", false, 2),
    ("95.161.76.100", true, 2),
    ("149.154.162.123", false, 2),
    ("149.154.162.123", true, 2),
    ("149.154.167.151", false, 2),
    ("149.154.167.151", true, 2),
    ("149.154.167.222", false, 2),
    ("149.154.167.222", true, 2),
    ("149.154.167.223", false, 2),
    ("149.154.167.223", true, 2),
    ("149.154.167.99", false, 2),
    ("149.154.167.99", true, 2),
    ("149.154.175.100", false, 3),
    ("149.154.175.100", true, 3),
    ("149.154.175.101", false, 3),
    ("149.154.175.101", true, 3),
    ("149.154.175.102", false, 3),
    ("149.154.175.102", true, 3),
    ("149.154.164.250", false, 4),
    ("149.154.164.250", true, 4),
    ("149.154.165.111", false, 4),
    ("149.154.165.111", true, 4),
    ("149.154.166.120", false, 4),
    ("149.154.166.120", true, 4),
    ("149.154.166.121", false, 4),
    ("149.154.166.121", true, 4),
    ("149.154.167.91", false, 4),
    ("149.154.167.91", true, 4),
    ("149.154.167.92", false, 4),
    ("149.154.167.92", true, 4),
    ("149.154.167.118", false, 4),
    ("149.154.167.118", true, 4),
    ("91.108.56.100", false, 5),
    ("91.108.56.100", true, 5),
    ("91.108.56.101", false, 5),
    ("91.108.56.101", true, 5),
    ("91.108.56.102", false, 5),
    ("91.108.56.102", true, 5),
    ("91.108.56.116", false, 5),
    ("91.108.56.116", true, 5),
    ("91.108.56.126", false, 5),
    ("91.108.56.126", true, 5),
    ("91.108.56.128", false, 5),
    ("91.108.56.128", true, 5),
    ("91.108.56.123", false, 5),
    ("91.108.56.123", true, 5),
    ("91.108.56.151", false, 5),
    ("91.108.56.151", true, 5),
    ("149.154.171.5", false, 5),
    ("149.154.171.5", true, 5),
    ("91.105.192.100", false, 203),
    ("91.105.192.100", true, 203),
    ("173.239.243.185", false, 5),
    ("173.239.243.185", true, 5),
    ("5.28.195.2", false, 4),
    ("5.28.195.2", true, 4),
    ("149.154.167.255", false, 4),
    ("149.154.167.255", true, 4),
    ("91.108.56.0", false, 5),
    ("91.108.56.0", true, 5),
    ("91.108.59.255", false, 5),
    ("91.108.59.255", true, 5),
    ("91.108.60.0", false, 0),
    ("91.108.60.0", true, 0),
    ("149.154.171.0", false, 5),
    ("149.154.171.0", true, 5),
    ("149.154.171.255", false, 5),
    ("149.154.171.255", true, 5),
    ("149.154.172.0", false, 0),
    ("149.154.172.0", true, 0),
    ("149.154.167.0", false, 2),
    ("149.154.167.0", true, 2),
    ("149.154.168.0", false, 0),
    ("149.154.168.0", true, 0),
    ("149.154.175.48", false, 1),
    ("149.154.175.48", true, 1),
    ("149.154.175.63", false, 1),
    ("149.154.175.63", true, 1),
    ("149.154.175.64", false, 0),
    ("149.154.175.64", true, 0),
    ("2001:67c:4e8:f002::1", false, 2),
    ("2001:67c:4e8:f002::1", true, 2),
    ("2001:67c:4e8:f004::5", false, 4),
    ("2001:67c:4e8:f004::5", true, 4),
    ("2001:b28:f23f:f005::7", false, 5),
    ("2001:b28:f23f:f005::7", true, 5),
    ("2001:db8::1", false, 0),
    ("2001:db8::1", true, 0),
    ("8.8.8.8", false, 0),
    ("8.8.8.8", true, 0),
    ("not-an-ip", false, 0),
    ("not-an-ip", true, 0),
    ("", false, 0),
    ("", true, 0),
];

/// `(address, port, dc, is_media)`.
const MEDIA_CASES: &[(&str, u16, u16, bool)] = &[
    ("149.154.167.99", 443, 2, true),
    ("149.154.167.99", 443, 4, true),
    ("149.154.167.99", 80, 2, true),
    ("149.154.167.99", 80, 4, true),
    ("149.154.167.99", 7300, 2, true),
    ("149.154.167.99", 7300, 4, true),
    ("149.154.167.99", 7305, 2, true),
    ("149.154.167.99", 7305, 4, true),
    ("149.154.167.99", 7310, 2, true),
    ("149.154.167.99", 7310, 4, true),
    ("149.154.167.99", 7311, 2, true),
    ("149.154.167.99", 7311, 4, true),
    ("5.28.195.2", 443, 2, true),
    ("5.28.195.2", 443, 4, true),
    ("5.28.195.2", 80, 2, true),
    ("5.28.195.2", 80, 4, true),
    ("5.28.195.2", 7300, 2, true),
    ("5.28.195.2", 7300, 4, true),
    ("5.28.195.2", 7305, 2, true),
    ("5.28.195.2", 7305, 4, true),
    ("5.28.195.2", 7310, 2, true),
    ("5.28.195.2", 7310, 4, true),
    ("5.28.195.2", 7311, 2, true),
    ("5.28.195.2", 7311, 4, true),
    ("149.154.167.91", 443, 2, false),
    ("149.154.167.91", 443, 4, false),
    ("149.154.167.91", 80, 2, false),
    ("149.154.167.91", 80, 4, false),
    ("149.154.167.91", 7300, 2, false),
    ("149.154.167.91", 7300, 4, false),
    ("149.154.167.91", 7305, 2, false),
    ("149.154.167.91", 7305, 4, false),
    ("149.154.167.91", 7310, 2, false),
    ("149.154.167.91", 7310, 4, false),
    ("149.154.167.91", 7311, 2, false),
    ("149.154.167.91", 7311, 4, false),
    ("149.154.167.51", 443, 2, false),
    ("149.154.167.51", 443, 4, false),
    ("149.154.167.51", 80, 2, false),
    ("149.154.167.51", 80, 4, false),
    ("149.154.167.51", 7300, 2, false),
    ("149.154.167.51", 7300, 4, false),
    ("149.154.167.51", 7305, 2, false),
    ("149.154.167.51", 7305, 4, false),
    ("149.154.167.51", 7310, 2, false),
    ("149.154.167.51", 7310, 4, false),
    ("149.154.167.51", 7311, 2, false),
    ("149.154.167.51", 7311, 4, false),
    ("149.154.175.52", 443, 2, true),
    ("149.154.175.52", 443, 4, true),
    ("149.154.175.52", 80, 2, true),
    ("149.154.175.52", 80, 4, true),
    ("149.154.175.52", 7300, 2, true),
    ("149.154.175.52", 7300, 4, true),
    ("149.154.175.52", 7305, 2, true),
    ("149.154.175.52", 7305, 4, true),
    ("149.154.175.52", 7310, 2, true),
    ("149.154.175.52", 7310, 4, true),
    ("149.154.175.52", 7311, 2, true),
    ("149.154.175.52", 7311, 4, true),
    ("8.8.8.8", 443, 2, false),
    ("8.8.8.8", 443, 4, true),
    ("8.8.8.8", 80, 2, false),
    ("8.8.8.8", 80, 4, true),
    ("8.8.8.8", 7300, 2, false),
    ("8.8.8.8", 7300, 4, false),
    ("8.8.8.8", 7305, 2, false),
    ("8.8.8.8", 7305, 4, false),
    ("8.8.8.8", 7310, 2, false),
    ("8.8.8.8", 7310, 4, false),
    ("8.8.8.8", 7311, 2, false),
    ("8.8.8.8", 7311, 4, false),
    ("", 443, 2, false),
    ("", 443, 4, true),
    ("", 80, 2, false),
    ("", 80, 4, true),
    ("", 7300, 2, false),
    ("", 7300, 4, false),
    ("", 7305, 2, false),
    ("", 7305, 4, false),
    ("", 7310, 2, false),
    ("", 7310, 4, false),
    ("", 7311, 2, false),
    ("", 7311, 4, false),
];

/// `(address, dc, media, chosen)`.
const PREFERRED_CASES: &[(&str, u16, bool, &str)] = &[
    ("149.154.167.51", 1, false, "149.154.167.51"),
    ("149.154.167.51", 1, true, "149.154.167.51"),
    ("149.154.167.51", 2, false, "149.154.167.220"),
    ("149.154.167.51", 2, true, "149.154.167.220"),
    ("149.154.167.51", 4, false, "149.154.167.51"),
    ("149.154.167.51", 4, true, "149.154.167.220"),
    ("149.154.167.51", 5, false, "149.154.167.51"),
    ("149.154.167.51", 5, true, "149.154.167.51"),
    ("5.28.195.2", 1, false, "5.28.195.2"),
    ("5.28.195.2", 1, true, "5.28.195.2"),
    ("5.28.195.2", 2, false, "149.154.167.220"),
    ("5.28.195.2", 2, true, "149.154.167.220"),
    ("5.28.195.2", 4, false, "149.154.167.220"),
    ("5.28.195.2", 4, true, "149.154.167.220"),
    ("5.28.195.2", 5, false, "5.28.195.2"),
    ("5.28.195.2", 5, true, "5.28.195.2"),
    ("149.154.167.91", 1, false, "149.154.167.91"),
    ("149.154.167.91", 1, true, "149.154.167.91"),
    ("149.154.167.91", 2, false, "149.154.167.220"),
    ("149.154.167.91", 2, true, "149.154.167.220"),
    ("149.154.167.91", 4, false, "149.154.167.220"),
    ("149.154.167.91", 4, true, "149.154.167.220"),
    ("149.154.167.91", 5, false, "149.154.167.91"),
    ("149.154.167.91", 5, true, "149.154.167.91"),
    ("149.154.167.255", 1, false, "149.154.167.255"),
    ("149.154.167.255", 1, true, "149.154.167.255"),
    ("149.154.167.255", 2, false, "149.154.167.220"),
    ("149.154.167.255", 2, true, "149.154.167.220"),
    ("149.154.167.255", 4, false, "149.154.167.220"),
    ("149.154.167.255", 4, true, "149.154.167.220"),
    ("149.154.167.255", 5, false, "149.154.167.255"),
    ("149.154.167.255", 5, true, "149.154.167.255"),
    ("1.2.3.4", 1, false, "1.2.3.4"),
    ("1.2.3.4", 1, true, "1.2.3.4"),
    ("1.2.3.4", 2, false, "149.154.167.220"),
    ("1.2.3.4", 2, true, "149.154.167.220"),
    ("1.2.3.4", 4, false, "1.2.3.4"),
    ("1.2.3.4", 4, true, "149.154.167.220"),
    ("1.2.3.4", 5, false, "1.2.3.4"),
    ("1.2.3.4", 5, true, "1.2.3.4"),
];

#[test]
fn domain_attribution_matches_the_python_original() {
    for (domain, expected) in DOMAIN_CASES {
        assert_eq!(dc_number(domain_dc(domain)), *expected, "domain {domain:?}");
    }
}

#[test]
fn address_attribution_matches_the_python_original() {
    for (ip, media, expected) in HINT_CASES {
        assert_eq!(dc_number(target_dc_hint(ip, *media)), *expected, "ip {ip} media={media}");
    }
}

#[test]
fn media_attribution_matches_the_python_original() {
    for (ip, port, dc, expected) in MEDIA_CASES {
        assert_eq!(
            likely_media_target(ip, *port, Dc::new(*dc)),
            *expected,
            "ip {ip} port {port} dc {dc}"
        );
    }
}

#[test]
fn the_chosen_wss_target_matches_the_python_original() {
    for (ip, dc, media, expected) in PREFERRED_CASES {
        assert_eq!(preferred_ws_target(ip, Dc::new(*dc), *media), *expected, "ip {ip} dc {dc} media={media}");
    }
}

#[test]
fn the_corpus_covers_more_than_one_answer_on_every_axis() {
    // A parity table where every row agrees proves nothing.
    use std::collections::BTreeSet;
    assert!(DOMAIN_CASES.iter().map(|c| c.1).collect::<BTreeSet<_>>().len() >= 5);
    assert!(HINT_CASES.iter().map(|c| c.2).collect::<BTreeSet<_>>().len() >= 5);
    assert!(HINT_CASES.iter().any(|c| c.2 == 0), "and some addresses belong to nothing");
    assert!(MEDIA_CASES.iter().any(|c| c.3));
    assert!(MEDIA_CASES.iter().any(|c| !c.3));
    assert!(PREFERRED_CASES.iter().any(|c| c.0 != c.3), "some are redirected");
    assert!(PREFERRED_CASES.iter().any(|c| c.0 == c.3), "and some are left alone");
}
