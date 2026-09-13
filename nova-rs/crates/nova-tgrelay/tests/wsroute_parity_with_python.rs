//! Route-family order, against the order the shipped Python produces.
//!
//! Layer 28. Every row was produced by **executing** `_cf_first` (compiled out of
//! `tgrelay/transparent_relay.py` by AST) together with the branch conditions of
//! `_connect_ws_route`, lifted as the `test` of their `If` nodes and evaluated.
//! Generator: `temp/wsroute_oracle.py`.
//!
//! The same run answered a question reading could only suggest: over all sixteen
//! combinations of its inputs, `custom_cf_first` changes the first-pass decision
//! **zero** times. It is dead, and the `_has_custom_cfproxy_domain()` call it
//! exists to make is dead with it.

use nova_tgrelay::egress::Dc;
use nova_tgrelay::wsroute::{order, Allowed, CfFirst, Family};

/// `(dc, media, allow_cf, cf_fallback_enabled, cf_order_configured, families)`
#[allow(clippy::type_complexity)]
const TABLE: &[(u16, bool, bool, bool, bool, &[Family])] = &[
    (1, true, true, true, true, &[Family::TelegramWeb, Family::Cloudflare]),
    (1, true, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (1, true, true, false, true, &[Family::TelegramWeb]),
    (1, true, true, false, false, &[Family::TelegramWeb]),
    (1, true, false, true, true, &[Family::TelegramWeb]),
    (1, true, false, true, false, &[Family::TelegramWeb]),
    (1, true, false, false, true, &[Family::TelegramWeb]),
    (1, true, false, false, false, &[Family::TelegramWeb]),
    (1, false, true, true, true, &[Family::Cloudflare, Family::TelegramWeb]),
    (1, false, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (1, false, true, false, true, &[Family::TelegramWeb]),
    (1, false, true, false, false, &[Family::TelegramWeb]),
    (1, false, false, true, true, &[Family::TelegramWeb]),
    (1, false, false, true, false, &[Family::TelegramWeb]),
    (1, false, false, false, true, &[Family::TelegramWeb]),
    (1, false, false, false, false, &[Family::TelegramWeb]),
    (2, true, true, true, true, &[Family::Cloudflare, Family::TelegramWeb]),
    (2, true, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (2, true, true, false, true, &[Family::TelegramWeb]),
    (2, true, true, false, false, &[Family::TelegramWeb]),
    (2, true, false, true, true, &[Family::TelegramWeb]),
    (2, true, false, true, false, &[Family::TelegramWeb]),
    (2, true, false, false, true, &[Family::TelegramWeb]),
    (2, true, false, false, false, &[Family::TelegramWeb]),
    (2, false, true, true, true, &[Family::Cloudflare, Family::TelegramWeb]),
    (2, false, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (2, false, true, false, true, &[Family::TelegramWeb]),
    (2, false, true, false, false, &[Family::TelegramWeb]),
    (2, false, false, true, true, &[Family::TelegramWeb]),
    (2, false, false, true, false, &[Family::TelegramWeb]),
    (2, false, false, false, true, &[Family::TelegramWeb]),
    (2, false, false, false, false, &[Family::TelegramWeb]),
    (3, true, true, true, true, &[Family::TelegramWeb, Family::Cloudflare]),
    (3, true, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (3, true, true, false, true, &[Family::TelegramWeb]),
    (3, true, true, false, false, &[Family::TelegramWeb]),
    (3, true, false, true, true, &[Family::TelegramWeb]),
    (3, true, false, true, false, &[Family::TelegramWeb]),
    (3, true, false, false, true, &[Family::TelegramWeb]),
    (3, true, false, false, false, &[Family::TelegramWeb]),
    (3, false, true, true, true, &[Family::Cloudflare, Family::TelegramWeb]),
    (3, false, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (3, false, true, false, true, &[Family::TelegramWeb]),
    (3, false, true, false, false, &[Family::TelegramWeb]),
    (3, false, false, true, true, &[Family::TelegramWeb]),
    (3, false, false, true, false, &[Family::TelegramWeb]),
    (3, false, false, false, true, &[Family::TelegramWeb]),
    (3, false, false, false, false, &[Family::TelegramWeb]),
    (4, true, true, true, true, &[Family::Cloudflare, Family::TelegramWeb]),
    (4, true, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (4, true, true, false, true, &[Family::TelegramWeb]),
    (4, true, true, false, false, &[Family::TelegramWeb]),
    (4, true, false, true, true, &[Family::TelegramWeb]),
    (4, true, false, true, false, &[Family::TelegramWeb]),
    (4, true, false, false, true, &[Family::TelegramWeb]),
    (4, true, false, false, false, &[Family::TelegramWeb]),
    (4, false, true, true, true, &[Family::Cloudflare, Family::TelegramWeb]),
    (4, false, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (4, false, true, false, true, &[Family::TelegramWeb]),
    (4, false, true, false, false, &[Family::TelegramWeb]),
    (4, false, false, true, true, &[Family::TelegramWeb]),
    (4, false, false, true, false, &[Family::TelegramWeb]),
    (4, false, false, false, true, &[Family::TelegramWeb]),
    (4, false, false, false, false, &[Family::TelegramWeb]),
    (5, true, true, true, true, &[Family::Cloudflare, Family::TelegramWeb]),
    (5, true, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (5, true, true, false, true, &[Family::TelegramWeb]),
    (5, true, true, false, false, &[Family::TelegramWeb]),
    (5, true, false, true, true, &[Family::TelegramWeb]),
    (5, true, false, true, false, &[Family::TelegramWeb]),
    (5, true, false, false, true, &[Family::TelegramWeb]),
    (5, true, false, false, false, &[Family::TelegramWeb]),
    (5, false, true, true, true, &[Family::Cloudflare, Family::TelegramWeb]),
    (5, false, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (5, false, true, false, true, &[Family::TelegramWeb]),
    (5, false, true, false, false, &[Family::TelegramWeb]),
    (5, false, false, true, true, &[Family::TelegramWeb]),
    (5, false, false, true, false, &[Family::TelegramWeb]),
    (5, false, false, false, true, &[Family::TelegramWeb]),
    (5, false, false, false, false, &[Family::TelegramWeb]),
    (203, true, true, true, true, &[Family::Cloudflare, Family::TelegramWeb]),
    (203, true, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (203, true, true, false, true, &[Family::TelegramWeb]),
    (203, true, true, false, false, &[Family::TelegramWeb]),
    (203, true, false, true, true, &[Family::TelegramWeb]),
    (203, true, false, true, false, &[Family::TelegramWeb]),
    (203, true, false, false, true, &[Family::TelegramWeb]),
    (203, true, false, false, false, &[Family::TelegramWeb]),
    (203, false, true, true, true, &[Family::Cloudflare, Family::TelegramWeb]),
    (203, false, true, true, false, &[Family::Cloudflare, Family::TelegramWeb]),
    (203, false, true, false, true, &[Family::TelegramWeb]),
    (203, false, true, false, false, &[Family::TelegramWeb]),
    (203, false, false, true, true, &[Family::TelegramWeb]),
    (203, false, false, true, false, &[Family::TelegramWeb]),
    (203, false, false, false, true, &[Family::TelegramWeb]),
    (203, false, false, false, false, &[Family::TelegramWeb]),
    (100, true, true, true, true, &[Family::Cloudflare]),
    (100, true, true, true, false, &[Family::Cloudflare]),
    (100, true, true, false, true, &[]),
    (100, true, true, false, false, &[]),
    (100, true, false, true, true, &[]),
    (100, true, false, true, false, &[]),
    (100, true, false, false, true, &[]),
    (100, true, false, false, false, &[]),
    (100, false, true, true, true, &[Family::Cloudflare]),
    (100, false, true, true, false, &[Family::Cloudflare]),
    (100, false, true, false, true, &[]),
    (100, false, true, false, false, &[]),
    (100, false, false, true, true, &[]),
    (100, false, false, true, false, &[]),
    (100, false, false, false, true, &[]),
    (100, false, false, false, false, &[]),
];

#[test]
fn the_family_order_matches_the_python_for_every_combination() {
    let mut wrong = Vec::new();
    for (dc, media, allow_cf, enabled, configured, expected) in TABLE {
        let config = CfFirst { configured: *configured, ..CfFirst::default() };
        let allowed = Allowed { cloudflare: *allow_cf, cf_fallback_enabled: *enabled };
        let got = order(Dc::new(*dc).expect("a data centre"), *media, allowed, &config);
        if got != *expected {
            wrong.push(format!(
                "dc={dc} media={media} allow_cf={allow_cf} enabled={enabled} configured={configured}:                  python {expected:?}, port {got:?}"
            ));
        }
    }
    assert!(wrong.is_empty(), "{} rows disagree:
{}", wrong.len(), wrong.join("
"));
}

#[test]
fn the_table_covers_a_dc_with_no_redirect_address_and_one_with_it() {
    assert!(TABLE.iter().any(|r| r.0 == 100), "the no-redirect case is in the table");
    assert!(TABLE.iter().any(|r| r.0 == 2));
    assert!(TABLE.iter().any(|r| r.5.is_empty()), "and the case where nothing is available");
}

#[test]
fn no_row_offers_cloudflare_twice() {
    // The `tried_cf_route` guard, checked against the generated table rather
    // than against the port's own reading of it.
    for (dc, media, _, _, _, families) in TABLE {
        let n = families.iter().filter(|f| **f == Family::Cloudflare).count();
        assert!(n <= 1, "dc={dc} media={media} offers Cloudflare {n} times");
    }
}
