//! Layer 28: which family of WSS routes is tried, in what order, and when to
//! stop trying one.
//!
//! The decisions of `_connect_ws_route` (`transparent_relay.py:3537`), without
//! the dialling. Two families can carry a WSS tunnel — Nova's own Cloudflare
//! Workers, and Telegram's own `web.telegram.org` endpoints reached through a
//! per-DC redirect address — and this decides which goes first, whether the
//! other is a fallback, and whether either is available at all.
//!
//! **The default is Cloudflare first, for every DC, and that is a live rule
//! rather than a leftover.** `cf_first` consults the per-DC lists *only* when an
//! operator has actually set one of the two environment variables. Without that
//! guard the built-in `CF_FIRST_MEDIA_DCS` — which omits 1 and 3 — would quietly
//! send media on those two data centres to Telegram Web first, which is a
//! routing change nobody asked for. The Python spells this out in a comment
//! beside the code; it is worth restating because the guard looks redundant
//! until you notice the defaults differ from "everything".
//!
//! **One dead expression is left out on purpose.** The Python also computes
//! `custom_cf_first = allow_cf and CF_FALLBACK_ENABLED and
//! _has_custom_cfproxy_domain() and cf_first` and then branches on
//! `custom_cf_first or cf_first`. The first operand implies the second, so the
//! disjunction is exactly `cf_first` and the whole expression — including the
//! `_has_custom_cfproxy_domain()` call it exists to consult — can never change a
//! decision. See G52.

use crate::egress::Dc;
use std::collections::BTreeSet;

/// `_TG_WS_REDIRECT_IPS`: the address a data centre's Telegram Web tunnel is
/// pointed at.
///
/// Not every DC has one, and that is the whole availability question for the
/// web family: without an entry there is nothing to connect to and the family is
/// skipped rather than attempted and failed.
const WS_REDIRECT_IPS: &[(u16, &str)] = &[
    (1, "149.154.174.100"),
    (2, "149.154.167.220"),
    (3, "149.154.174.100"),
    (4, "149.154.167.220"),
    (5, "149.154.170.100"),
    (203, "149.154.167.220"),
];

pub fn redirect_target(dc: Dc) -> Option<&'static str> {
    WS_REDIRECT_IPS.iter().find(|(n, _)| *n == dc.get()).map(|(_, ip)| *ip)
}

/// Where the operator's `NOVA_TG_RELAY_CF_FIRST_*` variables ended up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfFirst {
    /// Either variable was set to something non-empty.
    ///
    /// The load-bearing field. When this is false the per-DC lists are not
    /// consulted at all and every DC gets Cloudflare first.
    pub configured: bool,
    /// The plain variable was `*` or `ALL`.
    pub every_dc: bool,
    pub plain: BTreeSet<u16>,
    pub media: BTreeSet<u16>,
}

impl Default for CfFirst {
    /// The shipped defaults, and `configured: false` — which is what makes the
    /// two sets below unreachable until somebody sets a variable.
    fn default() -> Self {
        Self {
            configured: false,
            every_dc: false,
            plain: [1, 2, 3, 4, 5, 203].into_iter().collect(),
            media: [2, 4, 5, 203].into_iter().collect(),
        }
    }
}

/// Whether Cloudflare is tried before Telegram Web for this tunnel.
pub fn cf_first(dc: Dc, media: bool, config: &CfFirst) -> bool {
    if !config.configured {
        return true;
    }
    if config.every_dc {
        return true;
    }
    let set = if media { &config.media } else { &config.plain };
    set.contains(&dc.get())
}

/// A family of WSS routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Nova's own Workers.
    Cloudflare,
    /// `web.telegram.org` and its siblings, through the DC's redirect address.
    TelegramWeb,
}

/// What the tunnel is allowed to reach for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowed {
    /// The caller's `allow_cf`. False on the paths that must not recurse back
    /// into Cloudflare.
    pub cloudflare: bool,
    /// `CF_FALLBACK_ENABLED`, the global switch.
    pub cf_fallback_enabled: bool,
}

/// The families to try, in order.
///
/// **Cloudflare appears at most once.** The Python guards the second attempt
/// with `tried_cf_route` for exactly this reason: the first pass already walked
/// every Worker domain the health table would offer, so repeating it spends
/// Worker invocations to re-learn what was just learned.
pub fn order(dc: Dc, media: bool, allowed: Allowed, config: &CfFirst) -> Vec<Family> {
    let cf = allowed.cloudflare && allowed.cf_fallback_enabled;
    let web = redirect_target(dc).is_some();
    let mut out = Vec::with_capacity(2);
    if cf && cf_first(dc, media, config) {
        out.push(Family::Cloudflare);
        if web {
            out.push(Family::TelegramWeb);
        }
        return out;
    }
    if web {
        out.push(Family::TelegramWeb);
    }
    if cf {
        out.push(Family::Cloudflare);
    }
    out
}

/// What to do after one Telegram Web domain failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterWebFailure {
    /// A redirect is the endpoint saying "not me, try the next name". The list
    /// exists to be walked on exactly this.
    TryNextDomain,
    /// Anything else abandons the **whole** family, not just this domain.
    ///
    /// Surprising and deliberate: these endpoints are the same Telegram front
    /// end under different names, reached through one redirect address, so a
    /// timeout or a refusal at one is evidence about the path rather than about
    /// the name. Walking the rest would spend the tunnel's budget re-proving it.
    GiveUpOnFamily,
}

/// The rule above, from the two things the Python tests: whether it was an HTTP
/// handshake failure at all, and whether that status was a redirect.
pub fn after_web_failure(http_status: Option<u16>) -> AfterWebFailure {
    match http_status {
        Some(status) if is_redirect(status) => AfterWebFailure::TryNextDomain,
        _ => AfterWebFailure::GiveUpOnFamily,
    }
}

/// `WsHandshakeError.is_redirect`.
pub fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Per-attempt budget for a Telegram Web domain, and the looser ceiling the
/// Python wraps around it.
///
/// Two deadlines on purpose: the inner one is what the connect is told, the
/// outer one is what the caller will actually wait. The gap is the slack for
/// everything the inner budget does not cover.
pub fn web_attempt_budget(media: bool) -> (std::time::Duration, std::time::Duration) {
    if media {
        (std::time::Duration::from_millis(2500), std::time::Duration::from_secs(3))
    } else {
        (std::time::Duration::from_secs(6), std::time::Duration::from_secs(7))
    }
}

/// The `route=` field for a Telegram Web tunnel: `domain@target via egress`.
///
/// The `@` is what separates it from a Cloudflare label in a log line, and
/// [`crate::cfdomains::domain_of`] relies on both forms recovering the domain.
pub fn web_route_label(domain: &str, target: &str, egress: &str) -> String {
    format!("{domain}@{target} via {egress}")
}

/// The `route=` field for a Cloudflare tunnel: `domain via egress`.
pub fn cf_route_label(domain: &str, egress: &str) -> String {
    format!("{domain} via {egress}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfdomains::domain_of;

    fn dc(n: u16) -> Dc {
        Dc::new(n).expect("a real data centre")
    }

    fn allow_both() -> Allowed {
        Allowed { cloudflare: true, cf_fallback_enabled: true }
    }

    #[test]
    fn the_redirect_table_came_over_whole() {
        assert_eq!(WS_REDIRECT_IPS.len(), 6);
        assert_eq!(redirect_target(dc(2)), Some("149.154.167.220"));
        assert_eq!(redirect_target(dc(5)), Some("149.154.170.100"));
        assert_eq!(redirect_target(dc(1)), redirect_target(dc(3)), "1 and 3 share an address");
    }

    #[test]
    fn a_data_centre_with_no_redirect_address_has_no_web_family() {
        // Not "tried and failed" — never offered. There is nothing to point a
        // tunnel at, and an attempt would spend a budget proving it.
        let unknown = dc(100);
        assert_eq!(redirect_target(unknown), None);
        assert_eq!(order(unknown, false, allow_both(), &CfFirst::default()), [Family::Cloudflare]);
    }

    #[test]
    fn cloudflare_goes_first_for_every_data_centre_by_default() {
        let config = CfFirst::default();
        for n in [1u16, 2, 3, 4, 5, 203] {
            for media in [true, false] {
                assert!(cf_first(dc(n), media, &config), "dc={n} media={media}");
            }
        }
    }

    #[test]
    fn the_per_dc_lists_are_dead_until_an_operator_sets_one() {
        // The guard that matters. `CF_FIRST_MEDIA_DCS` omits 1 and 3, so
        // consulting it unconditionally would move media on those two to
        // Telegram Web first — a routing change nobody asked for.
        let unset = CfFirst::default();
        assert!(cf_first(dc(1), true, &unset), "not in the media list, and it does not matter");
        assert!(cf_first(dc(3), true, &unset));

        let set = CfFirst { configured: true, ..CfFirst::default() };
        assert!(!cf_first(dc(1), true, &set), "now the list bites");
        assert!(!cf_first(dc(3), true, &set));
        assert!(cf_first(dc(2), true, &set));
        assert!(cf_first(dc(1), false, &set), "the plain list does contain 1");
    }

    #[test]
    fn a_star_means_every_data_centre_including_ones_not_in_either_list() {
        let config = CfFirst { configured: true, every_dc: true, ..CfFirst::default() };
        assert!(cf_first(dc(100), true, &config));
        assert!(cf_first(dc(1), true, &config));
    }

    #[test]
    fn web_first_puts_cloudflare_behind_it_rather_than_dropping_it() {
        let config = CfFirst { configured: true, ..CfFirst::default() };
        // DC1 media is not in the media list, so web goes first.
        assert_eq!(order(dc(1), true, allow_both(), &config), [Family::TelegramWeb, Family::Cloudflare]);
    }

    #[test]
    fn cloudflare_is_never_offered_twice() {
        // The `tried_cf_route` guard. A second pass would walk the same Worker
        // domains the health table just ordered and spend invocations
        // re-learning what the first pass learned.
        for media in [true, false] {
            for configured in [true, false] {
                let config = CfFirst { configured, ..CfFirst::default() };
                let families = order(dc(2), media, allow_both(), &config);
                assert_eq!(
                    families.iter().filter(|f| **f == Family::Cloudflare).count(),
                    1,
                    "media={media} configured={configured}"
                );
            }
        }
    }

    #[test]
    fn a_caller_that_forbids_cloudflare_gets_the_web_family_alone() {
        let forbidden = Allowed { cloudflare: false, cf_fallback_enabled: true };
        assert_eq!(order(dc(2), false, forbidden, &CfFirst::default()), [Family::TelegramWeb]);
    }

    #[test]
    fn the_global_switch_removes_cloudflare_wherever_it_would_have_gone() {
        let off = Allowed { cloudflare: true, cf_fallback_enabled: false };
        let config = CfFirst { configured: true, ..CfFirst::default() };
        assert_eq!(order(dc(2), false, off, &config), [Family::TelegramWeb], "cf-first case");
        assert_eq!(order(dc(1), true, off, &config), [Family::TelegramWeb], "web-first case");
    }

    #[test]
    fn nothing_is_available_when_cloudflare_is_off_and_the_dc_has_no_redirect() {
        let off = Allowed { cloudflare: false, cf_fallback_enabled: false };
        assert!(order(dc(100), false, off, &CfFirst::default()).is_empty());
    }

    #[test]
    fn a_redirect_moves_to_the_next_name_and_anything_else_abandons_the_family() {
        for status in [301u16, 302, 303, 307, 308] {
            assert_eq!(after_web_failure(Some(status)), AfterWebFailure::TryNextDomain, "{status}");
        }
        for status in [200u16, 403, 421, 500, 502] {
            assert_eq!(after_web_failure(Some(status)), AfterWebFailure::GiveUpOnFamily, "{status}");
        }
        // No status at all: a timeout, a reset, a silent peer. The Python's
        // bare `except Exception: break`.
        assert_eq!(after_web_failure(None), AfterWebFailure::GiveUpOnFamily);
    }

    #[test]
    fn the_outer_ceiling_is_always_looser_than_the_budget_it_wraps() {
        for media in [true, false] {
            let (inner, outer) = web_attempt_budget(media);
            assert!(outer > inner, "media={media}: {outer:?} must leave slack over {inner:?}");
        }
        assert_eq!(web_attempt_budget(true).0, std::time::Duration::from_millis(2500));
        assert_eq!(web_attempt_budget(false).1, std::time::Duration::from_secs(7));
    }

    #[test]
    fn both_label_shapes_give_their_domain_back() {
        // The health table keys on the domain it parses out of a route label,
        // so a label this side builds and that side cannot read is a silent
        // bench entry under the wrong name.
        let web = web_route_label("kws2-1.web.telegram.org", "149.154.167.220", "warp-socks");
        assert_eq!(web, "kws2-1.web.telegram.org@149.154.167.220 via warp-socks");
        assert_eq!(domain_of(&web), "kws2-1.web.telegram.org");

        let cf = cf_route_label("kws2.nova-app.eu", "opera-http");
        assert_eq!(cf, "kws2.nova-app.eu via opera-http");
        assert_eq!(domain_of(&cf), "kws2.nova-app.eu");
    }
}
