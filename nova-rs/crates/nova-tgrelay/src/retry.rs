//! Layer 29: what happens when a WSS tunnel closes without carrying anything.
//!
//! The decisions of `_try_cf_bootstrap_non_media`'s tail (`:3006`) and
//! `_retry_web_ws_after_empty` (`:3590`) — the path the live logs spend most of
//! their lines on: `WSS custom empty; retrying Telegram Web WSS`,
//! `WSS empty response; skipping TCP fallback`, `WSS media progress stalled`.
//!
//! **A media tunnel can fail while carrying bytes.** Four kilobytes is the line
//! ([`crate::wsbridge::MEDIA_MIN_PROGRESS`]); under it, after nearly two
//! seconds, the tunnel is open and useless — Telegram is waiting on a photo that
//! is arriving at a few hundred bytes a second. The relay calls that a stall and
//! **reports it to the first-byte circuit as zero bytes down**, because "it
//! technically delivered something" is exactly the reading that would keep a
//! dead route in rotation.
//!
//! The two places the Python computes this were checked against each other
//! rather than assumed equal: `:2790` and `:3671` agree on all three terms.
//!
//! **One branch here is unreachable in every shipped build, and that is the
//! point of stating it.** `_has_custom_cfproxy_domain()` looks like a
//! configuration question and is a constant: `get_cfproxy_domains` appends
//! `NOVA_CFPROXY_PRIMARY_DOMAINS` — `['nova-app.eu']` — unconditionally, and the
//! predicate tests for exactly that name. Executed with every `NOVA_TG*`
//! variable removed, it still answers `True`. So [`AfterEmpty::TcpFallback`] and
//! its log line `WSS empty response; TCP fallback` **cannot occur**, which a
//! reporter's hour-long log confirms: 41 of the other line, zero of that one.
//! Kept as a value rather than folded away, because the day a build ships
//! without that zone the branch is the correct behaviour again. See G54.

use crate::egress::Dc;
use crate::wsbridge::MEDIA_MIN_PROGRESS;
use std::time::Duration;

/// How long a media tunnel may dribble before "it is delivering" becomes "it is
/// stalled".
///
/// Just under two seconds because that is roughly one Telegram media chunk's
/// worth of patience: shorter and a slow-but-working route is cut, longer and
/// the user watches a progress bar that is not moving.
pub const MEDIA_STALL_AFTER: Duration = Duration::from_millis(1800);

/// How a WSS tunnel ended, in the terms the health tables need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// It carried. For media that means it cleared [`MEDIA_MIN_PROGRESS`].
    Carried,
    /// Open, delivering, and useless.
    MediaStalled,
    /// Not a byte came back.
    Empty,
}

/// Judge a closed tunnel.
pub fn verdict(media: bool, down: u64, duration: Duration) -> Verdict {
    if down == 0 {
        return Verdict::Empty;
    }
    if media && down < MEDIA_MIN_PROGRESS && duration >= MEDIA_STALL_AFTER {
        return Verdict::MediaStalled;
    }
    Verdict::Carried
}

/// What the first-byte circuit is told.
///
/// A stall is reported as **zero**, not as the bytes that actually arrived. The
/// circuit exists to notice routes that answer without working, and a route that
/// answers with 200 bytes for two seconds is the exact case it is for — counting
/// those 200 bytes as success is how such a route stays in rotation forever.
pub fn recorded_down(verdict: Verdict, down: u64) -> u64 {
    match verdict {
        Verdict::MediaStalled | Verdict::Empty => 0,
        Verdict::Carried => down,
    }
}

/// What to do once the retry has also come back empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterEmpty {
    /// A `:80` bootstrap socket on a data centre that had a working WSS route
    /// moments ago. Telegram will reconnect on its own; opening a raw tunnel
    /// here would spend the ISP's patience to deliver a control message that is
    /// about to be re-sent anyway.
    CloseQuietly,
    /// Close and let Telegram come back over WSS. The provider throttles raw
    /// Telegram TCP even through WARP, so the fallback is a slower way to fail.
    SkipTcpFallback,
    /// Carry it over raw TCP after all.
    ///
    /// **Unreachable in every shipped build** — see the module note and G54.
    TcpFallback,
}

/// The tail of the empty-response path.
///
/// `recent_good` is [`crate::wss::RecentGood::within`] over the last three
/// minutes for this data centre.
pub fn after_empty(target_port: u16, recent_good: bool, owned_zone_available: bool) -> AfterEmpty {
    if target_port == 80 && recent_good {
        return AfterEmpty::CloseQuietly;
    }
    if owned_zone_available {
        return AfterEmpty::SkipTcpFallback;
    }
    AfterEmpty::TcpFallback
}

/// True for every build that ships `nova-app.eu` in its primary domains, which
/// is every build there has been.
///
/// Named so the call sites read as what they are — a constant — instead of as a
/// question. Executed against the shipped `config.py` with the environment
/// cleared: still true.
pub const SHIPPED_OWNED_ZONE: bool = true;

/// Where a retry after an empty close may look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrySource {
    /// The Worker zones again, minus the name that just failed.
    ///
    /// The exclusion is per-attempt and does **not** touch the health table:
    /// benching it is the caller's separate decision, made with a TTL that
    /// depends on whether that domain was the last known good one.
    CloudflareExcluding(String),
    /// Telegram's own endpoints, with Cloudflare explicitly forbidden.
    ///
    /// `allow_cf=False` matters: without it the route walk would re-enter the
    /// Worker pool that has just been asked and answered.
    TelegramWebOnly,
}

/// The retry plan after an empty close.
///
/// `failed_domain` comes from [`crate::cfdomains::domain_of`], so both label
/// shapes — `domain via egress` and `domain@target via egress` — reduce to the
/// same name.
pub fn retry_sources(cf_enabled: bool, owned_zone_available: bool, failed_domain: &str) -> Vec<RetrySource> {
    let mut out = Vec::with_capacity(2);
    if cf_enabled && owned_zone_available {
        out.push(RetrySource::CloudflareExcluding(failed_domain.trim().to_ascii_lowercase()));
    }
    out.push(RetrySource::TelegramWebOnly);
    out
}

/// What the retry has to put on the wire before anything else.
///
/// The obfuscated init packet goes out **raw and first**; only the buffered
/// upload behind it goes through the splitter. Getting that order wrong costs
/// the whole session: the far side keys its stream on the init packet, so a
/// tunnel that replays the upload ahead of it is decrypting noise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    pub init: Vec<u8>,
    /// Everything the client sent while the dead route was still believed in.
    pub pending: Vec<u8>,
}

impl Replay {
    pub fn new(init: &[u8], pending: &[u8]) -> Self {
        Self { init: init.to_vec(), pending: pending.to_vec() }
    }

    /// What a caller that gives up on WSS hands to the raw tunnel: one buffer,
    /// init first.
    pub fn flattened(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.init.len() + self.pending.len());
        out.extend_from_slice(&self.init);
        out.extend_from_slice(&self.pending);
        out
    }

    pub fn is_empty(&self) -> bool {
        self.init.is_empty() && self.pending.is_empty()
    }
}

/// The log line's `dc=` field, which is `?` rather than `0` when unknown.
pub fn dc_field(dc: Option<Dc>) -> String {
    dc.map_or_else(|| "?".to_string(), |d| d.get().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tunnel_that_delivered_nothing_is_empty() {
        assert_eq!(verdict(false, 0, Duration::from_secs(5)), Verdict::Empty);
        assert_eq!(verdict(true, 0, Duration::from_secs(5)), Verdict::Empty);
    }

    #[test]
    fn a_media_tunnel_can_fail_while_carrying_bytes() {
        // The case the plain path has no equivalent of: open, delivering, and
        // useless. Telegram is waiting on a photo at a few hundred bytes/s.
        assert_eq!(verdict(true, 226, Duration::from_millis(4018)), Verdict::MediaStalled);
    }

    #[test]
    fn the_same_trickle_on_a_plain_tunnel_is_not_a_stall() {
        // A control message *is* a few hundred bytes. Only media has a floor.
        assert_eq!(verdict(false, 226, Duration::from_millis(4018)), Verdict::Carried);
    }

    #[test]
    fn both_halves_of_the_stall_test_have_to_hold() {
        // Enough bytes, however slow: it worked.
        assert_eq!(verdict(true, MEDIA_MIN_PROGRESS, Duration::from_secs(30)), Verdict::Carried);
        // Too few bytes but too early to judge: still carrying.
        assert_eq!(verdict(true, 100, MEDIA_STALL_AFTER - Duration::from_millis(1)), Verdict::Carried);
        // Exactly at the threshold counts as stalled — the Python's `>=`.
        assert_eq!(verdict(true, 100, MEDIA_STALL_AFTER), Verdict::MediaStalled);
        // Exactly at the floor counts as carried — the Python's `<`.
        assert_eq!(verdict(true, MEDIA_MIN_PROGRESS, MEDIA_STALL_AFTER), Verdict::Carried);
    }

    #[test]
    fn a_stall_is_reported_to_the_circuit_as_zero_and_not_as_what_arrived() {
        // Otherwise a route that answers with 200 bytes for two seconds looks
        // like a success to the table that is supposed to retire it.
        assert_eq!(recorded_down(Verdict::MediaStalled, 226), 0);
        assert_eq!(recorded_down(Verdict::Empty, 0), 0);
        assert_eq!(recorded_down(Verdict::Carried, 5399), 5399);
    }

    #[test]
    fn a_bootstrap_socket_on_a_healthy_dc_is_closed_rather_than_tunnelled() {
        assert_eq!(after_empty(80, true, SHIPPED_OWNED_ZONE), AfterEmpty::CloseQuietly);
        // Both halves required: the port names it a bootstrap socket, the recent
        // good says Telegram has somewhere to come back to.
        assert_eq!(after_empty(80, false, SHIPPED_OWNED_ZONE), AfterEmpty::SkipTcpFallback);
        assert_eq!(after_empty(443, true, SHIPPED_OWNED_ZONE), AfterEmpty::SkipTcpFallback);
    }

    #[test]
    fn the_raw_tcp_fallback_cannot_be_reached_by_anything_that_ships() {
        // `_has_custom_cfproxy_domain()` reads as a configuration question and
        // is a constant — `nova-app.eu` is appended to the domain list
        // unconditionally. A reporter's hour of logs has 41 lines of the branch
        // above and zero of this one.
        for port in [80u16, 443, 2053] {
            for recent_good in [true, false] {
                assert_ne!(
                    after_empty(port, recent_good, SHIPPED_OWNED_ZONE),
                    AfterEmpty::TcpFallback,
                    "port={port} recent_good={recent_good}"
                );
            }
        }
        // And it is still the right answer for a build without the zone.
        assert_eq!(after_empty(443, false, false), AfterEmpty::TcpFallback);
    }

    #[test]
    fn the_retry_asks_cloudflare_first_and_never_re_enters_it_afterwards() {
        assert_eq!(
            retry_sources(true, true, "KWS2.Offshor.co.uk"),
            vec![RetrySource::CloudflareExcluding("kws2.offshor.co.uk".to_string()), RetrySource::TelegramWebOnly,],
            "and the exclusion is normalised, because the health table is keyed lower-case"
        );
    }

    #[test]
    fn without_a_worker_zone_the_retry_is_telegram_web_alone() {
        assert_eq!(retry_sources(false, true, "x.y"), vec![RetrySource::TelegramWebOnly]);
        assert_eq!(retry_sources(true, false, "x.y"), vec![RetrySource::TelegramWebOnly]);
    }

    #[test]
    fn the_init_packet_is_replayed_ahead_of_the_upload_it_keys() {
        // Order is the whole content of this type. The far side derives its
        // stream from the init packet; anything replayed in front of it is
        // decrypted as noise and the session is lost.
        let replay = Replay::new(b"INIT", b"upload");
        assert_eq!(replay.flattened(), b"INITupload");
        assert!(!replay.is_empty());
        assert!(Replay::new(b"", b"").is_empty());
    }

    #[test]
    fn an_unknown_data_centre_is_a_question_mark_and_not_a_zero() {
        // `dc=0` reads as a real data centre in a log line, and there is no
        // DC 0. The Python spells this `dc={dc_hint or '?'}`.
        assert_eq!(dc_field(None), "?");
        assert_eq!(dc_field(Dc::new(2)), "2");
    }
}
