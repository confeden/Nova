//! Matching a connection on 1372 back to the flow WinDivert redirected.
//!
//! Layer 22, the pure half of `_lookup_divert_context`. When a client is caught
//! by the redirect rather than sent by the PAC, the socket that arrives says
//! nothing about where it was going — the divert rewrites below the socket
//! layer, so the peer address is the client's own. The real target is in a state
//! file the redirect writes, keyed by the client's local address, and this is
//! the part that decides which entry is the right one.
//!
//! **Three ways to match, in order, and the third is a heuristic.** Exact
//! address, then same local port on the same service, then — for a non-loopback
//! peer only — a *nearby* port. That last one exists because the client's source
//! port can move between the moment the redirect recorded it and the moment the
//! connection reaches us; it is bounded by ±16 ports and 8 seconds precisely so
//! that it stays a repair for that race and does not become a way to attach a
//! session to somebody else's flow.

use std::time::Duration;

/// How far a source port may have moved and still be the same flow.
pub const NEARBY_PORT_WINDOW: u16 = 16;
/// How stale a nearby entry may be. Beyond this it is a different connection
/// that happens to have landed close by.
pub const NEARBY_MAX_AGE: Duration = Duration::from_secs(8);

/// One row of the redirect's state file.
#[derive(Debug, Clone, PartialEq)]
pub struct DivertEntry {
    pub local_host: String,
    pub local_port: u16,
    /// The relay port this flow was redirected to.
    pub service_port: u16,
    pub target_host: String,
    pub target_port: u16,
    /// Wall-clock seconds.
    pub updated: f64,
    pub expires: f64,
    /// The redirect has seen this flow start to close.
    pub closing: bool,
}

impl DivertEntry {
    /// A row with no usable target is not a match, however well it scores.
    pub fn is_usable(&self) -> bool {
        !self.target_host.trim().is_empty() && self.target_port > 0
    }

    pub fn key(&self) -> String {
        format!("{}:{}", self.local_host, self.local_port)
    }
}

/// Who is asking.
#[derive(Debug, Clone, Copy)]
pub struct Peer<'a> {
    pub host: &'a str,
    pub port: u16,
    /// The relay's own listening port, which the entry must name.
    pub service_port: u16,
}

/// `127.0.0.0/8`, `::1`, or the literal name.
pub fn is_loopback(host: &str) -> bool {
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// How many times to re-read the state file before giving up.
///
/// A loopback peer is the PAC path, where the redirect has either recorded the
/// flow already or never will; anything else was diverted, and the record can
/// still be on its way. Forty attempts at 50 ms is two seconds of patience for
/// the case that needs it and 150 ms for the case that does not.
pub fn read_attempts(loopback_peer: bool) -> u32 {
    if loopback_peer {
        3
    } else {
        40
    }
}

/// The pause between attempts.
pub const RETRY_PAUSE: Duration = Duration::from_millis(50);

/// Pick the entry this peer belongs to, or `None`.
///
/// `now` is wall-clock seconds, matching what the redirect writes.
pub fn match_entry<'a>(entries: &'a [DivertEntry], peer: Peer<'_>, now: f64) -> Option<&'a DivertEntry> {
    let loopback = is_loopback(peer.host);

    // 1. The address the redirect recorded, exactly.
    let mut candidates: Vec<&DivertEntry> =
        entries.iter().filter(|e| e.local_host == peer.host && e.local_port == peer.port).collect();

    // 2. The same local port on the same service, whatever host it was recorded
    //    under — the redirect and the socket can disagree about which of a
    //    machine's addresses is "the" local one.
    if candidates.is_empty() {
        candidates =
            entries.iter().filter(|e| e.local_port == peer.port && e.service_port == peer.service_port).collect();
    }

    // 3. The nearby heuristic. **Loopback peers are excluded**: they arrived
    //    through the PAC with an address the redirect never wrote, so a nearby
    //    match there would attach the session to a flow that has nothing to do
    //    with it.
    if candidates.is_empty() && !loopback {
        let mut nearby: Vec<&DivertEntry> = entries
            .iter()
            .filter(|e| {
                e.local_host == peer.host
                    && e.expires >= now
                    && e.local_port.abs_diff(peer.port) <= NEARBY_PORT_WINDOW
                    && (now - e.updated) <= NEARBY_MAX_AGE.as_secs_f64()
            })
            .collect();
        // Closest port first, then most recently updated.
        nearby.sort_by(|a, b| {
            a.local_port
                .abs_diff(peer.port)
                .cmp(&b.local_port.abs_diff(peer.port))
                .then(b.updated.total_cmp(&a.updated))
        });
        candidates = nearby.into_iter().take(1).collect();
    }

    candidates.retain(|e| e.expires >= now);
    // A flow the redirect has seen closing is a last resort, not a first choice.
    if candidates.iter().any(|e| !e.closing) {
        candidates.retain(|e| !e.closing);
    }
    candidates.sort_by(|a, b| b.updated.total_cmp(&a.updated));
    candidates.into_iter().find(|e| e.is_usable())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: u16 = 1372;

    fn entry(host: &str, port: u16, target: &str, updated: f64) -> DivertEntry {
        DivertEntry {
            local_host: host.to_string(),
            local_port: port,
            service_port: RELAY,
            target_host: target.to_string(),
            target_port: 443,
            updated,
            expires: updated + 60.0,
            closing: false,
        }
    }

    fn peer(host: &str, port: u16) -> Peer<'_> {
        Peer { host, port, service_port: RELAY }
    }

    #[test]
    fn loopback_is_recognised_by_address_and_by_name() {
        for host in ["127.0.0.1", "127.9.9.9", "::1", "localhost", "LOCALHOST"] {
            assert!(is_loopback(host), "{host}");
        }
        for host in ["192.168.1.5", "8.8.8.8", "", "not-an-ip"] {
            assert!(!is_loopback(host), "{host}");
        }
    }

    #[test]
    fn the_exact_address_wins() {
        let entries = vec![entry("192.168.1.5", 50000, "149.154.167.51", 100.0)];
        let found = match_entry(&entries, peer("192.168.1.5", 50000), 110.0).expect("match");
        assert_eq!(found.target_host, "149.154.167.51");
    }

    #[test]
    fn the_same_port_on_the_same_service_matches_under_another_host() {
        // The redirect and the socket can disagree about which of a machine's
        // addresses is "the" local one.
        let entries = vec![entry("10.0.0.7", 50000, "149.154.167.51", 100.0)];
        let found = match_entry(&entries, peer("192.168.1.5", 50000), 110.0).expect("match");
        assert_eq!(found.target_host, "149.154.167.51");
    }

    #[test]
    fn a_different_service_port_is_not_this_relays_flow() {
        let mut e = entry("10.0.0.7", 50000, "149.154.167.51", 100.0);
        e.service_port = 17870;
        assert!(match_entry(&[e], peer("192.168.1.5", 50000), 110.0).is_none());
    }

    #[test]
    fn a_nearby_port_on_the_same_host_is_taken_as_the_same_flow() {
        // The source port can move between the redirect recording it and the
        // connection arriving.
        let entries = vec![entry("192.168.1.5", 50010, "149.154.167.51", 100.0)];
        let found = match_entry(&entries, peer("192.168.1.5", 50000), 104.0).expect("match");
        assert_eq!(found.local_port, 50010);
    }

    #[test]
    fn the_nearby_window_is_bounded_at_sixteen_ports_and_eight_seconds() {
        // The bounds are what keep this a repair for a race rather than a way to
        // attach a session to somebody else's flow.
        let just_inside = vec![entry("192.168.1.5", 50016, "a", 100.0)];
        assert!(match_entry(&just_inside, peer("192.168.1.5", 50000), 108.0).is_some());

        let too_far = vec![entry("192.168.1.5", 50017, "a", 100.0)];
        assert!(match_entry(&too_far, peer("192.168.1.5", 50000), 108.0).is_none());

        let too_old = vec![entry("192.168.1.5", 50010, "a", 100.0)];
        assert!(match_entry(&too_old, peer("192.168.1.5", 50000), 108.1).is_none());
    }

    #[test]
    fn a_loopback_peer_never_gets_a_nearby_match() {
        // It arrived through the PAC with an address the redirect never wrote;
        // a nearby match would attach it to an unrelated flow.
        let entries = vec![entry("127.0.0.1", 50010, "149.154.167.51", 100.0)];
        assert!(match_entry(&entries, peer("127.0.0.1", 50000), 104.0).is_none());
        // The exact address still works for it.
        assert!(match_entry(&entries, peer("127.0.0.1", 50010), 104.0).is_some());
    }

    #[test]
    fn the_closest_port_wins_even_when_a_farther_one_is_newer() {
        // Distance decides first and recency only breaks ties. Written this way
        // after a mutation that sorted by recency alone passed the earlier
        // version, where the two happened to agree.
        let entries = vec![
            entry("192.168.1.5", 50010, "far-but-newer", 103.9),
            entry("192.168.1.5", 50001, "closest", 100.0),
        ];
        let found = match_entry(&entries, peer("192.168.1.5", 50000), 104.0).expect("match");
        assert_eq!(found.target_host, "closest");
    }

    #[test]
    fn recency_breaks_a_tie_in_distance() {
        let entries = vec![
            entry("192.168.1.5", 50002, "same-distance-old", 100.0),
            entry("192.168.1.5", 49998, "same-distance-new", 103.5),
        ];
        let found = match_entry(&entries, peer("192.168.1.5", 50000), 104.0).expect("match");
        assert_eq!(found.target_host, "same-distance-new");
    }

    #[test]
    fn an_expired_entry_is_never_returned() {
        let mut e = entry("192.168.1.5", 50000, "a", 100.0);
        e.expires = 105.0;
        assert!(match_entry(std::slice::from_ref(&e), peer("192.168.1.5", 50000), 104.9).is_some());
        let expired = [e];
        assert!(match_entry(&expired, peer("192.168.1.5", 50000), 105.1).is_none());
    }

    #[test]
    fn a_closing_flow_is_a_last_resort_not_a_first_choice() {
        let mut closing = entry("192.168.1.5", 50000, "closing", 105.0);
        closing.closing = true;
        let open = entry("192.168.1.5", 50000, "open", 100.0);
        // The closing one is newer, and still loses.
        let both = [closing.clone(), open];
        let found = match_entry(&both, peer("192.168.1.5", 50000), 110.0).expect("match");
        assert_eq!(found.target_host, "open");
        // With nothing else, it is used.
        let alone = [closing];
        let only = match_entry(&alone, peer("192.168.1.5", 50000), 110.0).expect("match");
        assert_eq!(only.target_host, "closing");
    }

    #[test]
    fn a_row_with_no_usable_target_is_not_a_match() {
        // It would send the tunnel to `":0"`, which fails later and further away
        // from the cause.
        let mut empty = entry("192.168.1.5", 50000, "  ", 100.0);
        assert!(match_entry(std::slice::from_ref(&empty), peer("192.168.1.5", 50000), 110.0).is_none());
        empty.target_host = "149.154.167.51".to_string();
        empty.target_port = 0;
        let no_port = [empty];
        assert!(match_entry(&no_port, peer("192.168.1.5", 50000), 110.0).is_none());
    }

    #[test]
    fn the_newest_of_several_exact_matches_wins() {
        let entries =
            vec![entry("192.168.1.5", 50000, "older", 100.0), entry("192.168.1.5", 50000, "newer", 106.0)];
        let found = match_entry(&entries, peer("192.168.1.5", 50000), 110.0).expect("match");
        assert_eq!(found.target_host, "newer");
    }

    #[test]
    fn a_diverted_peer_is_given_far_more_patience_than_a_pac_one() {
        // The record for a diverted flow can still be on its way; a PAC one was
        // either recorded already or never will be.
        assert_eq!(read_attempts(false), 40);
        assert_eq!(read_attempts(true), 3);
        assert_eq!(RETRY_PAUSE * read_attempts(false), Duration::from_secs(2));
    }

    #[test]
    fn nothing_to_match_against_is_not_a_match() {
        assert!(match_entry(&[], peer("192.168.1.5", 50000), 110.0).is_none());
    }
}
