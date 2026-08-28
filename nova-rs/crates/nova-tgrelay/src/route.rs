//! Which health bucket a WSS route belongs to.

/// The two families of WSS upstream.
///
/// The health table is keyed by `(dc, is_media, route_kind)`. Before the kind
/// was part of the key, two empty replies from the weaker route tripped the
/// breaker for the healthy one on the same DC — visible in the log as a
/// `web.telegram.org` pair at `down=0` followed immediately by the Worker zone
/// being paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WssRouteKind {
    /// Our own Cloudflare Worker zones.
    Cf,
    /// `kwsN[-1].web.telegram.org`.
    Web,
}

impl WssRouteKind {
    /// Classify a route label.
    ///
    /// Labels look like `domain via egress` or `domain@ip via egress`. An
    /// unparsable one counts as `Cf`, which is the path that carries most of the
    /// traffic and the behaviour these counters had before the split.
    pub fn from_label(label: &str) -> Self {
        let domain =
            label.split(" via ").next().unwrap_or("").split('@').next().unwrap_or("").trim().to_ascii_lowercase();
        if domain.ends_with("web.telegram.org") {
            Self::Web
        } else {
            Self::Cf
        }
    }

    pub const ALL: [Self; 2] = [Self::Cf, Self::Web];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_web_upstreams_are_web() {
        for label in [
            "kws2.web.telegram.org via warp-socks",
            "kws5-1.web.telegram.org via opera-http",
            "kws2.web.telegram.org@149.154.167.99 via direct",
            "WEB.TELEGRAM.ORG via direct",
        ] {
            assert_eq!(WssRouteKind::from_label(label), WssRouteKind::Web, "{label}");
        }
    }

    #[test]
    fn worker_zones_are_cf() {
        for label in ["kws2.nova-app.eu via warp-socks", "kws2-1.pclead.co.uk@104.21.0.1 via direct"] {
            assert_eq!(WssRouteKind::from_label(label), WssRouteKind::Cf, "{label}");
        }
    }

    #[test]
    fn an_unparsable_label_falls_back_to_cf_not_to_a_panic() {
        for label in ["", "   ", " via ", "@", "garbage"] {
            assert_eq!(WssRouteKind::from_label(label), WssRouteKind::Cf, "{label:?}");
        }
    }

    #[test]
    fn a_lookalike_suffix_does_not_count_as_web() {
        // Ends with the string but is not that zone — checked because a naive
        // "contains" would take it.
        assert_eq!(WssRouteKind::from_label("notweb.telegram.org.evil.example via direct"), WssRouteKind::Cf);
    }

    #[test]
    fn all_kinds_are_enumerated() {
        assert_eq!(WssRouteKind::ALL.len(), 2);
    }
}
