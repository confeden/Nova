//! Signal chain for "is this site fronted by Cloudflare, and can we reach it".

use std::net::IpAddr;

use nova_core::{BlockSignature, Domain};

use crate::ranges::Ranges;

/// Evidence gathered about one host, from whatever sources happened to be
/// available. Every field is optional so the classifier works off a DNS answer
/// alone, off response headers alone, or off both.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Evidence {
    /// Addresses the host resolved to.
    pub addresses: Vec<IpAddr>,
    /// CNAME chain, lowercased.
    pub cname_chain: Vec<String>,
    /// Value of the HTTP `server` header, lowercased.
    pub server_header: Option<String>,
    /// Whether a `cf-ray` header was present. The single most specific header
    /// signal: it is emitted by every Cloudflare edge response and by nothing
    /// else.
    pub cf_ray: bool,
    /// Whether the response carried `cf-mitigated`, i.e. the edge itself
    /// challenged the request.
    pub cf_mitigated: bool,
    /// HTTP status code, when a response was obtained at all.
    pub status: Option<u16>,
    /// How the connection failed, when it did.
    pub failure: Option<BlockSignature>,
}

/// What Nova concluded about a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Confirmed Cloudflare edge, and it answered.
    Fronted,
    /// Confirmed Cloudflare edge, and the path to it is being interfered with.
    ///
    /// This is the case requirement 5 exists for: the ISP blocks Cloudflare's
    /// ranges, so the site is unreachable even though nothing is wrong with it.
    FrontedAndBlocked,
    /// Confirmed Cloudflare edge; the edge is up but the customer's origin is
    /// not. Rerouting will not help and must not be attempted.
    FrontedOriginDown,
    /// Definitely not Cloudflare.
    NotFronted,
    /// Not enough evidence either way.
    Unknown,
}

impl Classification {
    /// Whether this classification justifies overriding the configured route.
    pub fn warrants_reroute(self) -> bool {
        matches!(self, Classification::FrontedAndBlocked)
    }

    pub fn is_cloudflare(self) -> bool {
        matches!(
            self,
            Classification::Fronted | Classification::FrontedAndBlocked | Classification::FrontedOriginDown
        )
    }
}

/// Confidence attached to a classification, so a weak DNS-only guess can be
/// distinguished from a header-confirmed fact when deciding whether to act.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
pub struct Confidence(f32);

impl Confidence {
    pub const CERTAIN: Confidence = Confidence(1.0);
    /// Minimum confidence at which Nova will silently change a site's route.
    ///
    /// Set high because the failure mode of a false positive is user-visible:
    /// traffic that should have gone direct gets tunnelled through WARP, adding
    /// latency and changing the apparent country of a site that was working.
    pub const ACT_THRESHOLD: Confidence = Confidence(0.75);

    pub fn new(value: f32) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    pub fn value(self) -> f32 {
        self.0
    }

    pub fn is_actionable(self) -> bool {
        self.0 >= Self::ACT_THRESHOLD.0
    }
}

/// Classifier over the evidence chain.
#[derive(Debug, Clone, Default)]
pub struct Detector {
    ranges: Ranges,
}

impl Detector {
    pub fn new(ranges: Ranges) -> Self {
        Self { ranges }
    }

    pub fn ranges(&self) -> &Ranges {
        &self.ranges
    }

    pub fn set_ranges(&mut self, ranges: Ranges) {
        self.ranges = ranges;
    }

    /// Classify a host from whatever evidence exists.
    ///
    /// The signals are ordered by specificity, strongest first, and the first
    /// one that settles the question wins. Cheap signals (a DNS answer Nova
    /// already had to make anyway) are enough on their own; the expensive
    /// header probe is only needed when DNS is ambiguous.
    pub fn classify(&self, host: &Domain, evidence: &Evidence) -> (Classification, Confidence) {
        // 1. `cf-ray` is emitted by Cloudflare edges and by nothing else. If we
        //    got one, the question of "is it Cloudflare" is closed.
        if evidence.cf_ray {
            return (self.reachability(evidence), Confidence::CERTAIN);
        }

        // 2. A CNAME into Cloudflare's own zones is equally conclusive and costs
        //    nothing beyond the resolution Nova already performs.
        if evidence.cname_chain.iter().any(|c| is_cloudflare_cname(c)) {
            return (self.reachability(evidence), Confidence(0.95));
        }

        // 3. Every resolved address inside the published prefixes. Strong, but
        //    not conclusive: a customer can point a record at a Cloudflare IP
        //    they do not control, and more importantly a poisoned resolver can
        //    fabricate this.
        let in_range =
            !evidence.addresses.is_empty() && evidence.addresses.iter().all(|ip| self.ranges.contains(*ip));
        if in_range {
            let confidence = if evidence.server_header.as_deref() == Some("cloudflare") {
                Confidence::CERTAIN
            } else {
                Confidence(0.85)
            };
            return (self.reachability(evidence), confidence);
        }

        // 4. `server: cloudflare` without any address corroboration. Trivially
        //    forgeable by an interception proxy, so it is a hint, not a fact.
        if evidence.server_header.as_deref() == Some("cloudflare") {
            return (self.reachability(evidence), Confidence(0.6));
        }

        // 5. A partial address match means a mixed deployment — some records on
        //    Cloudflare, some not. Worth remembering, not worth acting on.
        if evidence.addresses.iter().any(|ip| self.ranges.contains(*ip)) {
            return (Classification::Fronted, Confidence(0.5));
        }

        if evidence.addresses.is_empty() && evidence.status.is_none() && evidence.failure.is_none() {
            tracing::trace!(%host, "no evidence to classify");
            return (Classification::Unknown, Confidence(0.0));
        }
        if evidence.addresses.is_empty() {
            return (Classification::Unknown, Confidence(0.0));
        }
        (Classification::NotFronted, Confidence(0.8))
    }

    /// Given that the host *is* on Cloudflare, decide whether we can reach it.
    fn reachability(&self, evidence: &Evidence) -> Classification {
        // Cloudflare's 52x family means the edge answered and the origin did
        // not. Rerouting Nova's egress cannot fix someone else's dead server,
        // and trying would make Nova look responsible for the outage.
        if let Some(status) = evidence.status
            && (520..=527).contains(&status)
        {
            return Classification::FrontedOriginDown;
        }
        if evidence.cf_mitigated || evidence.status == Some(403) {
            // A managed challenge is not an ISP block, but it is still a reason
            // to change egress: the challenge is usually aimed at the datacentre
            // or reputation of the exit address.
            return Classification::FrontedAndBlocked;
        }
        match evidence.failure {
            Some(sig) if sig.is_not_our_fault() => Classification::FrontedOriginDown,
            Some(_) => Classification::FrontedAndBlocked,
            None => Classification::Fronted,
        }
    }
}

/// CNAME targets that only Cloudflare operates.
fn is_cloudflare_cname(name: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        ".cdn.cloudflare.net",
        ".cloudflare.net",
        ".cloudflaressl.com",
        ".pages.dev",
        ".workers.dev",
        ".cdn.cloudflare.com",
    ];
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    SUFFIXES.iter().any(|s| name.ends_with(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(s: &str) -> Domain {
        Domain::parse(s).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn detector() -> Detector {
        Detector::new(Ranges::builtin())
    }

    #[test]
    fn cf_ray_alone_is_conclusive() {
        let ev = Evidence { cf_ray: true, status: Some(200), ..Default::default() };
        let (class, conf) = detector().classify(&host("example.com"), &ev);
        assert_eq!(class, Classification::Fronted);
        assert_eq!(conf, Confidence::CERTAIN);
    }

    #[test]
    fn dns_alone_is_enough_to_act_on() {
        let ev = Evidence {
            addresses: vec![ip("104.16.132.229"), ip("104.16.133.229")],
            failure: Some(BlockSignature::SniTimeout),
            ..Default::default()
        };
        let (class, conf) = detector().classify(&host("chatgpt.com"), &ev);
        assert_eq!(class, Classification::FrontedAndBlocked);
        assert!(conf.is_actionable(), "a clean DNS-in-range answer must be actionable on its own");
        assert!(class.warrants_reroute());
    }

    #[test]
    fn cname_into_cloudflare_is_recognised() {
        let ev = Evidence {
            cname_chain: vec!["site.example.com.cdn.cloudflare.net".to_owned()],
            addresses: vec![ip("8.8.8.8")],
            ..Default::default()
        };
        let (class, conf) = detector().classify(&host("site.example.com"), &ev);
        assert!(class.is_cloudflare());
        assert!(conf.is_actionable());
    }

    #[test]
    fn a_dead_origin_must_not_trigger_rerouting() {
        for status in [520u16, 521, 522, 523, 524, 525, 526, 527] {
            let ev = Evidence { cf_ray: true, status: Some(status), ..Default::default() };
            let (class, _) = detector().classify(&host("example.com"), &ev);
            assert_eq!(class, Classification::FrontedOriginDown, "status {status}");
            assert!(!class.warrants_reroute(), "status {status} must not reroute");
        }
    }

    #[test]
    fn a_managed_challenge_does_warrant_a_different_egress() {
        let ev = Evidence { cf_ray: true, cf_mitigated: true, status: Some(403), ..Default::default() };
        let (class, _) = detector().classify(&host("example.com"), &ev);
        assert!(class.warrants_reroute());
    }

    #[test]
    fn a_forgeable_server_header_alone_is_not_actionable() {
        let ev = Evidence {
            server_header: Some("cloudflare".to_owned()),
            addresses: vec![ip("93.158.134.3")],
            failure: Some(BlockSignature::RstImmediate),
            ..Default::default()
        };
        let (class, conf) = detector().classify(&host("suspicious.example"), &ev);
        assert!(class.is_cloudflare());
        assert!(!conf.is_actionable(), "an unverifiable header must not silently reroute traffic");
    }

    #[test]
    fn ordinary_sites_are_classified_as_not_fronted() {
        let ev = Evidence {
            addresses: vec![ip("93.158.134.3")],
            server_header: Some("nginx".to_owned()),
            status: Some(200),
            ..Default::default()
        };
        let (class, conf) = detector().classify(&host("ya.ru"), &ev);
        assert_eq!(class, Classification::NotFronted);
        assert!(conf.is_actionable());
    }

    #[test]
    fn no_evidence_yields_unknown_rather_than_a_guess() {
        let (class, conf) = detector().classify(&host("example.com"), &Evidence::default());
        assert_eq!(class, Classification::Unknown);
        assert!(!conf.is_actionable());
        assert!(!class.warrants_reroute());
    }
}
