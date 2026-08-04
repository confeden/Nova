use crate::Seconds;

/// What a single connection attempt actually did.
///
/// The Python learner collapsed everything to a bool, which threw away the one
/// thing that tells a DPI block apart from a dead site. Keeping the shape of
/// the failure lets the learner skip whole families of strategies (there is no
/// point trying TLS-fragmentation tricks against a DNS poisoning) and lets the
/// Cloudflare detector reason about *why* a probe failed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// Full request/response cycle completed.
    Success {
        /// Milliseconds from connect start to first response byte.
        latency_ms: u32,
    },
    /// Connection established and data flowed, but the peer answered with a
    /// block page or a challenge rather than content.
    Intercepted { signature: BlockSignature },
    /// Connection did not complete.
    Failed { signature: BlockSignature },
}

impl ProbeOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, ProbeOutcome::Success { .. })
    }

    pub fn signature(&self) -> Option<BlockSignature> {
        match self {
            ProbeOutcome::Success { .. } => None,
            ProbeOutcome::Intercepted { signature } | ProbeOutcome::Failed { signature } => Some(*signature),
        }
    }

    pub fn latency_ms(&self) -> Option<u32> {
        match self {
            ProbeOutcome::Success { latency_ms } => Some(*latency_ms),
            _ => None,
        }
    }
}

/// The fingerprint of an interference event.
///
/// Ordering of the variants is meaningless; the discriminants are never
/// persisted numerically (serde uses the snake_case names) so variants may be
/// added without breaking on-disk state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockSignature {
    /// TCP RST arrived with minimal delay after our ClientHello — far sooner
    /// than a round trip to the server.
    ///
    /// Per the zapret manual: *"если вместо ACK или SACK идет RST пакет с
    /// минимальной задержкой, то DPI вас отсекает еще на этапе вашего
    /// запроса"*. The DPI cut the **request**, so request-side desync (fake,
    /// split, hostfakesplit, TTL games) is the family that can defeat it.
    RstImmediate,
    /// TCP RST arrived roughly one round trip after the ClientHello.
    ///
    /// *"Если RST идет после полного ACK спустя задержку, равную примерно пингу
    /// до сервера, тогда вероятно DPI реагирует на ответ сервера"* — the DPI
    /// inspected the server's ServerHello / certificate. Mangling our own
    /// request cannot help; the countermeasure is to make the *server* fragment
    /// its reply, which is what `--wssize` does.
    ///
    /// Keeping this apart from [`BlockSignature::RstImmediate`] is what lets the
    /// learner stop spending probes on a whole family of strategies that are
    /// structurally incapable of fixing this case.
    RstAfterServerHello,
    /// Connection opened, ClientHello sent, then silence. Typical of SNI-based
    /// blackholing where the DPI drops rather than resets.
    SniTimeout,
    /// SYN never answered. Route-level blackhole of the destination IP; no
    /// amount of payload tampering will fix it, only a different egress.
    Blackholed,
    /// SYN answered with RST immediately. Usually the host really is down, or a
    /// local firewall refused — not a DPI event.
    ConnectionRefused,
    /// Resolver returned an address that does not belong to the service
    /// (registry stub, provider sinkhole).
    DnsPoisoned,
    /// Name did not resolve at all.
    DnsFailure,
    /// TLS completed but the certificate did not match the requested name —
    /// interception proxy or wrong-origin sinkhole.
    TlsCertificateMismatch,
    /// Provider's "access restricted by RF law" interstitial or an equivalent
    /// HTTP-level substitution.
    IspBlockPage,
    /// Cloudflare's managed challenge / "Just a moment…" / error 1020.
    CloudflareChallenge,
    /// Cloudflare edge reachable but the origin behind it is not (5xx family
    /// 52x). Distinguishes "our path to CF is fine" from "CF is unreachable".
    CloudflareOriginDown,
    /// Something failed in a way Nova could not classify.
    Unknown,
}

/// The family of countermeasures that can plausibly defeat a given block.
///
/// This is the mechanism that makes the learner adaptive rather than merely
/// exhaustive: knowing *how* a connection failed rules out most of the strategy
/// pool before a single probe is spent. The families come from the zapret
/// author's own account of what each technique acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Countermeasure {
    /// Mangle our outbound request so the DPI cannot parse the hostname:
    /// `fake`, `multisplit`, `multidisorder`, `hostfakesplit`, TTL and fooling
    /// tricks. The large majority of Nova's corpus.
    RequestSideDesync,
    /// Make the server fragment its own reply so the DPI cannot reassemble the
    /// certificate — `--wssize`. Note the manual's constraint: wssize acts from
    /// the start of the connection and therefore does not work inside profiles
    /// that are gated by a hostlist.
    ServerResponseFragmentation,
    /// No packet manipulation helps; the traffic has to leave by another route.
    DifferentEgress,
    /// Nothing to do — the failure is not ours.
    None,
}

impl BlockSignature {
    /// Which family of countermeasures applies.
    pub fn countermeasure(self) -> Countermeasure {
        match self {
            BlockSignature::RstImmediate
            | BlockSignature::SniTimeout
            | BlockSignature::IspBlockPage
            | BlockSignature::Unknown => Countermeasure::RequestSideDesync,
            BlockSignature::RstAfterServerHello => Countermeasure::ServerResponseFragmentation,
            BlockSignature::Blackholed
            | BlockSignature::DnsPoisoned
            | BlockSignature::TlsCertificateMismatch
            | BlockSignature::CloudflareChallenge => Countermeasure::DifferentEgress,
            BlockSignature::ConnectionRefused
            | BlockSignature::CloudflareOriginDown
            | BlockSignature::DnsFailure => Countermeasure::None,
        }
    }

    /// True when a winws DPI-bypass strategy could plausibly defeat this.
    ///
    /// Drives the learner's candidate filter: on a `Blackholed` or `DnsPoisoned`
    /// verdict there is nothing to learn about strategies, so the engine must
    /// change transport instead of burning probes on the strategy pool.
    pub fn is_dpi_addressable(self) -> bool {
        matches!(
            self.countermeasure(),
            Countermeasure::RequestSideDesync | Countermeasure::ServerResponseFragmentation
        )
    }

    /// True when the right answer is to leave via a different egress entirely.
    pub fn needs_different_egress(self) -> bool {
        self.countermeasure() == Countermeasure::DifferentEgress
    }

    /// True when the failure says nothing about Nova's configuration, so it
    /// must not be counted against the current strategy or transport.
    ///
    /// Charging these to the active arm is how a learner slowly poisons its own
    /// best option during an unrelated outage.
    pub fn is_not_our_fault(self) -> bool {
        self.countermeasure() == Countermeasure::None
    }
}

/// The engine's decision about a group at a point in time.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Verdict {
    pub transport: crate::Transport,
    /// Uptime seconds at which this verdict was taken.
    pub at: Seconds,
    /// Why the engine chose this, in words the log window can show verbatim.
    pub reason: String,
    /// Set when the verdict is a temporary deviation from the configured route
    /// and should be revisited.
    pub expires_at: Option<Seconds>,
}

impl Verdict {
    pub fn new(transport: crate::Transport, at: Seconds, reason: impl Into<String>) -> Self {
        Self { transport, at, reason: reason.into(), expires_at: None }
    }

    pub fn expiring(mut self, at: Seconds) -> Self {
        self.expires_at = Some(at);
        self
    }

    pub fn is_expired(&self, now: Seconds) -> bool {
        self.expires_at.is_some_and(|deadline| now >= deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transport;

    #[test]
    fn signature_routing_hints_are_disjoint_where_it_matters() {
        assert!(BlockSignature::RstImmediate.is_dpi_addressable());
        assert!(!BlockSignature::RstImmediate.needs_different_egress());
        assert!(BlockSignature::Blackholed.needs_different_egress());
        assert!(!BlockSignature::Blackholed.is_dpi_addressable());
    }

    #[test]
    fn the_two_rst_timings_demand_different_countermeasures() {
        // The zapret manual distinguishes an immediate RST (DPI cut our request)
        // from an RST arriving ~one RTT later (DPI read the server's
        // ServerHello). Conflating them makes the learner burn its whole probe
        // budget on request-side tricks that cannot possibly work.
        assert_eq!(BlockSignature::RstImmediate.countermeasure(), Countermeasure::RequestSideDesync);
        assert_eq!(
            BlockSignature::RstAfterServerHello.countermeasure(),
            Countermeasure::ServerResponseFragmentation
        );
        assert_ne!(
            BlockSignature::RstImmediate.countermeasure(),
            BlockSignature::RstAfterServerHello.countermeasure()
        );
        // Both are still winws-addressable, just by different techniques.
        assert!(BlockSignature::RstImmediate.is_dpi_addressable());
        assert!(BlockSignature::RstAfterServerHello.is_dpi_addressable());
    }

    #[test]
    fn every_signature_maps_to_exactly_one_countermeasure_family() {
        use BlockSignature::*;
        for sig in [
            RstImmediate,
            RstAfterServerHello,
            SniTimeout,
            Blackholed,
            ConnectionRefused,
            DnsPoisoned,
            DnsFailure,
            TlsCertificateMismatch,
            IspBlockPage,
            CloudflareChallenge,
            CloudflareOriginDown,
            Unknown,
        ] {
            let family = sig.countermeasure();
            // The three predicates are views onto the same classification and
            // must never disagree — that was the bug shape in the Python code,
            // where separate lists of signatures drifted apart.
            assert_eq!(sig.is_not_our_fault(), family == Countermeasure::None, "{sig:?}");
            assert_eq!(sig.needs_different_egress(), family == Countermeasure::DifferentEgress, "{sig:?}");
            assert_eq!(
                sig.is_dpi_addressable(),
                matches!(family, Countermeasure::RequestSideDesync | Countermeasure::ServerResponseFragmentation),
                "{sig:?}"
            );
        }
    }

    #[test]
    fn unattributable_failures_are_flagged() {
        assert!(BlockSignature::ConnectionRefused.is_not_our_fault());
        assert!(BlockSignature::CloudflareOriginDown.is_not_our_fault());
        assert!(!BlockSignature::RstImmediate.is_not_our_fault());
    }

    #[test]
    fn expiring_verdicts_lapse() {
        let v = Verdict::new(Transport::Warp, 100, "configured").expiring(160);
        assert!(!v.is_expired(159));
        assert!(v.is_expired(160));
        assert!(!Verdict::new(Transport::Warp, 100, "configured").is_expired(u64::MAX));
    }

    #[test]
    fn probe_outcome_accessors() {
        let ok = ProbeOutcome::Success { latency_ms: 42 };
        assert!(ok.is_success());
        assert_eq!(ok.latency_ms(), Some(42));
        assert_eq!(ok.signature(), None);
        let bad = ProbeOutcome::Failed { signature: BlockSignature::RstImmediate };
        assert_eq!(bad.signature(), Some(BlockSignature::RstImmediate));
    }
}
