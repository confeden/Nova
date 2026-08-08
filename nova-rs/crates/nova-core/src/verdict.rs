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

    // --- Phases of Nova's *own* tunnel ------------------------------------
    //
    // The signatures above describe a probe sent to somebody else's site,
    // where winws is the thing standing between Nova and the DPI. The four
    // below describe the relay's own TLS connection to a WebSocket endpoint,
    // where Nova writes the ClientHello itself and therefore has levers the
    // site prober does not have. Same enum because the countermeasure map is
    // the point of the type; distinct variants because the remedies differ.
    /// Our ClientHello left, TCP stayed up, and no ServerHello ever came back.
    ///
    /// The two candidate explanations — the name is blocked, or our TLS
    /// fingerprint is — are indistinguishable from a single attempt. They are
    /// separable by experiment: retry the same name with a different
    /// ClientHello shape and see. That is why this maps to
    /// [`Countermeasure::TlsFingerprint`] rather than to a hostname verdict —
    /// the cheap, reversible move is to change our own shape first.
    ///
    /// Deliberately *not* folded into [`BlockSignature::SniTimeout`]: that one
    /// is observed by the site prober, where the answer is a winws strategy,
    /// and charging it a TLS-profile rotation would rotate a knob that does
    /// not exist on that path.
    TunnelHandshakeIgnored,
    /// TLS completed, but the WebSocket upgrade answered with something other
    /// than `101`.
    ///
    /// Somebody terminated TLS and spoke HTTP back, which means the transport
    /// reached *a* server. The endpoint is the suspect, not the network path
    /// and not our fingerprint.
    TunnelUpgradeRejected,
    /// The handshake finished and nothing usable ever came back — the endpoint
    /// answered nothing at all, or answered `101` and then stayed silent.
    ///
    /// The near leg is proven to work all the way through the handshake, so
    /// the break is beyond the endpoint — the relay's route to the datacentre.
    /// Rotating our ClientHello here would be charging the one layer that just
    /// demonstrated it works.
    TunnelStalled,
    /// Data flowed both ways and the stream died far sooner than a session
    /// should last.
    ///
    /// Everything static about the connection passed inspection, so what got
    /// it killed is what a static check cannot see: sizes, timing, duration,
    /// volume. The lever is the shape of the traffic, not the handshake.
    TunnelSevered,

    /// Something failed in a way Nova could not classify.
    Unknown,
}

impl BlockSignature {
    /// Every variant, so exhaustiveness tests cannot silently fall behind.
    ///
    /// A plain `match` in [`BlockSignature::countermeasure`] already forces a
    /// new variant to be classified, but nothing forces it to be *tested*. The
    /// test that walks this array closes that gap, and the compile-time check
    /// in `all_is_complete` keeps the array itself honest.
    pub const ALL: [BlockSignature; 16] = [
        BlockSignature::RstImmediate,
        BlockSignature::RstAfterServerHello,
        BlockSignature::SniTimeout,
        BlockSignature::Blackholed,
        BlockSignature::ConnectionRefused,
        BlockSignature::DnsPoisoned,
        BlockSignature::DnsFailure,
        BlockSignature::TlsCertificateMismatch,
        BlockSignature::IspBlockPage,
        BlockSignature::CloudflareChallenge,
        BlockSignature::CloudflareOriginDown,
        BlockSignature::TunnelHandshakeIgnored,
        BlockSignature::TunnelUpgradeRejected,
        BlockSignature::TunnelStalled,
        BlockSignature::TunnelSevered,
        BlockSignature::Unknown,
    ];
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
    /// Rebuild our own ClientHello in a different shape.
    ///
    /// Only reachable on connections Nova originates itself, where the hello
    /// is ours to write. Kept apart from [`Countermeasure::RequestSideDesync`]
    /// because the two act on opposite objects: desync mangles a hello so the
    /// DPI *cannot parse* it, while this one makes a hello the DPI parses
    /// happily and files under "some browser".
    TlsFingerprint,
    /// Change the sizes and timing of what we send once the handshake is done.
    ///
    /// The remedy for interference that arrives only after a connection has
    /// proven itself well-formed, which no amount of handshake work can reach.
    TrafficShape,
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
            BlockSignature::TunnelHandshakeIgnored => Countermeasure::TlsFingerprint,
            BlockSignature::TunnelSevered => Countermeasure::TrafficShape,
            BlockSignature::Blackholed
            | BlockSignature::DnsPoisoned
            | BlockSignature::TlsCertificateMismatch
            | BlockSignature::CloudflareChallenge
            | BlockSignature::TunnelUpgradeRejected
            | BlockSignature::TunnelStalled => Countermeasure::DifferentEgress,
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
    ///
    /// The tunnel families are excluded on purpose. winws rewrites packets on
    /// their way out of this machine; the relay's own TLS connection is shaped
    /// before it becomes a packet at all, so a strategy pool has no lever on it.
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

    /// True when the tunnel should try a different ClientHello shape.
    ///
    /// Narrow by design. Rotating the profile on a DNS error or a dead TCP
    /// route retires a shape that was never given a chance to be judged, and
    /// the pool of good shapes is small enough that this matters: a handful of
    /// misattributed failures can burn all of them on a network whose actual
    /// problem was somewhere else entirely.
    pub fn wants_tls_profile_change(self) -> bool {
        self.countermeasure() == Countermeasure::TlsFingerprint
    }

    /// True when the tunnel should change the sizes and timing it emits.
    pub fn wants_traffic_reshape(self) -> bool {
        self.countermeasure() == Countermeasure::TrafficShape
    }

    /// True when the failure was observed on Nova's own tunnel rather than on
    /// a probe to somebody else's site.
    ///
    /// Lets a caller holding a mixed stream of observations route each one to
    /// the subsystem that owns the corresponding lever.
    pub fn is_tunnel_phase(self) -> bool {
        matches!(
            self,
            BlockSignature::TunnelHandshakeIgnored
                | BlockSignature::TunnelUpgradeRejected
                | BlockSignature::TunnelStalled
                | BlockSignature::TunnelSevered
        )
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
    fn all_lists_every_variant_exactly_once() {
        // The exhaustive match is the guard: adding a variant stops this test
        // compiling, which is the reminder that `ALL` needs it too. The array's
        // fixed length then refuses to accept the addition silently.
        for sig in BlockSignature::ALL {
            match sig {
                BlockSignature::RstImmediate
                | BlockSignature::RstAfterServerHello
                | BlockSignature::SniTimeout
                | BlockSignature::Blackholed
                | BlockSignature::ConnectionRefused
                | BlockSignature::DnsPoisoned
                | BlockSignature::DnsFailure
                | BlockSignature::TlsCertificateMismatch
                | BlockSignature::IspBlockPage
                | BlockSignature::CloudflareChallenge
                | BlockSignature::CloudflareOriginDown
                | BlockSignature::TunnelHandshakeIgnored
                | BlockSignature::TunnelUpgradeRejected
                | BlockSignature::TunnelStalled
                | BlockSignature::TunnelSevered
                | BlockSignature::Unknown => {}
            }
        }
        let mut seen = std::collections::HashSet::new();
        for sig in BlockSignature::ALL {
            assert!(seen.insert(sig), "{sig:?} appears in ALL twice");
        }
    }

    #[test]
    fn every_signature_maps_to_exactly_one_countermeasure_family() {
        for sig in BlockSignature::ALL {
            let family = sig.countermeasure();
            // The predicates are views onto the same classification and must
            // never disagree — that was the bug shape in the Python code, where
            // separate lists of signatures drifted apart.
            assert_eq!(sig.is_not_our_fault(), family == Countermeasure::None, "{sig:?}");
            assert_eq!(sig.needs_different_egress(), family == Countermeasure::DifferentEgress, "{sig:?}");
            assert_eq!(sig.wants_tls_profile_change(), family == Countermeasure::TlsFingerprint, "{sig:?}");
            assert_eq!(sig.wants_traffic_reshape(), family == Countermeasure::TrafficShape, "{sig:?}");
            assert_eq!(
                sig.is_dpi_addressable(),
                matches!(family, Countermeasure::RequestSideDesync | Countermeasure::ServerResponseFragmentation),
                "{sig:?}"
            );
        }
    }

    #[test]
    fn exactly_one_phase_rotates_the_tls_profile() {
        // The pool of ClientHello shapes that a filtering network tolerates is
        // small. Every phase that rotates it without evidence about the hello
        // spends one of them, so the set is deliberately a single element.
        let rotating: Vec<_> =
            BlockSignature::ALL.into_iter().filter(|s| s.wants_tls_profile_change()).collect();
        assert_eq!(rotating, vec![BlockSignature::TunnelHandshakeIgnored]);
    }

    #[test]
    fn phases_before_the_hello_never_blame_the_hello() {
        // DNS and TCP resolve before a ClientHello exists; a route that dies
        // there says nothing about its shape. This is the misattribution that
        // makes a profile pool burn down on a network whose problem was the
        // resolver.
        for sig in [
            BlockSignature::DnsFailure,
            BlockSignature::DnsPoisoned,
            BlockSignature::Blackholed,
            BlockSignature::ConnectionRefused,
        ] {
            assert!(!sig.wants_tls_profile_change(), "{sig:?} rotated the profile");
        }
    }

    #[test]
    fn phases_after_a_working_handshake_never_blame_the_hello() {
        // An upgrade that answered, or a stream that carried bytes, is proof
        // the hello passed inspection. Charging it afterwards retires a shape
        // that had just demonstrated it works.
        for sig in [
            BlockSignature::TunnelUpgradeRejected,
            BlockSignature::TunnelStalled,
            BlockSignature::TunnelSevered,
        ] {
            assert!(!sig.wants_tls_profile_change(), "{sig:?} rotated the profile");
        }
    }

    #[test]
    fn tunnel_phases_are_not_winws_addressable() {
        // winws rewrites packets leaving this machine. The relay shapes its own
        // TLS before it is a packet, so routing a tunnel phase into the strategy
        // learner would spend probes on a knob that cannot reach it.
        for sig in BlockSignature::ALL.into_iter().filter(|s| s.is_tunnel_phase()) {
            assert!(!sig.is_dpi_addressable(), "{sig:?} leaked into the strategy pool");
        }
        assert_eq!(BlockSignature::ALL.into_iter().filter(|s| s.is_tunnel_phase()).count(), 4);
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
