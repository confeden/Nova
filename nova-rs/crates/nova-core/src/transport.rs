use std::fmt;

/// How traffic for a group physically leaves the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// Straight out of the default route, no interception at all.
    Direct,
    /// Straight out of the default route, but with winws rewriting the first
    /// packets of each flow so the ISP's DPI does not recognise them.
    DirectBypass,
    /// Cloudflare WARP tunnel (warp-cli or the bundled wireproxy-awg).
    Warp,
    /// Opera's built-in VPN endpoints via opera-proxy.
    Opera,
}

impl TransportKind {
    /// Transports Nova can fall back *to* without user interaction, ordered by
    /// preference. `Direct` is deliberately absent: falling back to a fully
    /// unprotected path would silently expose traffic the user asked to tunnel.
    pub const FALLBACK_ORDER: [TransportKind; 3] =
        [TransportKind::Warp, TransportKind::Opera, TransportKind::DirectBypass];

    /// Whether this transport hides the client IP from the destination.
    ///
    /// Used to warn before a fallback changes the user's exposure, and to keep
    /// geo-sensitive groups off non-tunnelled paths.
    pub fn is_tunnelled(self) -> bool {
        matches!(self, TransportKind::Warp | TransportKind::Opera)
    }

    /// Whether winws must be running for this transport to work.
    pub fn needs_dpi_bypass(self) -> bool {
        matches!(self, TransportKind::DirectBypass)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::Direct => "direct",
            TransportKind::DirectBypass => "direct+winws",
            TransportKind::Warp => "warp",
            TransportKind::Opera => "opera",
        }
    }
}

impl fmt::Display for TransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A concrete, parameterised transport instance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Transport {
    Direct,
    DirectBypass {
        /// Strategy currently bound to this path, if the learner has picked one.
        strategy: Option<crate::StrategyId>,
    },
    Warp,
    Opera {
        /// Region code as understood by opera-proxy, e.g. `EU`, `AM`, `AS`.
        region: String,
    },
}

impl Transport {
    pub fn kind(&self) -> TransportKind {
        match self {
            Transport::Direct => TransportKind::Direct,
            Transport::DirectBypass { .. } => TransportKind::DirectBypass,
            Transport::Warp => TransportKind::Warp,
            Transport::Opera { .. } => TransportKind::Opera,
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Transport::Opera { region } => write!(f, "opera:{region}"),
            Transport::DirectBypass { strategy: Some(s) } => write!(f, "direct+winws:{s}"),
            other => f.write_str(other.kind().as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_order_never_includes_plain_direct() {
        assert!(!TransportKind::FALLBACK_ORDER.contains(&TransportKind::Direct));
    }

    #[test]
    fn tunnelled_classification() {
        assert!(TransportKind::Warp.is_tunnelled());
        assert!(TransportKind::Opera.is_tunnelled());
        assert!(!TransportKind::DirectBypass.is_tunnelled());
        assert!(TransportKind::DirectBypass.needs_dpi_bypass());
    }
}
