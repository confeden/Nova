//! Network context: the "which network am I on" key that everything else is
//! learned per.
//!
//! What defeats a DPI box is a property of the *operator*, not of the site. A
//! strategy that works on a home ISP is often useless on a mobile carrier and
//! irrelevant on a corporate LAN. Keying learned state on the network means
//! moving a laptop between them restores the right answers instantly instead of
//! relearning, which is the single largest source of avoided probing.

/// Raw observations that identify the network Nova is attached to.
///
/// Every field is optional because each is separately unavailable: no ASN
/// without a successful lookup, no SSID on Ethernet, no gateway MAC on some
/// VPN adapters. The fingerprint degrades rather than failing.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetworkFingerprint {
    /// Autonomous system of the public egress address. The strongest signal:
    /// it is exactly "which operator's DPI am I behind".
    pub asn: Option<u32>,
    /// Default gateway's MAC. Distinguishes two networks sharing an ASN, and is
    /// free to obtain from the local ARP table.
    pub gateway_mac: Option<String>,
    /// Wi-Fi SSID when on wireless.
    pub ssid: Option<String>,
    /// Windows Network List Manager network name, which the user recognises and
    /// which winws itself can filter on via `--nlm-filter`.
    pub nlm_name: Option<String>,
}

impl NetworkFingerprint {
    /// Collapse the observations into a stable context key.
    ///
    /// ASN alone would merge every subscriber network of one ISP, which is
    /// correct — they share a DPI deployment. The gateway MAC is folded in only
    /// when the ASN is unknown, so that a working ASN-keyed context is not
    /// fragmented every time the user's router is replaced.
    pub fn context(&self) -> NetworkContext {
        if let Some(asn) = self.asn {
            return NetworkContext(format!("as{asn}"));
        }
        if let Some(mac) = &self.gateway_mac {
            return NetworkContext(format!("gw{}", mac.to_ascii_lowercase().replace([':', '-'], "")));
        }
        if let Some(ssid) = &self.ssid {
            return NetworkContext(format!("wifi:{}", ssid.to_ascii_lowercase()));
        }
        if let Some(name) = &self.nlm_name {
            return NetworkContext(format!("nlm:{}", name.to_ascii_lowercase()));
        }
        NetworkContext::unknown()
    }

    /// Rough similarity in [0, 1], used to pick which known context to inherit
    /// priors from when a new one appears.
    ///
    /// Same ASN is near-certain transferability. Same gateway with a different
    /// ASN means the operator changed upstream — some transfer value. Nothing
    /// in common means no reason to prefer this source over any other.
    pub fn similarity(&self, other: &NetworkFingerprint) -> f32 {
        if self.asn.is_some() && self.asn == other.asn {
            return 1.0;
        }
        let mut score = 0.0f32;
        if self.gateway_mac.is_some() && self.gateway_mac == other.gateway_mac {
            score += 0.6;
        }
        if self.ssid.is_some() && self.ssid == other.ssid {
            score += 0.3;
        }
        if self.nlm_name.is_some() && self.nlm_name == other.nlm_name {
            score += 0.1;
        }
        score.min(1.0)
    }
}

/// Stable key for one network's learned state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct NetworkContext(String);

impl NetworkContext {
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// Fallback context used when nothing could be observed.
    ///
    /// Deliberately a real context rather than an `Option`: state learned here
    /// is still better than nothing, and it becomes the natural transfer source
    /// the first time a real fingerprint does appear.
    pub fn unknown() -> Self {
        Self("unknown".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NetworkContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(asn: Option<u32>, mac: Option<&str>, ssid: Option<&str>) -> NetworkFingerprint {
        NetworkFingerprint {
            asn,
            gateway_mac: mac.map(str::to_owned),
            ssid: ssid.map(str::to_owned),
            nlm_name: None,
        }
    }

    #[test]
    fn asn_dominates_the_context_key() {
        let a = fp(Some(12389), Some("aa:bb:cc:dd:ee:ff"), Some("home"));
        let b = fp(Some(12389), Some("11:22:33:44:55:66"), Some("cafe"));
        assert_eq!(a.context(), b.context(), "same ISP must share learned state");
        assert_eq!(a.context().as_str(), "as12389");
    }

    #[test]
    fn falls_back_through_the_signal_chain() {
        assert_eq!(fp(None, Some("AA-BB-CC-DD-EE-FF"), None).context().as_str(), "gwaabbccddeeff");
        assert_eq!(fp(None, None, Some("Home WiFi")).context().as_str(), "wifi:home wifi");
        assert_eq!(NetworkFingerprint::default().context(), NetworkContext::unknown());
    }

    #[test]
    fn similarity_ranks_transfer_sources() {
        let home = fp(Some(12389), Some("aa:bb:cc:dd:ee:ff"), Some("home"));
        let same_isp = fp(Some(12389), None, None);
        let same_router_new_isp = fp(Some(31133), Some("aa:bb:cc:dd:ee:ff"), Some("home"));
        let unrelated = fp(Some(65001), Some("00:00:00:00:00:01"), Some("cafe"));

        assert_eq!(home.similarity(&same_isp), 1.0);
        assert!(home.similarity(&same_router_new_isp) > home.similarity(&unrelated));
        assert_eq!(home.similarity(&unrelated), 0.0);
    }
}
