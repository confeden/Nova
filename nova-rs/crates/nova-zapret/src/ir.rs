//! The intent-level strategy model.

use nova_core::StrategyId;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StrategyError {
    #[error("strategy {0} has no filters, so it would match nothing")]
    NoFilters(StrategyId),
    #[error("unknown desync mode {mode:?} in strategy {id}")]
    UnknownMode { id: StrategyId, mode: String },
    #[error("option {option:?} in strategy {id} is not representable in the IR")]
    Unrepresentable { id: StrategyId, option: String },
    #[error("backend {backend} cannot express {what}")]
    Unsupported { backend: &'static str, what: String },
}

/// L3 protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L3 {
    Ipv4,
    Ipv6,
}

/// L7 protocol selector.
///
/// zapret2 makes this effectively mandatory for performance — an unfiltered
/// profile hands every packet to its Lua engine and is slower than v1. Keeping
/// it in the IR means the v2 emitter can enforce that without the strategy
/// corpus needing to know why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L7 {
    Http,
    Tls,
    Quic,
    Wireguard,
    Dht,
    Discord,
    Stun,
    Unknown,
}

impl L7 {
    pub fn as_str(self) -> &'static str {
        match self {
            L7::Http => "http",
            L7::Tls => "tls",
            L7::Quic => "quic",
            L7::Wireguard => "wireguard",
            L7::Dht => "dht",
            L7::Discord => "discord",
            L7::Stun => "stun",
            L7::Unknown => "unknown",
        }
    }
}

/// Which flows a profile applies to.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Filter {
    /// TCP port specifications, verbatim (`80`, `443`, `1024-65535`, `~80`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp_ports: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp_ports: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub l3: Vec<L3>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub l7: Vec<L7>,
    /// Hostlist file paths, relative to the Nova root.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostlists: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostlist_excludes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipsets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipset_excludes: Vec<String>,
}

impl Filter {
    pub fn is_empty(&self) -> bool {
        self.tcp_ports.is_empty() && self.udp_ports.is_empty()
    }
}

/// How the DPI state machine is confused.
///
/// Named by intent rather than by v1's flag spelling, so the v2 emitter can map
/// each to its Lua counterpart without a lossy string translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesyncMode {
    /// Send a fabricated packet before the real one.
    Fake,
    /// Fake using a known-good protocol sample.
    FakeKnown,
    /// Split the payload at one or more positions, in order.
    MultiSplit,
    /// Split and send out of order.
    MultiDisorder,
    /// Split with a fake first segment.
    FakedSplit,
    /// Split out of order with a fake first segment.
    FakedDisorder,
    /// Split the TLS record so the hostname straddles the boundary, with a
    /// decoy host in the first segment.
    HostFakeSplit,
    /// Data in the SYN packet.
    SynData,
    /// Split the TCP handshake itself.
    SynAck,
    /// Forge an RST.
    Rst,
    /// Forge an RST/ACK.
    RstAck,
    /// IPv4 fragmentation at layer 3.
    IpFrag1,
    /// IPv4 fragmentation at layer 4.
    IpFrag2,
    /// IPv6 hop-by-hop extension header abuse.
    HopByHop,
    /// IPv6 destination-options extension header abuse.
    DestOpt,
    /// Pad UDP payloads.
    UdpLen,
    /// Generic header tampering.
    Tamper,
}

impl DesyncMode {
    /// Parse a zapret v1 mode token.
    ///
    /// `split`, `split2` and `disorder` are v1's undocumented backward-compatible
    /// aliases: they are absent from `--help` on v72.12 but still accepted, as
    /// verified with `--dry-run`. They are accepted here so the existing corpus
    /// loads, and normalised to the current names so nothing re-emits a spelling
    /// that zapret2 has no equivalent for.
    pub fn parse_v1(token: &str) -> Option<Self> {
        Some(match token {
            "fake" => Self::Fake,
            "fakeknown" => Self::FakeKnown,
            "multisplit" | "split" | "split2" => Self::MultiSplit,
            "multidisorder" | "disorder" => Self::MultiDisorder,
            "fakedsplit" => Self::FakedSplit,
            "fakeddisorder" => Self::FakedDisorder,
            "hostfakesplit" => Self::HostFakeSplit,
            "syndata" => Self::SynData,
            "synack" => Self::SynAck,
            "rst" => Self::Rst,
            "rstack" => Self::RstAck,
            "ipfrag1" => Self::IpFrag1,
            "ipfrag2" => Self::IpFrag2,
            "hopbyhop" => Self::HopByHop,
            "destopt" => Self::DestOpt,
            "udplen" => Self::UdpLen,
            "tamper" => Self::Tamper,
            _ => return None,
        })
    }

    /// Spelling understood by zapret v1 v72.x.
    pub fn as_v1(self) -> &'static str {
        match self {
            Self::Fake => "fake",
            Self::FakeKnown => "fakeknown",
            Self::MultiSplit => "multisplit",
            Self::MultiDisorder => "multidisorder",
            Self::FakedSplit => "fakedsplit",
            Self::FakedDisorder => "fakeddisorder",
            Self::HostFakeSplit => "hostfakesplit",
            Self::SynData => "syndata",
            Self::SynAck => "synack",
            Self::Rst => "rst",
            Self::RstAck => "rstack",
            Self::IpFrag1 => "ipfrag1",
            Self::IpFrag2 => "ipfrag2",
            Self::HopByHop => "hopbyhop",
            Self::DestOpt => "destopt",
            Self::UdpLen => "udplen",
            Self::Tamper => "tamper",
        }
    }
}

/// A way of making a fake packet invisible to the destination but visible to
/// the DPI.
///
/// v1 expresses these as a comma list under one flag; zapret2 decomposes them
/// into separate arguments and drops `badseq` as a named concept in favour of
/// explicit sequence offsets. Modelling the offsets here rather than the flag
/// name is what lets both be emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fooling {
    /// Deliberately wrong TCP checksum.
    BadSum,
    /// Bogus TCP MD5 signature option.
    Md5Sig,
    /// Sequence and ack numbers shifted out of window.
    BadSeq {
        seq_delta: i32,
        ack_delta: i32,
    },
    /// Timestamp option shifted backwards.
    Timestamp {
        delta: i32,
    },
    /// Data packet with no ACK flag.
    DataNoAck,
    /// IPv6 hop-by-hop header the DPI mis-parses.
    HopByHop,
    HopByHop2,
}

impl Fooling {
    /// v1 defaults, used when a strategy names a fooling mode without giving
    /// explicit offsets.
    pub const DEFAULT_SEQ_DELTA: i32 = -10_000;
    pub const DEFAULT_ACK_DELTA: i32 = -66_000;
    pub const DEFAULT_TS_DELTA: i32 = -600_000;

    pub fn parse_v1(token: &str) -> Option<Self> {
        Some(match token {
            "badsum" => Self::BadSum,
            "md5sig" => Self::Md5Sig,
            "badseq" => Self::BadSeq { seq_delta: Self::DEFAULT_SEQ_DELTA, ack_delta: Self::DEFAULT_ACK_DELTA },
            "ts" => Self::Timestamp { delta: Self::DEFAULT_TS_DELTA },
            "datanoack" => Self::DataNoAck,
            "hopbyhop" => Self::HopByHop,
            "hopbyhop2" => Self::HopByHop2,
            "none" => return None,
            _ => return None,
        })
    }

    pub fn as_v1(self) -> &'static str {
        match self {
            Self::BadSum => "badsum",
            Self::Md5Sig => "md5sig",
            Self::BadSeq { .. } => "badseq",
            Self::Timestamp { .. } => "ts",
            Self::DataNoAck => "datanoack",
            Self::HopByHop => "hopbyhop",
            Self::HopByHop2 => "hopbyhop2",
        }
    }

    /// Whether this variant carries non-default offsets that must be emitted
    /// as separate increment arguments.
    pub fn non_default_offsets(self) -> bool {
        match self {
            Self::BadSeq { seq_delta, ack_delta } => {
                seq_delta != Self::DEFAULT_SEQ_DELTA || ack_delta != Self::DEFAULT_ACK_DELTA
            }
            Self::Timestamp { delta } => delta != Self::DEFAULT_TS_DELTA,
            _ => false,
        }
    }
}

/// TTL applied to fake packets so they die before reaching the destination but
/// after passing the DPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct TtlPolicy {
    /// Fixed hop limit.
    pub fixed: Option<u8>,
    /// Auto mode: delta from the measured hop count, clamped to `[min, max]`.
    pub auto: Option<AutoTtl>,
    /// IPv6 override. zapret2 does *not* inherit the IPv4 value the way v1
    /// does, so the field is kept explicitly rather than left implicit.
    pub fixed6: Option<u8>,
    pub auto6: Option<AutoTtl>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AutoTtl {
    pub delta: i8,
    pub min: u8,
    pub max: u8,
}

impl Default for AutoTtl {
    fn default() -> Self {
        // v1's documented default for --dpi-desync-autottl.
        Self { delta: -1, min: 3, max: 20 }
    }
}

/// Where to cut a payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SplitPosition {
    /// Absolute byte offset; negative counts from the end.
    Absolute(i32),
    /// Offset relative to a protocol landmark, e.g. `sniext+1`.
    Marker { marker: String, offset: i32 },
}

impl SplitPosition {
    pub fn render(&self) -> String {
        match self {
            Self::Absolute(n) => n.to_string(),
            Self::Marker { marker, offset } => {
                if *offset >= 0 {
                    format!("{marker}+{offset}")
                } else {
                    format!("{marker}{offset}")
                }
            }
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        if let Ok(n) = token.parse::<i32>() {
            return Some(Self::Absolute(n));
        }
        let split = token.find(['+', '-'])?;
        // A leading sign belongs to an absolute offset, already handled above.
        if split == 0 {
            return None;
        }
        let (marker, offset) = token.split_at(split);
        Some(Self::Marker { marker: marker.to_owned(), offset: offset.parse().ok()? })
    }
}

/// A fake payload, referenced by file or given inline as hex.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    /// Path relative to the Nova root, e.g. `fake/tls_clienthello_yandex_kz.bin`.
    File { path: String, offset: Option<u32> },
    /// Literal bytes as `0x…`.
    Hex(String),
}

impl Payload {
    pub fn render(&self) -> String {
        match self {
            Self::File { path, offset: Some(o) } => format!("+{o}@{path}"),
            Self::File { path, offset: None } => format!("@{path}"),
            Self::Hex(hex) => hex.clone(),
        }
    }

    pub fn parse(token: &str) -> Self {
        if let Some(rest) = token.strip_prefix('+')
            && let Some((offset, path)) = rest.split_once('@')
            && let Ok(offset) = offset.parse::<u32>()
        {
            return Self::File { path: path.to_owned(), offset: Some(offset) };
        }
        if let Some(path) = token.strip_prefix('@') {
            return Self::File { path: path.to_owned(), offset: None };
        }
        if token.starts_with("0x") || token.starts_with("0X") {
            return Self::Hex(token.to_owned());
        }
        // Nova's corpus writes bare paths without the `@` sigil.
        Self::File { path: token.to_owned(), offset: None }
    }
}

/// One complete bypass profile.
///
/// A `Strategy` corresponds to one `--new` section in v1 argv. A full winws
/// invocation is a sequence of them.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Strategy {
    pub id: StrategyId,
    pub filter: Filter,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modes: Vec<DesyncMode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fooling: Vec<Fooling>,
    #[serde(default)]
    pub ttl: TtlPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub split_positions: Vec<SplitPosition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seqovl: Option<SplitPosition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeats: Option<u32>,
    /// Fake payloads keyed by the protocol they impersonate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fakes: Vec<(FakeKind, Payload)>,
    /// Modifiers such as `rndsni` or `host=ya.ru`, kept as opaque tokens
    /// because their vocabulary is backend-specific.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mods: Vec<(ModTarget, String)>,
    /// Options the parser recognised but the IR has no concept for, preserved
    /// verbatim so a v1 round trip is lossless.
    ///
    /// A strategy carrying these cannot be emitted for zapret2; the v2 emitter
    /// reports it rather than silently dropping behaviour, because a silently
    /// weakened strategy is worse than one that refuses to load.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passthrough: Vec<String>,
}

impl Strategy {
    /// True when this profile carries no traffic filter of its own.
    ///
    /// `strat/boost.json` and `strat/warp.json` are written this way on purpose:
    /// their entries are *fragments* appended to a base command line that
    /// already established `--filter-tcp`, so standing alone they would match
    /// nothing. [`crate::Emitter::emit_profile`] refuses them for exactly that
    /// reason, which is right in production and wrong for tooling that needs to
    /// reason about a fragment in isolation.
    pub fn is_fragment(&self) -> bool {
        self.filter.is_empty()
    }

    /// A copy that can stand on its own, for validation and generation.
    ///
    /// Without this, 30 of Nova's 101 strategies — every entry in the `boost`
    /// and `warp` pools — were invisible to the evolver, because every candidate
    /// bred from them failed to render before it could be tested.
    ///
    /// The supplied ports are scaffolding, never persisted: the caller uses the
    /// result to ask "would this technique start", then keeps the fragment.
    pub fn as_standalone(&self, tcp_ports: &[&str]) -> Strategy {
        if !self.is_fragment() {
            return self.clone();
        }
        let mut standalone = self.clone();
        standalone.filter.tcp_ports = tcp_ports.iter().map(|p| (*p).to_owned()).collect();
        standalone
    }
}

/// Which protocol a fake payload impersonates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FakeKind {
    Tls,
    Quic,
    Http,
    SynData,
    Wireguard,
    Dht,
    Discord,
    Stun,
    Unknown,
    UnknownUdp,
}

impl FakeKind {
    pub fn as_v1_flag(self) -> &'static str {
        match self {
            Self::Tls => "--dpi-desync-fake-tls",
            Self::Quic => "--dpi-desync-fake-quic",
            Self::Http => "--dpi-desync-fake-http",
            Self::SynData => "--dpi-desync-fake-syndata",
            Self::Wireguard => "--dpi-desync-fake-wireguard",
            Self::Dht => "--dpi-desync-fake-dht",
            Self::Discord => "--dpi-desync-fake-discord",
            Self::Stun => "--dpi-desync-fake-stun",
            Self::Unknown => "--dpi-desync-fake-unknown",
            Self::UnknownUdp => "--dpi-desync-fake-unknown-udp",
        }
    }

    pub fn from_v1_flag(flag: &str) -> Option<Self> {
        Some(match flag {
            "--dpi-desync-fake-tls" => Self::Tls,
            "--dpi-desync-fake-quic" => Self::Quic,
            "--dpi-desync-fake-http" => Self::Http,
            "--dpi-desync-fake-syndata" => Self::SynData,
            "--dpi-desync-fake-wireguard" => Self::Wireguard,
            "--dpi-desync-fake-dht" => Self::Dht,
            "--dpi-desync-fake-discord" => Self::Discord,
            "--dpi-desync-fake-stun" => Self::Stun,
            "--dpi-desync-fake-unknown" => Self::Unknown,
            "--dpi-desync-fake-unknown-udp" => Self::UnknownUdp,
            _ => return None,
        })
    }
}

/// What a modifier list applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModTarget {
    TlsFake,
    TcpFake,
    HostFakeSplit,
    FakedSplit,
}

impl ModTarget {
    pub fn as_v1_flag(self) -> &'static str {
        match self {
            Self::TlsFake => "--dpi-desync-fake-tls-mod",
            Self::TcpFake => "--dpi-desync-fake-tcp-mod",
            Self::HostFakeSplit => "--dpi-desync-hostfakesplit-mod",
            Self::FakedSplit => "--dpi-desync-fakedsplit-mod",
        }
    }

    pub fn from_v1_flag(flag: &str) -> Option<Self> {
        Some(match flag {
            "--dpi-desync-fake-tls-mod" => Self::TlsFake,
            "--dpi-desync-fake-tcp-mod" => Self::TcpFake,
            "--dpi-desync-hostfakesplit-mod" => Self::HostFakeSplit,
            "--dpi-desync-fakedsplit-mod" => Self::FakedSplit,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_aliases_normalise_to_current_names() {
        // Verified against the bundled winws v72.12 with --dry-run: these
        // aliases are accepted but absent from --help.
        assert_eq!(DesyncMode::parse_v1("split2"), Some(DesyncMode::MultiSplit));
        assert_eq!(DesyncMode::parse_v1("split"), Some(DesyncMode::MultiSplit));
        assert_eq!(DesyncMode::parse_v1("disorder"), Some(DesyncMode::MultiDisorder));
        assert_eq!(DesyncMode::MultiSplit.as_v1(), "multisplit", "must not re-emit the deprecated spelling");
        assert_eq!(DesyncMode::parse_v1("nonsense"), None);
    }

    #[test]
    fn fooling_carries_offsets_not_just_a_name() {
        let badseq = Fooling::parse_v1("badseq").unwrap();
        assert_eq!(
            badseq,
            Fooling::BadSeq { seq_delta: Fooling::DEFAULT_SEQ_DELTA, ack_delta: Fooling::DEFAULT_ACK_DELTA }
        );
        assert!(!badseq.non_default_offsets());
        assert!(Fooling::BadSeq { seq_delta: -1, ack_delta: -2 }.non_default_offsets());
        assert_eq!(Fooling::parse_v1("none"), None);
    }

    #[test]
    fn split_positions_round_trip() {
        for token in ["1", "-5", "sniext+1", "midsld-2", "host+0"] {
            let parsed = SplitPosition::parse(token).unwrap_or_else(|| panic!("failed to parse {token}"));
            assert_eq!(parsed.render(), token, "round trip failed for {token}");
        }
    }

    #[test]
    fn payload_references_round_trip() {
        assert_eq!(
            Payload::parse("fake/tls_1.bin"),
            Payload::File { path: "fake/tls_1.bin".to_owned(), offset: None }
        );
        assert_eq!(Payload::parse("@fake/tls_1.bin").render(), "@fake/tls_1.bin");
        assert_eq!(Payload::parse("+3@fake/tls_1.bin").render(), "+3@fake/tls_1.bin");
        assert_eq!(Payload::parse("0xDEADBEEF").render(), "0xDEADBEEF");
    }

    #[test]
    fn fake_and_mod_flags_map_both_ways() {
        for kind in [FakeKind::Tls, FakeKind::Quic, FakeKind::SynData, FakeKind::UnknownUdp] {
            assert_eq!(FakeKind::from_v1_flag(kind.as_v1_flag()), Some(kind));
        }
        for target in [ModTarget::TlsFake, ModTarget::HostFakeSplit, ModTarget::FakedSplit, ModTarget::TcpFake] {
            assert_eq!(ModTarget::from_v1_flag(target.as_v1_flag()), Some(target));
        }
        assert_eq!(FakeKind::from_v1_flag("--not-a-flag"), None);
    }
}
