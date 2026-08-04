//! Rendering the IR into a concrete backend's command line, and reading the
//! existing v1 corpus back into the IR.

use nova_core::StrategyId;

use crate::ir::{
    DesyncMode, FakeKind, Filter, Fooling, L3, L7, ModTarget, Payload, SplitPosition, Strategy, StrategyError,
    TtlPolicy,
};

/// A backend that can turn strategies into a process command line.
pub trait Emitter {
    /// Name used in logs and errors.
    fn name(&self) -> &'static str;

    /// Render one strategy as the arguments of a single profile section.
    fn emit_profile(&self, strategy: &Strategy) -> Result<Vec<String>, StrategyError>;

    /// Render a full argv for a sequence of profiles, including whatever
    /// separator the backend uses between them.
    fn emit_all(&self, strategies: &[Strategy]) -> Result<Vec<String>, StrategyError> {
        let mut argv = Vec::new();
        for (index, strategy) in strategies.iter().enumerate() {
            if index > 0 {
                argv.push("--new".to_owned());
            }
            argv.extend(self.emit_profile(strategy)?);
        }
        Ok(argv)
    }
}

/// Emitter for zapret v1 (`winws.exe`), validated against the bundled v72.12.
#[derive(Debug, Clone, Copy, Default)]
pub struct V1Emitter;

impl V1Emitter {
    /// Parse one profile section of a v1 command line into the IR.
    ///
    /// `args` must be a single `--new`-delimited section, not a whole argv.
    /// Unrecognised options are preserved in [`Strategy::passthrough`] rather
    /// than dropped, so re-emitting is lossless even for options the IR has no
    /// opinion about.
    pub fn parse_profile(id: StrategyId, args: &[String]) -> Result<Strategy, StrategyError> {
        let mut s = Strategy { id: id.clone(), ..Strategy::default() };
        // The increment flags may appear either side of --dpi-desync-fooling,
        // so they are collected here and folded into the fooling entries after
        // the whole section has been read.
        let (mut seq_delta, mut ack_delta, mut ts_delta) = (None, None, None);
        for arg in args {
            let (flag, value) = match arg.split_once('=') {
                Some((f, v)) => (f, Some(v)),
                None => (arg.as_str(), None),
            };
            let value_or_empty = value.unwrap_or_default();
            match flag {
                "--new" | "--skip" => continue,
                "--filter-tcp" => push_csv(&mut s.filter.tcp_ports, value_or_empty),
                "--filter-udp" => push_csv(&mut s.filter.udp_ports, value_or_empty),
                "--filter-l3" => {
                    for token in value_or_empty.split(',') {
                        match token {
                            "ipv4" => s.filter.l3.push(L3::Ipv4),
                            "ipv6" => s.filter.l3.push(L3::Ipv6),
                            _ => {}
                        }
                    }
                }
                "--filter-l7" => {
                    for token in value_or_empty.split(',') {
                        if let Some(l7) = parse_l7(token) {
                            s.filter.l7.push(l7);
                        }
                    }
                }
                "--hostlist" => s.filter.hostlists.push(value_or_empty.to_owned()),
                "--hostlist-exclude" => s.filter.hostlist_excludes.push(value_or_empty.to_owned()),
                "--ipset" => s.filter.ipsets.push(value_or_empty.to_owned()),
                "--ipset-exclude" => s.filter.ipset_excludes.push(value_or_empty.to_owned()),
                "--dpi-desync" => {
                    for token in value_or_empty.split(',') {
                        let mode = DesyncMode::parse_v1(token)
                            .ok_or_else(|| StrategyError::UnknownMode { id: id.clone(), mode: token.to_owned() })?;
                        s.modes.push(mode);
                    }
                }
                "--dpi-desync-fooling" => {
                    for token in value_or_empty.split(',') {
                        if let Some(f) = Fooling::parse_v1(token) {
                            s.fooling.push(f);
                        }
                    }
                }
                "--dpi-desync-badseq-increment" => seq_delta = parse_signed(value_or_empty),
                "--dpi-desync-badack-increment" => ack_delta = parse_signed(value_or_empty),
                "--dpi-desync-ts-increment" => ts_delta = parse_signed(value_or_empty),
                "--dpi-desync-ttl" => s.ttl.fixed = value_or_empty.parse().ok(),
                "--dpi-desync-ttl6" => s.ttl.fixed6 = value_or_empty.parse().ok(),
                "--dpi-desync-autottl" => s.ttl.auto = Some(parse_autottl(value_or_empty)),
                "--dpi-desync-autottl6" => s.ttl.auto6 = Some(parse_autottl(value_or_empty)),
                "--dpi-desync-repeats" => s.repeats = value_or_empty.parse().ok(),
                "--dpi-desync-split-pos" => {
                    for token in value_or_empty.split(',') {
                        if let Some(p) = SplitPosition::parse(token) {
                            s.split_positions.push(p);
                        }
                    }
                }
                "--dpi-desync-split-seqovl" => s.seqovl = SplitPosition::parse(value_or_empty),
                other => {
                    if let Some(kind) = FakeKind::from_v1_flag(other) {
                        s.fakes.push((kind, Payload::parse(value_or_empty)));
                    } else if let Some(target) = ModTarget::from_v1_flag(other) {
                        s.mods.push((target, value_or_empty.to_owned()));
                    } else {
                        s.passthrough.push(arg.clone());
                    }
                }
            }
        }

        // An increment given without the corresponding fooling mode is inert in
        // v1, so it is folded in only where the mode is actually present.
        for fooling in &mut s.fooling {
            match fooling {
                Fooling::BadSeq { seq_delta: seq, ack_delta: ack } => {
                    if let Some(v) = seq_delta {
                        *seq = v;
                    }
                    if let Some(v) = ack_delta {
                        *ack = v;
                    }
                }
                Fooling::Timestamp { delta } => {
                    if let Some(v) = ts_delta {
                        *delta = v;
                    }
                }
                _ => {}
            }
        }
        Ok(s)
    }

    /// Split a full v1 argv into `--new`-delimited profile sections.
    pub fn split_profiles(args: &[String]) -> Vec<Vec<String>> {
        let mut sections: Vec<Vec<String>> = vec![Vec::new()];
        for arg in args {
            if arg == "--new" {
                sections.push(Vec::new());
            } else {
                sections.last_mut().expect("always at least one section").push(arg.clone());
            }
        }
        sections.retain(|s| !s.is_empty());
        sections
    }
}

impl Emitter for V1Emitter {
    fn name(&self) -> &'static str {
        "zapret-v1"
    }

    fn emit_profile(&self, s: &Strategy) -> Result<Vec<String>, StrategyError> {
        if s.filter.is_empty() && s.filter.l7.is_empty() {
            return Err(StrategyError::NoFilters(s.id.clone()));
        }
        let mut argv = Vec::with_capacity(16);
        emit_filter(&mut argv, &s.filter);

        if !s.modes.is_empty() {
            let modes: Vec<&str> = s.modes.iter().map(|m| m.as_v1()).collect();
            argv.push(format!("--dpi-desync={}", modes.join(",")));
        }
        if !s.fooling.is_empty() {
            let names: Vec<&str> = s.fooling.iter().map(|f| f.as_v1()).collect();
            argv.push(format!("--dpi-desync-fooling={}", names.join(",")));
            for fooling in &s.fooling {
                if !fooling.non_default_offsets() {
                    continue;
                }
                match fooling {
                    Fooling::BadSeq { seq_delta, ack_delta } => {
                        argv.push(format!("--dpi-desync-badseq-increment={seq_delta}"));
                        argv.push(format!("--dpi-desync-badack-increment={ack_delta}"));
                    }
                    Fooling::Timestamp { delta } => {
                        argv.push(format!("--dpi-desync-ts-increment={delta}"));
                    }
                    _ => {}
                }
            }
        }
        emit_ttl(&mut argv, &s.ttl);
        if !s.split_positions.is_empty() {
            let rendered: Vec<String> = s.split_positions.iter().map(SplitPosition::render).collect();
            argv.push(format!("--dpi-desync-split-pos={}", rendered.join(",")));
        }
        if let Some(seqovl) = &s.seqovl {
            argv.push(format!("--dpi-desync-split-seqovl={}", seqovl.render()));
        }
        if let Some(repeats) = s.repeats {
            argv.push(format!("--dpi-desync-repeats={repeats}"));
        }
        for (target, value) in &s.mods {
            argv.push(format!("{}={value}", target.as_v1_flag()));
        }
        for (kind, payload) in &s.fakes {
            argv.push(format!("{}={}", kind.as_v1_flag(), payload.render()));
        }
        argv.extend(s.passthrough.iter().cloned());
        Ok(argv)
    }
}

fn emit_filter(argv: &mut Vec<String>, f: &Filter) {
    if !f.tcp_ports.is_empty() {
        argv.push(format!("--filter-tcp={}", f.tcp_ports.join(",")));
    }
    if !f.udp_ports.is_empty() {
        argv.push(format!("--filter-udp={}", f.udp_ports.join(",")));
    }
    if !f.l3.is_empty() {
        let names: Vec<&str> = f.l3.iter().map(|l| if *l == L3::Ipv4 { "ipv4" } else { "ipv6" }).collect();
        argv.push(format!("--filter-l3={}", names.join(",")));
    }
    if !f.l7.is_empty() {
        let names: Vec<&str> = f.l7.iter().map(|l| l.as_str()).collect();
        argv.push(format!("--filter-l7={}", names.join(",")));
    }
    for list in &f.hostlists {
        argv.push(format!("--hostlist={list}"));
    }
    for list in &f.hostlist_excludes {
        argv.push(format!("--hostlist-exclude={list}"));
    }
    for set in &f.ipsets {
        argv.push(format!("--ipset={set}"));
    }
    for set in &f.ipset_excludes {
        argv.push(format!("--ipset-exclude={set}"));
    }
}

fn emit_ttl(argv: &mut Vec<String>, ttl: &TtlPolicy) {
    if let Some(auto) = ttl.auto {
        // v1 spells this `delta:min-max`; zapret2 uses a comma. Keeping the
        // separator inside the emitter rather than in the stored value is the
        // whole point of the IR.
        argv.push(format!("--dpi-desync-autottl={}:{}-{}", auto.delta, auto.min, auto.max));
    }
    if let Some(fixed) = ttl.fixed {
        argv.push(format!("--dpi-desync-ttl={fixed}"));
    }
    if let Some(auto6) = ttl.auto6 {
        argv.push(format!("--dpi-desync-autottl6={}:{}-{}", auto6.delta, auto6.min, auto6.max));
    }
    if let Some(fixed6) = ttl.fixed6 {
        argv.push(format!("--dpi-desync-ttl6={fixed6}"));
    }
}

/// Parse a signed value that zapret accepts in either decimal or `0x` form.
fn parse_signed(value: &str) -> Option<i32> {
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok().map(|v| v as i32);
    }
    value.parse().ok()
}

fn push_csv(target: &mut Vec<String>, value: &str) {
    target.extend(value.split(',').filter(|t| !t.is_empty()).map(str::to_owned));
}

fn parse_l7(token: &str) -> Option<L7> {
    Some(match token {
        "http" => L7::Http,
        "tls" => L7::Tls,
        "quic" => L7::Quic,
        "wireguard" => L7::Wireguard,
        "dht" => L7::Dht,
        "discord" => L7::Discord,
        "stun" => L7::Stun,
        "unknown" => L7::Unknown,
        _ => return None,
    })
}

fn parse_autottl(value: &str) -> crate::ir::AutoTtl {
    let mut auto = crate::ir::AutoTtl::default();
    let (delta, range) = match value.split_once(':') {
        Some((d, r)) => (d, Some(r)),
        None => (value, None),
    };
    if let Ok(d) = delta.parse::<i8>() {
        auto.delta = d;
    }
    if let Some(range) = range
        && let Some((min, max)) = range.split_once('-')
    {
        if let Ok(v) = min.parse() {
            auto.min = v;
        }
        if let Ok(v) = max.parse() {
            auto.max = v;
        }
    }
    auto
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A real strategy taken verbatim from strat/general.json.
    fn real_strategy() -> Vec<String> {
        args(&[
            "--filter-tcp=80,443",
            "--dpi-desync=hostfakesplit",
            "--dpi-desync-fake-tls-mod=rndsni",
            "--dpi-desync-hostfakesplit-mod=host=ya.ru,altorder=1",
            "--dpi-desync-fooling=badsum",
            "--dpi-desync-split-seqovl=1",
            "--dpi-desync-fake-tls=fake/tls_clienthello_yandex_kz.bin",
            "--dpi-desync-autottl=1",
            "--dpi-desync-ttl=8",
        ])
    }

    #[test]
    fn parses_a_real_strategy_without_losing_anything_to_passthrough() {
        let s = V1Emitter::parse_profile(StrategyId::new("hard_7_M65A"), &real_strategy()).unwrap();
        assert_eq!(s.filter.tcp_ports, vec!["80", "443"]);
        assert_eq!(s.modes, vec![DesyncMode::HostFakeSplit]);
        assert_eq!(s.fooling, vec![Fooling::BadSum]);
        assert_eq!(s.ttl.fixed, Some(8));
        assert_eq!(s.ttl.auto.unwrap().delta, 1);
        assert_eq!(s.seqovl, Some(SplitPosition::Absolute(1)));
        assert_eq!(s.fakes.len(), 1);
        assert_eq!(s.mods.len(), 2);
        assert!(s.passthrough.is_empty(), "unmodelled options: {:?}", s.passthrough);
    }

    #[test]
    fn emitting_a_parsed_strategy_reproduces_an_equivalent_command_line() {
        // Byte equality is the wrong property: the emitter deliberately
        // canonicalises, spelling out autottl's default 3-20 range and the `@`
        // file sigil that Nova's corpus omits. The property that matters is
        // that the canonical form means the same thing, i.e. re-parsing it
        // yields an identical IR.
        let once = V1Emitter::parse_profile(StrategyId::new("t"), &real_strategy()).unwrap();
        let emitted = V1Emitter.emit_profile(&once).unwrap();
        let twice = V1Emitter::parse_profile(StrategyId::new("t"), &emitted).unwrap();
        assert_eq!(once, twice, "emit is not idempotent");
        assert_eq!(V1Emitter.emit_profile(&twice).unwrap(), emitted);
    }

    #[test]
    fn deprecated_aliases_are_rewritten_to_supported_spellings() {
        let s = V1Emitter::parse_profile(
            StrategyId::new("legacy"),
            &args(&["--filter-tcp=443", "--dpi-desync=split2", "--dpi-desync-ttl=4"]),
        )
        .unwrap();
        let emitted = V1Emitter.emit_profile(&s).unwrap();
        assert!(emitted.contains(&"--dpi-desync=multisplit".to_owned()));
        assert!(!emitted.iter().any(|a| a.contains("split2")), "deprecated spelling survived: {emitted:?}");
    }

    #[test]
    fn unknown_desync_modes_are_rejected_rather_than_silently_dropped() {
        let err =
            V1Emitter::parse_profile(StrategyId::new("bad"), &args(&["--filter-tcp=443", "--dpi-desync=teleport"]))
                .unwrap_err();
        assert!(matches!(err, StrategyError::UnknownMode { .. }), "got {err:?}");
    }

    #[test]
    fn unmodelled_options_survive_a_round_trip_verbatim() {
        let s = V1Emitter::parse_profile(
            StrategyId::new("exotic"),
            &args(&["--filter-tcp=443", "--dpi-desync=fake", "--wssize=1:6", "--hostcase"]),
        )
        .unwrap();
        assert_eq!(s.passthrough, vec!["--wssize=1:6", "--hostcase"]);
        let emitted = V1Emitter.emit_profile(&s).unwrap();
        assert!(emitted.contains(&"--wssize=1:6".to_owned()));
        assert!(emitted.contains(&"--hostcase".to_owned()));
    }

    #[test]
    fn a_strategy_that_matches_nothing_is_an_error() {
        let s = Strategy { id: StrategyId::new("empty"), ..Strategy::default() };
        assert!(matches!(V1Emitter.emit_profile(&s), Err(StrategyError::NoFilters(_))));
    }

    #[test]
    fn multi_profile_argv_is_rejoined_with_new() {
        let a = V1Emitter::parse_profile(StrategyId::new("a"), &args(&["--filter-tcp=443", "--dpi-desync=fake"]))
            .unwrap();
        let b = V1Emitter::parse_profile(StrategyId::new("b"), &args(&["--filter-udp=443", "--dpi-desync=fake"]))
            .unwrap();
        let argv = V1Emitter.emit_all(&[a, b]).unwrap();
        assert_eq!(argv.iter().filter(|x| *x == "--new").count(), 1);
        let sections = V1Emitter::split_profiles(&argv);
        assert_eq!(sections.len(), 2);
    }

    #[test]
    fn splitting_a_two_section_command_line_recovers_both() {
        let argv = args(&[
            "--filter-tcp=80,443",
            "--dpi-desync=hostfakesplit",
            "--new",
            "--filter-udp=443",
            "--dpi-desync=fake",
            "--dpi-desync-repeats=6",
        ]);
        let sections = V1Emitter::split_profiles(&argv);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[1].len(), 3);
        let udp = V1Emitter::parse_profile(StrategyId::new("udp"), &sections[1]).unwrap();
        assert_eq!(udp.repeats, Some(6));
        assert_eq!(udp.filter.udp_ports, vec!["443"]);
    }

    #[test]
    fn autottl_range_is_parsed_and_re_emitted() {
        let s = V1Emitter::parse_profile(
            StrategyId::new("t"),
            &args(&["--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-autottl=-2:4-16"]),
        )
        .unwrap();
        let auto = s.ttl.auto.unwrap();
        assert_eq!((auto.delta, auto.min, auto.max), (-2, 4, 16));
        let emitted = V1Emitter.emit_profile(&s).unwrap();
        assert!(emitted.contains(&"--dpi-desync-autottl=-2:4-16".to_owned()), "{emitted:?}");
    }
}
