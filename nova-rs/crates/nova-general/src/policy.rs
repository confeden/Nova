use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_CANDIDATES: usize = 12;
pub const STARTUP_DELAY: u64 = 60;
pub const MIN_GAP: u64 = 20;
pub const MAX_REQUESTS_PER_WINDOW: u32 = 32;
pub const WINDOW_SECS: u64 = 30 * 60;
pub const DAILY_REQUESTS: u32 = 192;
pub const BODY_BUDGET: u64 = 2 * 1024 * 1024;
pub const FRESH_SECS: u64 = 24 * 3600;
pub const CONTROLS: [&str; 3] = ["www.cloudflare.com", "www.apple.com", "www.microsoft.com"];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Rkn,
    Youtube,
    Control,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub candidate: String,
    pub domain: String,
    pub kind: Kind,
    pub baseline: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub candidate: String,
    pub domain: String,
    pub kind: Kind,
    pub baseline: bool,
    pub at: u64,
    pub physical: bool,
    pub opened: bool,
    pub http: u16,
    pub body_bytes: u64,
}
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub schema: u32,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub cursor: usize,
    #[serde(default)]
    pub observations: Vec<Observation>,
    #[serde(default)]
    pub recommended: Option<String>,
    #[serde(default)]
    pub requests: u32,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub last_probe: u64,
    #[serde(default)]
    pub dns: BTreeMap<String, (String, u64)>,
    #[serde(default)]
    pub last_transport_error: Option<String>,
    #[serde(default)]
    pub window_at: u64,
    #[serde(default)]
    pub day_at: u64,
    #[serde(default)]
    pub day_requests: u32,
}

pub fn domains(text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let d = line
            .split('#')
            .next()
            .unwrap_or("")
            .trim()
            .trim_start_matches('\u{feff}')
            .trim_start_matches('^')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if d.len() > 253
            || !d.contains('.')
            || !d.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || d.parse::<std::net::IpAddr>().is_ok()
        {
            continue;
        }
        if seen.insert(d.clone()) {
            out.push(d);
        }
    }
    out
}
fn latest<'a>(s: &'a State, candidate: &str, domain: &str, baseline: bool, now: u64) -> Option<&'a Observation> {
    s.observations.iter().rev().find(|o| {
        o.candidate == candidate
            && o.domain == domain
            && o.baseline == baseline
            && o.at <= now
            && now.saturating_sub(o.at) < FRESH_SECS
            && o.physical
    })
}
pub fn plan(candidates: &[String], rkn: &[String], s: &State, now: u64) -> Vec<Job> {
    let mut jobs = Vec::new();
    let mut selected: Vec<_> =
        rkn.iter().filter(|d| !matches!(d.as_str(), "youtube.com" | "www.youtube.com")).cloned().collect();
    if !selected.is_empty() {
        let len = selected.len();
        selected.rotate_left(s.cursor % len);
        selected.truncate(3);
    }
    let push = |jobs: &mut Vec<Job>, candidate: &str, domain: &str, kind: Kind, baseline: bool| {
        if latest(s, candidate, domain, baseline, now).is_none() {
            jobs.push(Job { candidate: candidate.into(), domain: domain.into(), kind, baseline });
        }
    };
    for d in &selected {
        push(&mut jobs, "baseline", d, Kind::Rkn, true);
    }
    for d in ["youtube.com", "www.youtube.com"] {
        push(&mut jobs, "baseline", d, Kind::Youtube, true);
    }
    for d in CONTROLS {
        push(&mut jobs, "baseline", d, Kind::Control, true);
    }
    // Every selected profile sees YouTube even when it is absent from rkn.txt.
    for candidate in candidates.iter().take(MAX_CANDIDATES) {
        for d in ["youtube.com", "www.youtube.com"] {
            push(&mut jobs, candidate, d, Kind::Youtube, false);
        }
        for d in &selected {
            push(&mut jobs, candidate, d, Kind::Rkn, false);
        }
        for d in CONTROLS {
            push(&mut jobs, candidate, d, Kind::Control, false);
        }
    }
    jobs
}
pub fn blocked_once(s: &State, domain: &str, now: u64) -> bool {
    latest(s, "baseline", domain, true, now).is_some_and(|o| !o.opened && o.http == 0)
}
pub fn eligible_rkn(s: &State, domain: &str, now: u64) -> bool {
    if s.observations.iter().any(|o| {
        o.baseline && o.domain == domain && o.physical && o.opened && o.at <= now && now - o.at < FRESH_SECS
    }) {
        return false;
    }
    blocked_once(s, domain, now)
        && s.observations
            .iter()
            .filter(|o| {
                o.baseline
                    && o.domain == domain
                    && o.physical
                    && !o.opened
                    && o.http == 0
                    && o.at <= now
                    && now.saturating_sub(o.at) < FRESH_SECS
            })
            .map(|o| o.at)
            .collect::<BTreeSet<_>>()
            .len()
            >= 2
}
pub fn baseline_failures(s: &State, domain: &str, now: u64) -> usize {
    s.observations
        .iter()
        .filter(|o| {
            o.baseline
                && o.domain == domain
                && o.physical
                && !o.opened
                && o.http == 0
                && o.at <= now
                && now - o.at < FRESH_SECS
        })
        .map(|o| o.at)
        .collect::<BTreeSet<_>>()
        .len()
}
pub fn roll_budget(s: &mut State, now: u64) {
    if s.day_at == 0 || now.saturating_sub(s.day_at) >= 86400 {
        s.day_at = now;
        s.day_requests = 0;
    }
    if s.window_at == 0 || now.saturating_sub(s.window_at) >= WINDOW_SECS {
        s.window_at = now;
        s.requests = 0;
        s.bytes = 0;
    }
}
pub fn next_window(s: &State, now: u64) -> u64 {
    if s.day_requests >= DAILY_REQUESTS {
        s.day_at.saturating_add(86400).saturating_sub(now)
    } else {
        s.window_at.saturating_add(WINDOW_SECS).saturating_sub(now)
    }
}
pub fn recommendation(s: &State, now: u64) -> Option<String> {
    let mut scores = BTreeMap::<String, (usize, bool)>::new();
    for o in &s.observations {
        if o.baseline || !o.physical || o.at > now || now.saturating_sub(o.at) >= FRESH_SECS {
            continue;
        }
        scores.entry(o.candidate.clone()).or_default();
    }
    for (candidate, (count, allowed)) in &mut scores {
        *allowed = ["youtube.com", "www.youtube.com"]
            .iter()
            .all(|d| latest(s, candidate, d, false, now).is_some_and(|o| o.opened))
            && CONTROLS.iter().all(|d| match latest(s, "baseline", d, true, now) {
                Some(b) if b.opened => latest(s, candidate, d, false, now).is_some_and(|o| o.opened),
                _ => false,
            });
        let mut unique = BTreeSet::new();
        for o in &s.observations {
            if o.candidate == *candidate
                && o.kind == Kind::Rkn
                && o.opened
                && o.physical
                && o.at <= now
                && now.saturating_sub(o.at) < FRESH_SECS
                && latest(s, candidate, &o.domain, false, now).is_some_and(|last| last.opened)
                && eligible_rkn(s, &o.domain, now)
            {
                unique.insert(&o.domain);
            }
        }
        *count = unique.len();
    }
    scores
        .into_iter()
        .filter(|(_, (count, allowed))| *count >= 3 && *allowed)
        .max_by(|a, b| a.1.0.cmp(&b.1.0).then_with(|| b.0.cmp(&a.0)))
        .map(|(name, _)| name)
}
pub fn should_probe(s: &State, now: u64, uptime: u64, busy: bool) -> bool {
    uptime >= STARTUP_DELAY
        && !busy
        && s.requests < MAX_REQUESTS_PER_WINDOW
        && s.day_requests < DAILY_REQUESTS
        && s.bytes < BODY_BUDGET
        && now.saturating_sub(s.last_probe) >= MIN_GAP
}
pub fn retain(s: &mut State, now: u64) {
    s.observations.retain(|o| o.at <= now && now.saturating_sub(o.at) < FRESH_SECS);
    if s.observations.len() > 4096 {
        let n = s.observations.len() - 4096;
        s.observations.drain(..n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn add(s: &mut State, c: &str, d: &str, k: Kind, base: bool, open: bool, physical: bool) {
        s.observations.push(Observation {
            candidate: c.into(),
            domain: d.into(),
            kind: k,
            baseline: base,
            at: 100,
            physical,
            opened: open,
            http: if open { 200 } else { 0 },
            body_bytes: 100,
        });
    }
    #[test]
    fn rkn_is_primary_and_youtube_is_mandatory() {
        let r = domains("#comment\nblocked.org\nblocked.org\n127.0.0.1\n");
        assert_eq!(r, ["blocked.org"]);
        let jobs = plan(&["a".into()], &r, &State::default(), 100);
        assert!(jobs.iter().any(|j| j.domain == "youtube.com" && !j.baseline));
        assert!(jobs.iter().any(|j| j.domain == "www.youtube.com" && !j.baseline));
    }
    #[test]
    fn vpn_success_and_direct_access_are_not_dpi_evidence() {
        let mut s = State::default();
        for d in ["one.org", "two.org", "three.org"] {
            add(&mut s, "baseline", d, Kind::Rkn, true, false, true);
            s.observations.last_mut().unwrap().at = 99;
            add(&mut s, "baseline", d, Kind::Rkn, true, false, true);
            add(&mut s, "a", d, Kind::Rkn, false, true, false);
        }
        for d in ["youtube.com", "www.youtube.com"] {
            add(&mut s, "a", d, Kind::Youtube, false, true, true);
        }
        for d in CONTROLS {
            add(&mut s, "baseline", d, Kind::Control, true, true, true);
            add(&mut s, "a", d, Kind::Control, false, true, true);
        }
        assert_eq!(recommendation(&s, 100), None);
        for o in &mut s.observations {
            o.physical = true;
        }
        assert_eq!(recommendation(&s, 100), Some("a".into()));
        add(&mut s, "a", "one.org", Kind::Rkn, false, false, true);
        assert_eq!(recommendation(&s, 100), None);
        s.observations.pop();
        for o in &mut s.observations {
            if o.baseline && o.kind == Kind::Rkn {
                o.opened = true;
                o.http = 200;
            }
        }
        assert_eq!(recommendation(&s, 100), None);
    }
    #[test]
    fn startup_and_budget_never_burst() {
        let mut s = State::default();
        assert!(!should_probe(&s, 100, 10, false));
        assert!(should_probe(&s, 100, 60, false));
        s.requests = 32;
        assert!(!should_probe(&s, 100, 60, false));
        s.requests = 0;
        s.last_probe = 95;
        assert!(!should_probe(&s, 100, 60, false));
        assert!(!should_probe(&State::default(), 100, 60, true));
    }
    #[test]
    fn restart_does_not_reset_network_budget() {
        let mut s = State { window_at: 100, day_at: 100, requests: 32, day_requests: 32, ..State::default() };
        roll_budget(&mut s, 200);
        assert_eq!(s.requests, 32);
        roll_budget(&mut s, 1900);
        assert_eq!(s.requests, 0);
        assert_eq!(s.day_requests, 32);
        s.day_requests = 192;
        assert!(!should_probe(&s, 2000, 100, false));
    }
    #[test]
    fn missing_youtube_or_control_blocks_promotion() {
        let mut s = State::default();
        for d in ["one.org", "two.org", "three.org"] {
            add(&mut s, "baseline", d, Kind::Rkn, true, false, true);
            add(&mut s, "a", d, Kind::Rkn, false, true, true);
        }
        assert_eq!(recommendation(&s, 100), None);
    }
}
