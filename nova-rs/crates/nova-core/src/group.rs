use std::fmt;

/// Stable identifier of a routing/learning bucket.
///
/// Groups are data-driven, not an enum: they come from the shipped list files
/// (`list/youtube.txt`, `list/telegram.txt`, …) plus the synthetic groups the
/// runtime creates for auto-detected sites. Hard-coding them as a Rust enum was
/// how the Python version ended up with category checks scattered over a dozen
/// call sites.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct GroupId(String);

impl GroupId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into().to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Bucket for hosts that were classified at runtime rather than listed.
    ///
    /// Kept separate from the shipped groups so a bad auto-detection can be
    /// cleared wholesale without touching curated state.
    pub fn auto_cloudflare() -> Self {
        Self::new("auto:cloudflare")
    }

    pub fn is_auto(&self) -> bool {
        self.0.starts_with("auto:")
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for GroupId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// A routing/learning bucket together with everything the engine needs to act
/// on it. Populated from configuration; see `nova-config`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Group {
    pub id: GroupId,
    /// Human-readable label for the UI.
    pub label: String,
    /// Canary hostnames probed to decide whether this group is healthy.
    ///
    /// More than one, because a single canary conflates "the transport died"
    /// with "that one site is down" — the mistake the Python watchdog made.
    pub canaries: Vec<crate::Domain>,
    /// Strategy pool this group draws from, e.g. `youtube` -> `strat/youtube.json`.
    pub strategy_pool: String,
    /// Whether the learner is allowed to explore on this group.
    ///
    /// Voice-carrying groups (Discord, WhatsApp) default to `false`: a failed
    /// exploration there drops a call, which costs the user far more than the
    /// marginal information is worth.
    pub allow_exploration: bool,
}

impl Group {
    pub fn new(id: impl Into<GroupId>, label: impl Into<String>, strategy_pool: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            canaries: Vec::new(),
            strategy_pool: strategy_pool.into(),
            allow_exploration: true,
        }
    }

    pub fn with_canaries(mut self, canaries: impl IntoIterator<Item = crate::Domain>) -> Self {
        self.canaries = canaries.into_iter().collect();
        self
    }

    pub fn without_exploration(mut self) -> Self {
        self.allow_exploration = false;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_ids_are_case_insensitive() {
        assert_eq!(GroupId::new("YouTube"), GroupId::new("youtube"));
    }

    #[test]
    fn auto_groups_are_distinguishable() {
        assert!(GroupId::auto_cloudflare().is_auto());
        assert!(!GroupId::new("youtube").is_auto());
    }
}
