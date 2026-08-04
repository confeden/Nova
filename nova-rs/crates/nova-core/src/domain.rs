use std::fmt;

/// A normalised DNS name used as a routing and learning key.
///
/// Normalisation is lowercase ASCII with the trailing root dot and any leading
/// `*.` wildcard stripped. Nova's list files mix all three spellings, so the
/// invariant is enforced at construction rather than at every comparison site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Domain(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainParseError {
    #[error("domain is empty")]
    Empty,
    #[error("domain is longer than 253 bytes")]
    TooLong,
    #[error("label {label:?} is empty or longer than 63 bytes")]
    BadLabel { label: String },
    #[error("character {ch:?} is not allowed in a domain name")]
    IllegalCharacter { ch: char },
}

impl Domain {
    pub fn parse(input: &str) -> Result<Self, DomainParseError> {
        let trimmed = input.trim().trim_end_matches('.');
        let trimmed = trimmed.strip_prefix("*.").unwrap_or(trimmed);
        if trimmed.is_empty() {
            return Err(DomainParseError::Empty);
        }
        if trimmed.len() > 253 {
            return Err(DomainParseError::TooLong);
        }
        for ch in trimmed.chars() {
            let ok = ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' || ch == '_';
            if !ok {
                return Err(DomainParseError::IllegalCharacter { ch });
            }
        }
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(DomainParseError::BadLabel { label: label.to_owned() });
            }
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Registrable-ish parent used to share learned state between siblings.
    ///
    /// This is a deliberate approximation of the Public Suffix List: it keeps
    /// three labels for the handful of two-level public suffixes Nova actually
    /// meets in Russian and UK domain lists, and two labels otherwise. Getting
    /// this wrong only widens or narrows a learning bucket, never breaks
    /// routing, so a 40-line heuristic beats shipping a 200 KB PSL snapshot
    /// that would need its own update channel.
    pub fn learning_key(&self) -> &str {
        const TWO_LEVEL_SUFFIXES: &[&str] = &[
            "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "com.br", "com.tr", "com.ua", "co.jp", "com.cn",
            "com.mx", "co.in", "co.kr", "co.za", "com.sg", "com.hk",
        ];
        let labels: Vec<&str> = self.0.split('.').collect();
        if labels.len() <= 2 {
            return &self.0;
        }
        // Byte length of the last `n` labels including the dots between them.
        let tail_len =
            |n: usize| -> usize { labels[labels.len() - n..].iter().map(|l| l.len()).sum::<usize>() + (n - 1) };
        let keep = if TWO_LEVEL_SUFFIXES.contains(&&self.0[self.0.len() - tail_len(2)..]) { 3 } else { 2 };
        if labels.len() <= keep {
            return &self.0;
        }
        &self.0[self.0.len() - tail_len(keep)..]
    }

    /// True when `self` is `other` or a subdomain of it.
    ///
    /// Mirrors zapret hostlist semantics, where listing `youtube.com` also
    /// covers `www.youtube.com` but must not cover `notyoutube.com`.
    pub fn is_within(&self, other: &Domain) -> bool {
        if self.0 == other.0 {
            return true;
        }
        self.0.len() > other.0.len()
            && self.0.ends_with(&other.0)
            && self.0.as_bytes()[self.0.len() - other.0.len() - 1] == b'.'
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Domain {
    type Error = DomainParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Domain::parse(&value)
    }
}

impl From<Domain> for String {
    fn from(value: Domain) -> Self {
        value.0
    }
}

impl std::str::FromStr for Domain {
    type Err = DomainParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Domain::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_case_wildcard_and_root_dot() {
        assert_eq!(Domain::parse("*.YouTube.COM.").unwrap().as_str(), "youtube.com");
        assert_eq!(Domain::parse("  Www.Example.Org  ").unwrap().as_str(), "www.example.org");
    }

    #[test]
    fn rejects_malformed_names() {
        assert_eq!(Domain::parse(""), Err(DomainParseError::Empty));
        assert_eq!(Domain::parse("a..b"), Err(DomainParseError::BadLabel { label: String::new() }));
        assert!(matches!(Domain::parse("ex ample.com"), Err(DomainParseError::IllegalCharacter { .. })));
        assert_eq!(Domain::parse(&"a".repeat(300)), Err(DomainParseError::TooLong));
    }

    #[test]
    fn subdomain_containment_is_label_aligned() {
        let yt = Domain::parse("youtube.com").unwrap();
        assert!(Domain::parse("www.youtube.com").unwrap().is_within(&yt));
        assert!(yt.is_within(&yt));
        assert!(!Domain::parse("notyoutube.com").unwrap().is_within(&yt));
        assert!(!yt.is_within(&Domain::parse("www.youtube.com").unwrap()));
    }

    #[test]
    fn learning_key_collapses_to_registrable_parent() {
        assert_eq!(Domain::parse("rr1---sn-4g5e6nsz.googlevideo.com").unwrap().learning_key(), "googlevideo.com");
        assert_eq!(Domain::parse("a.b.c.example.co.uk").unwrap().learning_key(), "example.co.uk");
        assert_eq!(Domain::parse("example.com").unwrap().learning_key(), "example.com");
        assert_eq!(Domain::parse("localhost").unwrap().learning_key(), "localhost");
    }
}
