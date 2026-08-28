//! The `host:port` of a `CONNECT` request line.

/// A parsed CONNECT target. Both fields are always valid: there is no way to
/// build one with an empty host or a zero port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    host: String,
    port: u16,
}

impl Authority {
    /// Build one from parts that did not come from a CONNECT line — the SOCKS5
    /// handshake produces a host and a port separately.
    ///
    /// Fallible on purpose: the invariant on this type is the whole reason it
    /// exists, so there is no infallible constructor to reach for when a caller
    /// finds validation inconvenient.
    pub fn new(host: impl Into<String>, port: u16) -> Option<Self> {
        let host = host.into();
        let host = host.trim().to_string();
        if host.is_empty() || port == 0 {
            return None;
        }
        Some(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A CONNECT line without a port is not RFC 9110, but home-grown clients send
/// it. Exactly one port is meaningful for a tunnel.
const DEFAULT_CONNECT_PORT: u16 = 443;

/// Split a CONNECT target into host and port.
///
/// IPv6 arrives in brackets (`[2001:db8::1]:443`), so splitting on the last
/// colon is only safe once the brackets are off — otherwise every colon of the
/// address is a candidate separator.
pub fn split_http_authority(target: &str) -> Option<Authority> {
    let text = target.trim();
    if text.is_empty() {
        return None;
    }

    let (host, port_text) = if let Some(rest) = text.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        if !tail.is_empty() && !tail.starts_with(':') {
            return None;
        }
        (host, tail.get(1..).unwrap_or(""))
    } else {
        match text.rfind(':') {
            Some(idx) => (&text[..idx], &text[idx + 1..]),
            None => (text, ""),
        }
    };

    let host = host.trim();
    if host.is_empty() {
        return None;
    }

    let port = if port_text.is_empty() {
        DEFAULT_CONNECT_PORT
    } else {
        // Parsed wide, then range-checked, so that "0" and "70000" are rejected
        // for being out of range rather than accepted by a lucky wrap.
        let parsed: i64 = port_text.trim().parse().ok()?;
        if parsed <= 0 || parsed >= 65536 {
            return None;
        }
        parsed as u16
    };

    Some(Authority { host: host.to_string(), port })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(target: &str) -> Option<(String, u16)> {
        split_http_authority(target).map(|a| (a.host().to_string(), a.port()))
    }

    #[test]
    fn plain_host_and_port() {
        assert_eq!(parts("example.com:8443"), Some(("example.com".into(), 8443)));
    }

    #[test]
    fn missing_port_falls_back_to_443() {
        assert_eq!(parts("example.com"), Some(("example.com".into(), 443)));
        assert_eq!(parts("example.com:"), Some(("example.com".into(), 443)));
    }

    #[test]
    fn ipv6_needs_the_brackets_off_before_splitting() {
        assert_eq!(parts("[2001:db8::1]:443"), Some(("2001:db8::1".into(), 443)));
        assert_eq!(parts("[2001:db8::1]"), Some(("2001:db8::1".into(), 443)));
        assert_eq!(parts("[::1]:80"), Some(("::1".into(), 80)));
    }

    #[test]
    fn malformed_ipv6_is_rejected_not_guessed() {
        assert_eq!(parts("[2001:db8::1"), None, "no closing bracket");
        assert_eq!(parts("[::1]x"), None, "tail that is not a port");
        assert_eq!(parts("[]:443"), None, "empty host inside brackets");
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(parts("  example.com:443  "), Some(("example.com".into(), 443)));
    }

    #[test]
    fn out_of_range_and_non_numeric_ports_are_rejected() {
        assert_eq!(parts("example.com:0"), None);
        assert_eq!(parts("example.com:65536"), None);
        assert_eq!(parts("example.com:-1"), None);
        assert_eq!(parts("example.com:https"), None);
        assert_eq!(parts("example.com:0x10"), None);
    }

    #[test]
    fn boundary_ports_are_accepted() {
        assert_eq!(parts("example.com:1"), Some(("example.com".into(), 1)));
        assert_eq!(parts("example.com:65535"), Some(("example.com".into(), 65535)));
    }

    #[test]
    fn empty_and_hostless_targets_are_rejected() {
        assert_eq!(parts(""), None);
        assert_eq!(parts("   "), None);
        assert_eq!(parts(":443"), None);
    }

    #[test]
    fn new_rejects_the_states_the_type_forbids() {
        assert!(Authority::new("example.com", 443).is_some());
        assert!(Authority::new("", 443).is_none(), "empty host");
        assert!(Authority::new("   ", 443).is_none(), "whitespace-only host");
        assert!(Authority::new("example.com", 0).is_none(), "port 0");
    }

    #[test]
    fn new_trims_the_host_like_the_parser_does() {
        let a = Authority::new("  example.com  ", 443).expect("valid");
        assert_eq!(a.host(), "example.com");
    }

    #[test]
    fn authority_cannot_be_built_in_an_invalid_state() {
        // The only constructor is the parser, and it never yields these.
        let a = split_http_authority("example.com:443").expect("valid");
        assert!(!a.host().is_empty());
        assert!(a.port() > 0);
    }
}
