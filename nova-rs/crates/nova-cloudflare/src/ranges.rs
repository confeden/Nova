//! Cloudflare address-space membership test.
//!
//! The published prefix lists (`https://www.cloudflare.com/ips-v4`,
//! `ips-v6`) are small — around 15 IPv4 and 7 IPv6 entries — and change perhaps
//! twice a year, so they are compiled in as a fallback and refreshed from the
//! network opportunistically. Compiling them in matters: the refresh itself
//! goes to Cloudflare, so a build that could only learn the ranges over the
//! network would be unable to bootstrap on exactly the connections this crate
//! exists to fix.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Cloudflare's published IPv4 prefixes, as of the 2026-08 snapshot.
const BUILTIN_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(173, 245, 48, 0), 20),
    (Ipv4Addr::new(103, 21, 244, 0), 22),
    (Ipv4Addr::new(103, 22, 200, 0), 22),
    (Ipv4Addr::new(103, 31, 4, 0), 22),
    (Ipv4Addr::new(141, 101, 64, 0), 18),
    (Ipv4Addr::new(108, 162, 192, 0), 18),
    (Ipv4Addr::new(190, 93, 240, 0), 20),
    (Ipv4Addr::new(188, 114, 96, 0), 20),
    (Ipv4Addr::new(197, 234, 240, 0), 22),
    (Ipv4Addr::new(198, 41, 128, 0), 17),
    (Ipv4Addr::new(162, 158, 0, 0), 15),
    (Ipv4Addr::new(104, 16, 0, 0), 13),
    (Ipv4Addr::new(104, 24, 0, 0), 14),
    (Ipv4Addr::new(172, 64, 0, 0), 13),
    (Ipv4Addr::new(131, 0, 72, 0), 22),
];

/// Cloudflare's published IPv6 prefixes, as of the 2026-08 snapshot.
const BUILTIN_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0x2400, 0xcb00, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2803, 0xf800, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0xb500, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0x8100, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2a06, 0x98c0, 0, 0, 0, 0, 0, 0), 29),
    (Ipv6Addr::new(0x2c0f, 0xf248, 0, 0, 0, 0, 0, 0), 32),
];

/// Prefix set supporting membership queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranges {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl Default for Ranges {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Ranges {
    /// The compiled-in snapshot.
    pub fn builtin() -> Self {
        Self {
            v4: BUILTIN_V4.iter().map(|(addr, len)| (u32::from(*addr), mask32(*len))).collect(),
            v6: BUILTIN_V6.iter().map(|(addr, len)| (u128::from(*addr), mask128(*len))).collect(),
        }
    }

    /// Parse a refreshed list in the one-CIDR-per-line format both published
    /// endpoints use. Unparseable lines are skipped rather than failing the
    /// whole refresh: a single malformed entry must not cost the user the other
    /// twenty valid ones.
    pub fn parse(text: &str) -> Self {
        let mut ranges = Self { v4: Vec::new(), v6: Vec::new() };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (addr, len) = match line.split_once('/') {
                Some((a, l)) => (a, l.parse::<u8>().ok()),
                None => (line, None),
            };
            match addr.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => {
                    let len = len.unwrap_or(32).min(32);
                    ranges.v4.push((u32::from(v4) & mask32(len), mask32(len)));
                }
                Ok(IpAddr::V6(v6)) => {
                    let len = len.unwrap_or(128).min(128);
                    ranges.v6.push((u128::from(v6) & mask128(len), mask128(len)));
                }
                Err(_) => continue,
            }
        }
        ranges
    }

    /// Merge a refreshed list into the builtin one.
    ///
    /// Union rather than replace, because a truncated or hijacked response
    /// (exactly what a blocking ISP might inject) must not be able to *shrink*
    /// Nova's idea of Cloudflare's address space and thereby disable detection.
    pub fn merged_with(&self, other: &Ranges) -> Ranges {
        let mut v4 = self.v4.clone();
        v4.extend_from_slice(&other.v4);
        v4.sort_unstable();
        v4.dedup();
        let mut v6 = self.v6.clone();
        v6.extend_from_slice(&other.v6);
        v6.sort_unstable();
        v6.dedup();
        Ranges { v4, v6 }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                self.v4.iter().any(|(net, mask)| bits & mask == *net)
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                self.v6.iter().any(|(net, mask)| bits & mask == *net)
            }
        }
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn mask32(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len.min(32)) }
}

fn mask128(len: u8) -> u128 {
    if len == 0 { 0 } else { u128::MAX << (128 - len.min(128)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn recognises_well_known_cloudflare_addresses() {
        let r = Ranges::builtin();
        assert!(r.contains(ip("104.16.132.229")), "104.16.0.0/13");
        assert!(r.contains(ip("172.67.74.1")), "172.64.0.0/13");
        assert!(r.contains(ip("162.159.200.1")), "162.158.0.0/15");
        assert!(r.contains(ip("2606:4700:3033::ac43:a01")));
    }

    #[test]
    fn rejects_addresses_outside_the_published_space() {
        let r = Ranges::builtin();
        assert!(!r.contains(ip("8.8.8.8")));
        assert!(!r.contains(ip("93.158.134.3")), "yandex");
        assert!(!r.contains(ip("1.1.1.1")), "the resolver is not the CDN edge");
        assert!(!r.contains(ip("2a02:6b8::2:242")));
    }

    #[test]
    fn parses_the_published_list_format() {
        let r = Ranges::parse("# comment\n104.16.0.0/13\n\n2606:4700::/32\nnot-an-ip\n198.41.128.0/17\n");
        assert_eq!(r.len(), 3, "malformed line must be skipped, not fatal");
        assert!(r.contains(ip("104.20.1.1")));
        assert!(r.contains(ip("2606:4700::1")));
    }

    #[test]
    fn a_truncated_refresh_cannot_shrink_coverage() {
        let hostile = Ranges::parse("104.16.0.0/13\n");
        let merged = Ranges::builtin().merged_with(&hostile);
        assert!(merged.contains(ip("172.67.74.1")), "builtin coverage must survive a hostile refresh");
        assert!(merged.len() >= Ranges::builtin().len());
    }

    #[test]
    fn bare_address_without_prefix_is_a_host_route() {
        let r = Ranges::parse("104.16.132.229\n");
        assert!(r.contains(ip("104.16.132.229")));
        assert!(!r.contains(ip("104.16.132.230")));
    }
}
