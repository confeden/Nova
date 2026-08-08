//! What Nova's TLS looks like from outside, and what it should look like.
//!
//! The relay's own connections are made by CPython's OpenSSL, whose ClientHello
//! resembles no browser on any desktop. Under a filtering network that reads
//! JA4, that is a plainer statement of what the traffic is than anything the
//! payload could say — and it is read before the payload exists.
//!
//! This crate has two halves. [`ja4`] reads a ClientHello and computes its
//! fingerprint, which is what makes any claim here checkable offline. The
//! profiles below describe shapes worth wearing instead.
//!
//! No I/O, in keeping with the rest of the workspace: bytes and descriptions
//! in, fingerprints and configuration out.

#![forbid(unsafe_code)]

pub mod ja4;
#[cfg(feature = "shape")]
pub mod shape;

pub use ja4::{ClientHello, Ja4Error, is_grease, parse_client_hello};

/// `server_name`, which is a property of the request rather than of the client.
pub const SERVER_NAME: u16 = 0x0000;

/// Profiles captured from browsers on the machine Nova ships to.
///
/// Compiled in rather than loaded, so a build cannot start with a profile file
/// missing. Adding one is `capture-hello --out`, then dropping the JSON here
/// and naming it below — deliberately the shortest path, because a profile that
/// is annoying to refresh becomes a profile that describes a browser nobody
/// runs any more.
const BUILT_IN: &[(&str, &str)] = &[
    ("yandex-windows", include_str!("../profiles/yandex-windows.json")),
    ("chrome-windows", include_str!("../profiles/chrome-windows.json")),
    ("firefox-windows", include_str!("../profiles/firefox-windows.json")),
];

/// Every profile Nova knows, in preference order.
///
/// Yandex leads on the reasoning that a Russian filtering network has the
/// least appetite for degrading the browser it is most likely to see — but
/// that is a hypothesis, and the order here is only a starting point for the
/// learner, not a conclusion.
pub fn built_in_profiles() -> Vec<Profile> {
    BUILT_IN
        .iter()
        .map(|(name, json)| {
            serde_json::from_str::<Profile>(json)
                .unwrap_or_else(|err| panic!("built-in profile {name} does not parse: {err}"))
        })
        .collect()
}

/// One profile by name, or `None` when it is not built in.
pub fn built_in_profile(name: &str) -> Option<Profile> {
    built_in_profiles().into_iter().find(|profile| profile.name == name)
}

/// A shape the relay can present.
///
/// Deliberately data, not code: the shapes come from ClientHellos captured off
/// real browsers, and the way to add one is to capture another rather than to
/// hand-write a cipher list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Profile {
    /// Stable name, used as a persistence key and in logs. Never rewritten for
    /// cosmetic reasons.
    pub name: String,
    /// Cipher suites in the order the browser sends them.
    pub ciphers: Vec<u16>,
    /// Extension types in the order the browser sends them.
    pub extensions: Vec<u16>,
    /// Signature algorithms in wire order — the order is part of the identity.
    pub signature_algorithms: Vec<u16>,
    /// Named groups in wire order.
    pub groups: Vec<u16>,
    /// ALPN protocols offered.
    pub alpn: Vec<String>,
    /// Whether the browser pads its hello with GREASE values.
    pub grease: bool,
}

impl Profile {
    /// The fingerprint this profile is expected to produce for a named host.
    ///
    /// `has_sni` is a parameter rather than a field because it is a property of
    /// the request, not of the client: the same browser produces a `d` or an
    /// `i` depending on whether it was given a name or an address.
    pub fn expected_ja4(&self, has_sni: bool) -> String {
        self.as_client_hello(has_sni).ja4()
    }

    /// The profile expressed as a parsed hello, so it can be compared directly
    /// against something captured off the wire.
    ///
    /// `server_name` is added or removed to match `has_sni` rather than taken
    /// from the stored list. This is not a nicety: profiles are captured by
    /// pointing a browser at `127.0.0.1`, and no browser sends `server_name`
    /// for an address literal. Every stored profile is therefore one extension
    /// short of what the same browser sends to a hostname, and using it as-is
    /// would build a hello that announces itself by having the wrong extension
    /// count.
    pub fn as_client_hello(&self, has_sni: bool) -> ClientHello {
        let mut extensions: Vec<u16> =
            self.extensions.iter().copied().filter(|t| *t != SERVER_NAME).collect();
        if has_sni {
            // Position is irrelevant to JA4, which sorts the extension list —
            // and to Chrome, which shuffles it on every connection anyway.
            extensions.insert(0, SERVER_NAME);
        }
        ClientHello {
            // Every profile here offers TLS 1.3; a desktop browser that did not
            // would be the anomaly.
            version: 0x0304,
            has_sni,
            ciphers: self.ciphers.clone(),
            extensions,
            signature_algorithms: self.signature_algorithms.clone(),
            alpn: self.alpn.clone(),
            groups: self.groups.clone(),
        }
    }

    /// Read a profile out of a captured ClientHello.
    ///
    /// This is how profiles are meant to be produced: point it at bytes a real
    /// browser sent and keep the result. Hand-written cipher lists drift from
    /// what any browser actually ships and cannot be checked against anything.
    pub fn from_capture(name: impl Into<String>, capture: &[u8]) -> Result<Self, Ja4Error> {
        let hello = parse_client_hello(capture)?;
        Ok(Self {
            name: name.into(),
            ciphers: hello.ciphers,
            // A capture has GREASE already stripped by the parser, so its
            // absence here says nothing about whether the browser sent it.
            grease: true,
            extensions: hello.extensions,
            signature_algorithms: hello.signature_algorithms,
            groups: hello.groups,
            alpn: hello.alpn,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_round_trips_through_a_capture() {
        // The path a real profile takes: browser bytes in, profile out, and the
        // profile still describes the same fingerprint.
        let hello = ClientHello {
            version: 0x0304,
            has_sni: true,
            ciphers: vec![0x1301, 0x1302, 0x1303],
            extensions: vec![0x0000, 0x000a, 0x000d, 0x0010, 0x002b],
            signature_algorithms: vec![0x0403, 0x0804, 0x0401],
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            groups: vec![0x001d, 0x0017],
        };
        let profile = Profile {
            name: "test".to_owned(),
            ciphers: hello.ciphers.clone(),
            extensions: hello.extensions.clone(),
            signature_algorithms: hello.signature_algorithms.clone(),
            groups: hello.groups.clone(),
            alpn: hello.alpn.clone(),
            grease: true,
        };
        assert_eq!(profile.expected_ja4(true), hello.ja4());
    }

    #[test]
    fn every_built_in_profile_parses_and_is_named_after_itself() {
        let profiles = built_in_profiles();
        assert_eq!(profiles.len(), 3);
        for profile in &profiles {
            assert!(built_in_profile(&profile.name).is_some(), "{} is not findable", profile.name);
            assert!(!profile.ciphers.is_empty(), "{}", profile.name);
            assert!(!profile.signature_algorithms.is_empty(), "{}", profile.name);
            assert_eq!(profile.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()], "{}", profile.name);
        }
        assert!(built_in_profile("netscape-4").is_none());
    }

    #[test]
    fn a_captured_profile_gains_the_extension_it_could_not_have_been_captured_with() {
        // Captures are taken against 127.0.0.1, and no browser sends
        // `server_name` to an address literal. Every stored profile is one
        // extension short of what the same browser sends to a hostname, and
        // shipping that count would be announcing ourselves by arithmetic.
        for profile in built_in_profiles() {
            assert!(
                !profile.extensions.contains(&SERVER_NAME),
                "{} was captured with an SNI, which the tooling cannot produce",
                profile.name
            );
            let to_host = profile.as_client_hello(true);
            let to_address = profile.as_client_hello(false);
            assert!(to_host.extensions.contains(&SERVER_NAME));
            assert!(!to_address.extensions.contains(&SERVER_NAME));
            assert_eq!(to_host.extensions.len(), to_address.extensions.len() + 1);
        }
    }

    #[test]
    fn the_profiles_reproduce_the_fingerprints_they_were_captured_as() {
        // The readable half is checkable by eye and by arithmetic: fifteen
        // ciphers and fifteen extensions were measured against an address, so
        // against a hostname the same browser shows sixteen extensions.
        let chrome = built_in_profile("chrome-windows").expect("built in");
        assert_eq!(chrome.as_client_hello(false).ja4_a(), "t13i1515h2");
        assert_eq!(chrome.as_client_hello(true).ja4_a(), "t13d1516h2");

        let yandex = built_in_profile("yandex-windows").expect("built in");
        assert_eq!(yandex.as_client_hello(true).ja4_a(), "t13d1516h2");

        let firefox = built_in_profile("firefox-windows").expect("built in");
        assert_eq!(firefox.as_client_hello(true).ja4_a(), "t13d1616h2");
    }

    #[test]
    fn yandex_and_chrome_differ_only_where_they_actually_differ() {
        // Yandex Browser is Chromium, so the two agree on ciphers and on the
        // set of extensions, and their readable halves are identical. What
        // separates them is the signature algorithm list — eight against
        // eleven — which lands in the third segment of the fingerprint. Any
        // claim that one of them gets through a filter and the other does not
        // rests entirely on this difference.
        let chrome = built_in_profile("chrome-windows").expect("built in");
        let yandex = built_in_profile("yandex-windows").expect("built in");

        assert_eq!(chrome.ciphers, yandex.ciphers);
        assert_eq!(chrome.as_client_hello(true).ja4_a(), yandex.as_client_hello(true).ja4_a());
        assert_eq!(chrome.as_client_hello(true).ja4_b(), yandex.as_client_hello(true).ja4_b());

        assert_ne!(chrome.signature_algorithms, yandex.signature_algorithms);
        assert_ne!(chrome.as_client_hello(true).ja4_c(), yandex.as_client_hello(true).ja4_c());
        assert_ne!(chrome.expected_ja4(true), yandex.expected_ja4(true));
    }

    #[test]
    fn no_profile_looks_like_what_nova_sends_today() {
        // Measured baseline of the relay's own hello: CPython over OpenSSL,
        // eighteen ciphers, eleven extensions, no ALPN at all. A rule matching
        // just the readable half catches every Nova connection and nothing
        // else, which is the whole reason this crate exists.
        const CURRENT: &str = "t13d181100";
        for profile in built_in_profiles() {
            assert_ne!(profile.as_client_hello(true).ja4_a(), CURRENT, "{}", profile.name);
        }
    }

    #[test]
    fn sni_presence_is_a_property_of_the_request_not_the_profile() {
        let profile = Profile {
            name: "test".to_owned(),
            ciphers: vec![0x1301],
            extensions: vec![0x0000, 0x002b],
            signature_algorithms: vec![0x0403],
            groups: vec![0x001d],
            alpn: vec!["h2".to_owned()],
            grease: true,
        };
        assert_ne!(profile.expected_ja4(true), profile.expected_ja4(false));
    }
}
