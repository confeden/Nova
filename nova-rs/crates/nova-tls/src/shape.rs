//! Emitting a ClientHello in the shape a profile describes.
//!
//! BoringSSL is the library Chrome's TLS is built on, so a Chromium profile is
//! being asked of the stack that produced it rather than reconstructed from
//! scratch. That is the whole reason for the dependency: an OpenSSL that has
//! been argued into approximately the right cipher list still emits OpenSSL's
//! extension set, and the extension set is two thirds of the fingerprint.
//!
//! The mapping tables below are deliberately total and deliberately fallible.
//! A profile naming a cipher, group or signature algorithm this build cannot
//! express is an error, never a silent omission — quietly dropping one value
//! produces a hello that is neither the browser nor the old stack, which is a
//! third fingerprint and the worst of the three outcomes.

use std::io::Write;

use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslConnectorBuilder,
    SslMethod, SslOptions, SslSignatureAlgorithm, SslVerifyMode, SslVersion,
};

use crate::Profile;

/// Extension codepoints the shaping layer knows how to switch on.
const STATUS_REQUEST: u16 = 0x0005;
const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
const COMPRESS_CERTIFICATE: u16 = 0x001b;
const APPLICATION_SETTINGS: u16 = 0x44cd;
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// Certificate decompression, offered because Chromium offers it.
///
/// Decompression only. A client advertises what it can *read* — the server is
/// the side that compresses — and claiming an ability we do not have would
/// break every connection to a server that took us up on it. That asymmetry is
/// why `CAN_COMPRESS` is false rather than an unimplemented stub.
struct BrotliCertificates;

impl CertificateCompressor for BrotliCertificates {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, _input: &[u8], _output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        Err(std::io::Error::other("clients do not compress certificates"))
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        let mut reader = brotli::Decompressor::new(input, 4096);
        std::io::copy(&mut reader, output)?;
        Ok(())
    }
}

/// Why a profile could not be turned into a handshake.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShapeError {
    #[error("cipher {0:#06x} has no name in this build; the hello would be missing it")]
    UnknownCipher(u16),
    #[error("group {0:#06x} is not available in this build; the hello would be missing it")]
    UnknownGroup(u16),
    #[error("signature algorithm {0:#06x} cannot be expressed in this build")]
    UnknownSignatureAlgorithm(u16),
    #[error("BoringSSL rejected the configuration: {0}")]
    Boring(String),
}

impl From<boring::error::ErrorStack> for ShapeError {
    fn from(err: boring::error::ErrorStack) -> Self {
        ShapeError::Boring(err.to_string())
    }
}

/// TLS 1.3 suites, which BoringSSL always offers and does not take from the
/// cipher list. Every profile captured so far offers exactly these three, so
/// they are filtered out of the string rather than being an error.
const TLS13_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];

fn cipher_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0xc02b => "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xc02f => "ECDHE-RSA-AES128-GCM-SHA256",
        0xc02c => "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xc030 => "ECDHE-RSA-AES256-GCM-SHA384",
        0xcca9 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        0xcca8 => "ECDHE-RSA-CHACHA20-POLY1305",
        0xc00a => "ECDHE-ECDSA-AES256-SHA",
        0xc009 => "ECDHE-ECDSA-AES128-SHA",
        0xc013 => "ECDHE-RSA-AES128-SHA",
        0xc014 => "ECDHE-RSA-AES256-SHA",
        0x009c => "AES128-GCM-SHA256",
        0x009d => "AES256-GCM-SHA384",
        0x002f => "AES128-SHA",
        0x0035 => "AES256-SHA",
        0x000a => "DES-CBC3-SHA",
        _ => return None,
    })
}

/// Group names as BoringSSL spells them for `set_curves_list`.
///
/// Names rather than the `SslCurve` constants: those are deprecated as
/// not ABI-stable and are slated for removal, and this list has to outlive a
/// point release of the binding.
fn curve_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x11ec => "X25519MLKEM768",
        0x001d => "X25519",
        0x0017 => "P-256",
        0x0018 => "P-384",
        0x0019 => "P-521",
        _ => return None,
    })
}

fn signature_algorithm(id: u16) -> Option<SslSignatureAlgorithm> {
    Some(match id {
        0x0201 => SslSignatureAlgorithm::RSA_PKCS1_SHA1,
        0x0203 => SslSignatureAlgorithm::ECDSA_SHA1,
        0x0401 => SslSignatureAlgorithm::RSA_PKCS1_SHA256,
        0x0403 => SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        0x0501 => SslSignatureAlgorithm::RSA_PKCS1_SHA384,
        0x0503 => SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        0x0601 => SslSignatureAlgorithm::RSA_PKCS1_SHA512,
        0x0603 => SslSignatureAlgorithm::ECDSA_SECP521R1_SHA512,
        0x0804 => SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        0x0805 => SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        0x0806 => SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        0x0807 => SslSignatureAlgorithm::ED25519,
        // 0x0904..0x0906 are Chrome's newest additions and have no constant in
        // this binding, whose newtype cannot be built from a raw value. They
        // are exactly the three algorithms that separate Chrome from Yandex —
        // so the profile Nova most wants is the one that is fully expressible,
        // and the one that is not is the one it was not going to use.
        _ => return None,
    })
}

/// Whether this build can emit the profile exactly.
///
/// Worth asking before choosing a profile rather than after failing to
/// connect: a profile that cannot be built is a configuration mistake, not a
/// network condition, and it should never reach the phase classifier as one.
pub fn can_express(profile: &Profile) -> Result<(), ShapeError> {
    for &id in &profile.ciphers {
        if !TLS13_SUITES.contains(&id) && cipher_name(id).is_none() {
            return Err(ShapeError::UnknownCipher(id));
        }
    }
    for &id in &profile.groups {
        if curve_name(id).is_none() {
            return Err(ShapeError::UnknownGroup(id));
        }
    }
    for &id in &profile.signature_algorithms {
        if signature_algorithm(id).is_none() {
            return Err(ShapeError::UnknownSignatureAlgorithm(id));
        }
    }
    Ok(())
}

/// Extensions the profile carries that this build cannot put on the wire.
///
/// Reported rather than hidden. A hello that is three extensions short of the
/// browser it claims to be is not that browser, and the difference belongs in
/// a log and in the learner's context — not in a comment nobody reads while
/// wondering why a network still says no.
pub fn unsupported_extensions(profile: &Profile) -> Vec<u16> {
    /// Extensions this binding has no way to put on the wire.
    ///
    /// - `0x44cd` ALPS carries Chromium's HTTP/2 settings; `boring` exposes the
    ///   codepoint as a constant and no setter, in 4.x and 5.x alike.
    /// - `0x001c` record_size_limit and `0x0022` delegated_credentials are
    ///   Firefox's, and likewise unreachable — listed so that a Firefox profile
    ///   reports its real gap rather than appearing exact.
    const UNREACHABLE: [u16; 3] = [APPLICATION_SETTINGS, 0x001c, 0x0022];
    let mut missing: Vec<u16> =
        profile.extensions.iter().copied().filter(|id| UNREACHABLE.contains(id)).collect();
    missing.sort_unstable();
    missing
}

/// The ALPN list this build may actually offer.
///
/// A browser offers `h2` first, and a server that is given the choice takes it
/// — measured against Cloudflare, which selects `h2` whenever it is offered.
/// The relay behind this crate speaks an HTTP/1.1 WebSocket upgrade, so an
/// `h2` connection would carry a request the peer cannot parse: the upgrade
/// would fail in a way that looks like a silent stall rather than a protocol
/// mismatch, and the relay would blame the endpoint for it.
///
/// So `h2` is withheld until something here can speak it. This costs the two
/// trailing characters of the fingerprint's readable half — `h1` where a
/// browser shows `h2` — and that is the honest trade, recorded rather than
/// hidden.
pub fn emitted_alpn(profile: &Profile) -> Vec<String> {
    profile.alpn.iter().filter(|p| p.as_str() != "h2").cloned().collect()
}

/// Every place this build knowingly differs from the browser it imitates.
///
/// One report rather than several scattered checks, because the sum is what
/// matters: each difference on its own is small, and the question worth asking
/// before trusting a profile is how far the total has drifted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Divergence {
    /// Extensions the profile carries that this build cannot send.
    pub missing_extensions: Vec<u16>,
    /// True when `h2` was withheld from the ALPN list.
    pub alpn_downgraded: bool,
}

impl Divergence {
    pub fn is_exact(&self) -> bool {
        self.missing_extensions.is_empty() && !self.alpn_downgraded
    }
}

/// What this build will differ on when emitting `profile`.
pub fn divergence(profile: &Profile) -> Divergence {
    Divergence {
        missing_extensions: unsupported_extensions(profile),
        alpn_downgraded: profile.alpn.iter().any(|p| p == "h2"),
    }
}

/// The fingerprint this build will actually put on the wire for `profile`.
///
/// Distinct from [`Profile::expected_ja4`], which is what the browser sends.
/// Where the two differ, the difference is measured and named by
/// [`divergence`] rather than discovered later by a network.
pub fn emitted_ja4(profile: &Profile, has_sni: bool) -> String {
    let missing = unsupported_extensions(profile);
    let mut hello = profile.as_client_hello(has_sni);
    hello.extensions.retain(|id| !missing.contains(id));
    hello.alpn = emitted_alpn(profile);
    hello.ja4()
}

/// A configured client that emits `profile`'s shape.
pub struct Shaper {
    connector: SslConnector,
    ech_grease: bool,
}

impl Shaper {
    /// `verify` is a parameter because the two callers want opposite things:
    /// the relay verifies, and the test that measures our own hello points at a
    /// listener with no certificate that never completes a handshake.
    pub fn new(profile: &Profile, verify: bool) -> Result<Self, ShapeError> {
        can_express(profile)?;
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        configure(&mut builder, profile, verify)?;
        Ok(Self {
            connector: builder.build(),
            ech_grease: profile.extensions.contains(&ENCRYPTED_CLIENT_HELLO),
        })
    }

    /// Start a handshake for `sni` over an already-connected stream.
    pub fn connect<S>(&self, sni: &str, stream: S) -> Result<boring::ssl::SslStream<S>, ShapeError>
    where
        S: std::io::Read + std::io::Write,
    {
        let config = self.connector.configure()?;
        if self.ech_grease {
            // GREASE ECH is a per-connection setting rather than a context one,
            // and it is what puts 0xfe0d on the wire without needing a real ECH
            // config — which is exactly what a browser does when the name it is
            // visiting publishes none.
            config.set_enable_ech_grease(true);
        }
        config.connect(sni, stream).map_err(|err| ShapeError::Boring(err.to_string()))
    }
}

/// Build a connector that speaks in the shape of `profile`.
///
/// Prefer [`Shaper`], which also carries the per-connection settings. This is
/// kept for callers that need the raw connector.
pub fn connector(profile: &Profile, verify: bool) -> Result<SslConnector, ShapeError> {
    can_express(profile)?;
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    configure(&mut builder, profile, verify)?;
    Ok(builder.build())
}

fn configure(
    builder: &mut SslConnectorBuilder,
    profile: &Profile,
    verify: bool,
) -> Result<(), ShapeError> {
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    let names: Vec<&str> = profile
        .ciphers
        .iter()
        .filter(|id| !TLS13_SUITES.contains(id))
        .filter_map(|id| cipher_name(*id))
        .collect();
    builder.set_cipher_list(&names.join(":"))?;

    // Order matters: the first group is the one a key share is generated for,
    // and a browser leads with its post-quantum hybrid.
    let curves: Vec<&str> = profile.groups.iter().filter_map(|id| curve_name(*id)).collect();
    builder.set_curves_list(&curves.join(":"))?;

    let sigalgs: Vec<SslSignatureAlgorithm> =
        profile.signature_algorithms.iter().filter_map(|id| signature_algorithm(*id)).collect();
    builder.set_verify_algorithm_prefs(&sigalgs)?;

    let alpn = emitted_alpn(profile);
    if !alpn.is_empty() {
        // Wire form: each protocol prefixed with its length. Its absence is the
        // single loudest thing about the hello Nova sends today.
        let mut wire = Vec::new();
        for protocol in &alpn {
            wire.push(protocol.len() as u8);
            wire.extend_from_slice(protocol.as_bytes());
        }
        builder.set_alpn_protos(&wire)?;
    }

    // Extensions that exist only because they are switched on, driven by what
    // the capture actually contained rather than by a fixed list — the profile
    // is the description, so it should be the thing that decides.
    if profile.extensions.contains(&STATUS_REQUEST) {
        builder.enable_ocsp_stapling();
    }
    if profile.extensions.contains(&SIGNED_CERTIFICATE_TIMESTAMP) {
        builder.enable_signed_cert_timestamps();
    }
    if profile.extensions.contains(&COMPRESS_CERTIFICATE) {
        builder.add_certificate_compression_algorithm(BrotliCertificates)?;
    }

    builder.set_grease_enabled(profile.grease);
    // Chrome shuffles its extension order on every connection, so a fixed order
    // is the anomaly rather than the safe choice. JA4 sorts the list, so this
    // costs nothing there and buys resistance to anything matching on order.
    builder.set_permute_extensions(true);

    // Renegotiation info, which every captured profile carries.
    builder.set_options(SslOptions::NO_RENEGOTIATION);

    builder.set_verify(if verify { SslVerifyMode::PEER } else { SslVerifyMode::NONE });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{built_in_profile, built_in_profiles};

    #[test]
    fn the_profile_nova_wants_is_fully_expressible() {
        // Yandex is Chrome minus three signature algorithms this binding cannot
        // name. That makes the preferred profile the exactly-reproducible one.
        let yandex = built_in_profile("yandex-windows").expect("built in");
        assert_eq!(can_express(&yandex), Ok(()));
        assert!(connector(&yandex, false).is_ok());
    }

    #[test]
    fn a_profile_this_build_cannot_emit_says_so_instead_of_approximating() {
        // Chrome carries 0x0904..0x0906. Silently dropping them would produce a
        // hello that is neither Chrome nor Yandex nor the old stack — a third
        // fingerprint, and the worst available outcome.
        let chrome = built_in_profile("chrome-windows").expect("built in");
        assert_eq!(
            can_express(&chrome),
            Err(ShapeError::UnknownSignatureAlgorithm(0x0904)),
            "an inexpressible profile must be refused, not approximated"
        );
    }

    #[test]
    fn every_cipher_in_every_built_in_profile_has_a_name() {
        // The cipher and group tables are allowed to be incomplete in general,
        // but never for a profile that ships.
        for profile in built_in_profiles() {
            for &id in &profile.ciphers {
                assert!(
                    TLS13_SUITES.contains(&id) || cipher_name(id).is_some(),
                    "{}: cipher {id:#06x} has no name",
                    profile.name
                );
            }
        }
    }

    #[test]
    fn firefox_is_refused_for_a_reason_that_names_the_group() {
        // Firefox offers finite-field groups that BoringSSL has no curve for.
        // The error has to say which, or diagnosing it means reading the table.
        let firefox = built_in_profile("firefox-windows").expect("built in");
        assert_eq!(can_express(&firefox), Err(ShapeError::UnknownGroup(0x0100)));
    }

    #[test]
    fn h2_is_withheld_because_offering_it_would_break_the_upgrade() {
        // Measured against Cloudflare: offering h2 gets h2 selected, and the
        // relay's HTTP/1.1 WebSocket upgrade cannot travel on an h2 connection.
        // The failure would surface as a stalled tunnel and be blamed on the
        // endpoint, so the offer is withheld rather than made and regretted.
        let yandex = built_in_profile("yandex-windows").expect("built in");
        assert_eq!(yandex.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
        assert_eq!(emitted_alpn(&yandex), vec!["http/1.1".to_owned()]);
    }

    #[test]
    fn the_alpn_downgrade_shows_up_in_the_fingerprint_rather_than_hiding() {
        let yandex = built_in_profile("yandex-windows").expect("built in");
        // A browser shows `h2` in the readable half; we will show `h1`.
        assert!(yandex.expected_ja4(true).starts_with("t13d1516h2"));
        assert!(emitted_ja4(&yandex, true).starts_with("t13d1515h1"));
    }

    #[test]
    fn divergence_accounts_for_every_known_difference() {
        // The sum, in one place. Each difference is small; the question worth
        // asking before trusting a profile is how far the total has drifted.
        let yandex = built_in_profile("yandex-windows").expect("built in");
        let d = divergence(&yandex);
        assert_eq!(d.missing_extensions, vec![APPLICATION_SETTINGS]);
        assert!(d.alpn_downgraded);
        assert!(!d.is_exact(), "nothing here is byte-exact yet, and saying so is the point");
    }

    #[test]
    fn a_profile_with_nothing_to_adjust_reports_itself_exact() {
        // Guards the reporting itself: if `is_exact` could never be true, it
        // would be a decoration rather than a check.
        let plain = Profile {
            name: "plain".to_owned(),
            ciphers: vec![0x1301],
            extensions: vec![0x002b],
            signature_algorithms: vec![0x0403],
            groups: vec![0x001d],
            alpn: vec!["http/1.1".to_owned()],
            grease: true,
        };
        assert!(divergence(&plain).is_exact());
    }

    #[test]
    fn a_connector_can_actually_be_built() {
        let yandex = built_in_profile("yandex-windows").expect("built in");
        connector(&yandex, true).expect("verifying connector builds");
        connector(&yandex, false).expect("non-verifying connector builds");
    }
}
