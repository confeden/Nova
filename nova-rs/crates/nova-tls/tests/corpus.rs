//! The parser, run against every TLS-shaped blob in `fake/`.
//!
//! This corpus was originally reached for as a source of browser fingerprints,
//! on the reasoning that zapret injects real captures as decoys. Measuring it
//! said otherwise: 38 of 60 files carry a `supported_versions` extension whose
//! length byte disagrees with its contents, dozens share the byte sequence
//! `030203040303` and an identical 560-byte size with only the SNI differing,
//! and two files whose names say `tls_clienthello` are not TLS at all —
//! `tls_clienthello_6.bin` is an HTTP response. They are templated decoys, not
//! distinct browsers.
//!
//! So the corpus is kept for what it is actually good for: hostile input. Every
//! one of these is a blob the parser may be handed, several are malformed, and
//! none of them may panic. Profiles come from [`super`]'s capture tooling
//! instead, pointed at a browser that is really running.

use std::path::PathBuf;

use nova_tls::parse_client_hello;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../fake")
}

fn captures() -> Vec<(String, Vec<u8>)> {
    let Ok(entries) = std::fs::read_dir(corpus_dir()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned();
        if !name.ends_with(".bin") {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path) {
            out.push((name, bytes));
        }
    }
    out.sort();
    out
}

/// The corpus is not published to git, so a clean clone legitimately lacks it.
fn corpus_or_skip() -> Option<Vec<(String, Vec<u8>)>> {
    let found = captures();
    if found.is_empty() { None } else { Some(found) }
}

#[test]
fn nothing_in_the_corpus_makes_the_parser_panic() {
    let Some(captures) = corpus_or_skip() else { return };
    // Everything in `fake/` — TLS hellos, QUIC initials, DTLS, WireGuard,
    // STUN, an HTTP response — goes in. A wrong answer is acceptable here; a
    // panic in the relay's connection path is not.
    for (name, bytes) in &captures {
        let _ = parse_client_hello(bytes);
        // …and so does every prefix of it, which is what a short read looks
        // like when a capture arrives over the wire in pieces.
        for cut in [1usize, 5, 9, 44, 100, bytes.len() / 2] {
            if cut < bytes.len() {
                let _ = parse_client_hello(&bytes[..cut]);
            }
        }
        let _ = name;
    }
}

#[test]
fn well_formed_hellos_produce_well_formed_fingerprints() {
    let Some(captures) = corpus_or_skip() else { return };
    let mut checked = 0usize;
    for (name, bytes) in captures {
        let Ok(hello) = parse_client_hello(&bytes) else { continue };
        if hello.ciphers.is_empty() {
            continue;
        }
        let ja4 = hello.ja4();
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 3, "{name}: {ja4}");
        assert_eq!(parts[0].len(), 10, "{name}: readable half is {}", parts[0]);
        assert_eq!(parts[1].len(), 12, "{name}: cipher hash is {}", parts[1]);
        assert_eq!(parts[2].len(), 12, "{name}: extension hash is {}", parts[2]);
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} usable hellos found; the corpus moved");
}

#[test]
fn grease_never_reaches_the_fingerprint() {
    let Some(captures) = corpus_or_skip() else { return };
    // If GREASE leaked through, a browser that sends it would produce a new
    // fingerprint on every connection and the whole measurement would be noise.
    for (name, bytes) in captures {
        let Ok(hello) = parse_client_hello(&bytes) else { continue };
        for cipher in &hello.ciphers {
            assert!(!nova_tls::is_grease(*cipher), "{name}: GREASE cipher {cipher:#06x}");
        }
        for extension in &hello.extensions {
            assert!(!nova_tls::is_grease(*extension), "{name}: GREASE extension {extension:#06x}");
        }
        for group in &hello.groups {
            assert!(!nova_tls::is_grease(*group), "{name}: GREASE group {group:#06x}");
        }
    }
}

#[test]
fn a_malformed_extension_does_not_poison_the_whole_parse() {
    let Some(captures) = corpus_or_skip() else { return };
    // The templated decoys have a broken `supported_versions`. That must cost
    // the version field and nothing else — the ciphers and extensions around it
    // are still readable, and a parser that gave up entirely would be unable to
    // say anything about a hello a real network had merely truncated.
    let path = corpus_dir().join("tls_clienthello_yandex_ru.bin");
    let Ok(bytes) = std::fs::read(&path) else { return };
    let hello = parse_client_hello(&bytes).expect("parses despite the broken extension");
    assert!(!hello.ciphers.is_empty(), "the cipher list should survive a bad later extension");
    assert!(hello.has_sni, "the SNI extension precedes the broken one and should survive");
    assert!(!hello.extensions.is_empty());
    // This decoy carries no `signature_algorithms` at all — one more reason it
    // is not a browser. The parser reports that as an empty list rather than
    // inventing one, and the fingerprint still computes.
    assert!(hello.signature_algorithms.is_empty());
    assert_eq!(hello.ja4().split('_').count(), 3);
    let _ = captures;
}

/// Not an assertion — a way to look at the corpus. Run with:
/// `cargo test -p nova-tls --test corpus -- --ignored --nocapture`
#[test]
#[ignore = "diagnostic output, not a check"]
fn show_the_corpus() {
    let Some(captures) = corpus_or_skip() else { return };
    let mut rows: Vec<(String, String, usize, usize)> = Vec::new();
    for (name, bytes) in captures {
        if let Ok(hello) = parse_client_hello(&bytes) {
            if hello.ciphers.is_empty() {
                continue;
            }
            rows.push((name, hello.ja4(), hello.ciphers.len(), hello.extensions.len()));
        }
    }
    rows.sort_by(|a, b| a.1.cmp(&b.1));
    println!("\n{:<44} {:<40} {:>7} {:>5}", "capture", "ja4", "ciphers", "ext");
    for (name, ja4, ciphers, extensions) in rows {
        println!("{name:<44} {ja4:<40} {ciphers:>7} {extensions:>5}");
    }
}
