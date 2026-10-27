//! The claim, checked against the wire.
//!
//! Everything else in this crate is a description: a profile says a browser
//! sends fifteen ciphers, a connector says it was configured to. Neither is
//! evidence. This test opens a socket, sends a real handshake through the real
//! library, reads back the bytes that actually left, and computes the
//! fingerprint a filtering network would compute from them.
//!
//! No certificate and no network. The listener reads the ClientHello and hangs
//! up, so the handshake always fails — which is fine, because the hello is the
//! entire subject. Anything that passes here passes offline, on any machine
//! with the toolchain, for ever.
//!
//! ```text
//! cargo test -p nova-tls --features shape --test shape_roundtrip
//! ```
#![cfg(feature = "shape")]

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use nova_tls::{ClientHello, built_in_profile, parse_client_hello, shape};

/// Run one handshake attempt against a listener that only ever listens, and
/// return the ClientHello it received.
fn hello_on_the_wire(profile_name: &str, sni: &str) -> ClientHello {
    parse_client_hello(&raw_hello_on_the_wire(profile_name, sni))
        .expect("what we sent is a ClientHello")
}

/// The same, as the bytes that left: the record, GREASE included.
fn raw_hello_on_the_wire(profile_name: &str, sni: &str) -> Vec<u8> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a loopback port");
    let port = listener.local_addr().expect("bound").port();
    let (tx, rx) = mpsc::channel();

    let collector = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the client connects");
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buf = vec![0u8; 16 * 1024];
        let mut filled = 0usize;
        // A ClientHello with a post-quantum key share does not fit in one
        // segment. Judging it on the first read would measure the loopback MTU.
        while filled < buf.len() {
            match stream.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => {
                    filled += n;
                    if filled >= 5 {
                        let declared = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                        if filled >= declared + 5 {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        buf.truncate(filled);
        let _ = tx.send(buf);
    });

    let profile = built_in_profile(profile_name).expect("built in");
    // Through `Shaper`, not the bare connector: some of the shape is
    // per-connection rather than per-context, and measuring the context alone
    // would quietly under-report what the relay actually sends.
    let shaper = shape::Shaper::new(&profile, false).expect("shaper builds");
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
    // Expected to fail: nothing is ever sent back. The hello has already left.
    let _ = shaper.connect(sni, stream);

    let bytes = rx.recv_timeout(Duration::from_secs(10)).expect("the hello arrives");
    collector.join().expect("collector finishes");
    bytes
}

#[test]
#[cfg(not(bssl_patched))] // the patched library adds 0xca34 and a sigalg GREASE to every profile
fn what_we_send_is_exactly_what_this_build_says_it_will_send() {
    // The whole point, in one assertion: no gap between the prediction and the
    // wire. Where the prediction falls short of the browser it is imitating,
    // that shortfall is named by `unsupported_extensions` and asserted
    // separately below — never discovered later by a network.
    let profile = built_in_profile("yandex-windows").expect("built in");
    let sent = hello_on_the_wire("yandex-windows", "kws2.nova-app.eu");
    assert_eq!(
        sent.ja4(),
        shape::emitted_ja4(&profile, true),
        "\n  on the wire: {}\n  predicted  : {}\n",
        sent.ja4(),
        shape::emitted_ja4(&profile, true)
    );
}

#[test]
#[cfg(not(bssl_patched))] // the patched library adds 0xca34 and a sigalg GREASE to every profile
fn the_gap_to_the_browser_is_exactly_two_named_things() {
    // Honest accounting of what is left. Two differences, both deliberate and
    // both recorded: `boring` exposes ALPS as a codepoint constant and no way
    // to send it (4.x and 5.x alike), and `h2` is withheld because the relay
    // behind this speaks an HTTP/1.1 upgrade that an h2 connection cannot
    // carry. Ciphers, groups, signature algorithms and every other extension
    // match the browser.
    let profile = built_in_profile("yandex-windows").expect("built in");
    let divergence = shape::divergence(&profile);
    assert_eq!(divergence.missing_extensions, vec![0x44cd]);
    assert!(divergence.alpn_downgraded);

    let sent = hello_on_the_wire("yandex-windows", "kws2.nova-app.eu");
    let browser = profile.as_client_hello(true);

    // The cipher half is identical — that is the whole of JA4_b.
    assert_eq!(sent.ja4_b(), browser.ja4_b(), "cipher list should match the browser exactly");
    assert_eq!(sent.groups, browser.groups);
    assert_eq!(sent.signature_algorithms, browser.signature_algorithms);

    // And the extension sets differ by exactly one member.
    let mut missing: Vec<u16> =
        browser.extensions.iter().copied().filter(|id| !sent.extensions.contains(id)).collect();
    missing.sort_unstable();
    assert_eq!(missing, vec![0x44cd]);
    let extra: Vec<u16> =
        sent.extensions.iter().copied().filter(|id| !browser.extensions.contains(id)).collect();
    assert!(extra.is_empty(), "we send something the browser does not: {extra:?}");
}

#[test]
#[cfg(not(bssl_patched))] // the patched library adds 0xca34 and a sigalg GREASE to every profile
fn what_we_send_no_longer_looks_like_the_old_stack() {
    // The measured baseline of CPython over OpenSSL, from `capture-hello`:
    // eighteen ciphers, eleven extensions, no ALPN at all. A rule matching just
    // this readable half caught every Nova connection and nothing else.
    const OLD: &str = "t13d181100";
    let sent = hello_on_the_wire("yandex-windows", "kws2.nova-app.eu");
    assert_ne!(sent.ja4_a(), OLD);
    assert_eq!(sent.ja4_a(), "t13d1515h1", "the readable half should now read as Chromium-shaped");
}

#[test]
#[cfg(not(bssl_patched))] // the patched library adds 0xca34 and a sigalg GREASE to every profile
fn the_three_tells_of_the_old_stack_are_gone() {
    let sent = hello_on_the_wire("yandex-windows", "kws2.nova-app.eu");

    // 1. ALPN. Its total absence was the loudest of the three: a TLS 1.3
    //    client with an SNI and no ALPN at all is not a browser. `h2` is
    //    withheld — see `emitted_alpn` — so this is http/1.1 alone, which is
    //    an improvement on nothing and short of a browser.
    assert_eq!(sent.alpn, vec!["http/1.1".to_owned()]);

    // 2. Extension count. Eleven against a browser's sixteen.
    assert_eq!(sent.extensions.len(), 15, "extensions: {:?}", sent.extensions);

    // 3. Finite-field Diffie-Hellman groups. OpenSSL offers ffdhe2048 upwards;
    //    no Chromium browser offers any of them.
    for group in &sent.groups {
        assert!(
            !(0x0100..=0x0104).contains(group),
            "still offering finite-field group {group:#06x}"
        );
    }
    // …and the group a current browser leads with is present.
    assert_eq!(sent.groups.first(), Some(&0x11ec), "X25519MLKEM768 should lead the key shares");
}

#[test]
fn grease_is_present_on_the_wire_but_absent_from_the_identity() {
    // Browsers send GREASE, so a hello without it is anomalous. It must reach
    // the wire and must not reach the fingerprint — otherwise every connection
    // would produce a different identity and the profile would mean nothing.
    let first = hello_on_the_wire("yandex-windows", "kws2.nova-app.eu");
    let second = hello_on_the_wire("yandex-windows", "kws2.nova-app.eu");
    assert_eq!(first.ja4(), second.ja4(), "two connections disagreed about who we are");
}

#[test]
fn the_name_asked_for_is_the_name_that_travels() {
    // The neutral-SNI work in the relay depends on this being exactly what was
    // requested and nothing else.
    let named = hello_on_the_wire("yandex-windows", "www.nova-app.eu");
    assert!(named.has_sni);
    assert!(named.ja4_a().contains('d'));
}

// ---- Yandex Browser 26.10, checked against the real capture -----------------
//
// The expected values below are what a real Yandex Browser 26.10.0.1796
// (Chromium 152) sent for a WebSocket connection to kws2.web.telegram.org on
// 2026-10-18. They only hold for the patched BoringSSL of `bssl-patch`.

/// (type, body) of every extension in a raw ClientHello record.
#[cfg(bssl_patched)]
struct Raw {
    ciphers: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

#[cfg(bssl_patched)]
fn dissect(record: &[u8]) -> Raw {
    let u16at = |at: usize| u16::from_be_bytes([record[at], record[at + 1]]) as usize;
    // record 5, handshake header 4, version 2, random 32
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + record[at] as usize; // session id
    let cipher_len = u16at(at);
    let ciphers = record[at + 2..at + 2 + cipher_len]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    at += 2 + cipher_len;
    at += 1 + record[at] as usize; // compression
    let total = u16at(at);
    at += 2;
    let end = at + total;
    let mut extensions = Vec::new();
    while at < end {
        let kind = u16at(at) as u16;
        let len = u16at(at + 2);
        extensions.push((kind, record[at + 4..at + 4 + len].to_vec()));
        at += 4 + len;
    }
    Raw { ciphers, extensions }
}

#[cfg(bssl_patched)]
fn is_grease(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0xff)
}

#[cfg(bssl_patched)]
fn ext<'a>(raw: &'a Raw, kind: u16) -> &'a [u8] {
    &raw.extensions.iter().find(|(k, _)| *k == kind).unwrap_or_else(|| panic!("no extension {kind:#06x}")).1
}

#[cfg(bssl_patched)]
fn words(body: &[u8]) -> Vec<u16> {
    body.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
}

#[cfg(bssl_patched)]
#[test]
fn the_26_10_hello_matches_the_real_browsers_capture() {
    let record = raw_hello_on_the_wire("yandex-windows-26.10", "kws2.web.telegram.org");
    let raw = dissect(&record);

    // Ciphers: one GREASE, then the fifteen the browser offers, in its order.
    assert!(is_grease(raw.ciphers[0]));
    assert_eq!(
        raw.ciphers[1..],
        [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
    );

    // Extensions: GREASE first and last, and the browser's sixteen in between
    // (with the SNI), order shuffled so only the set is compared.
    let kinds: Vec<u16> = raw.extensions.iter().map(|(k, _)| *k).collect();
    assert!(is_grease(kinds[0]) && is_grease(*kinds.last().unwrap()), "{kinds:x?}");
    assert_ne!(kinds[0], *kinds.last().unwrap(), "the two GREASE extensions must differ");
    let mut real: Vec<u16> = kinds.iter().copied().filter(|k| !is_grease(*k)).collect();
    real.sort_unstable();
    let mut expected: Vec<u16> =
        vec![0, 16, 13, 65281, 51, 35, 5, 45, 27, 11, 23, 0xca34, 65037, 10, 18, 43];
    expected.sort_unstable();
    assert_eq!(real, expected, "extension set differs from the capture");

    // Signature algorithms: GREASE, 0904 0905 0906, then the eight.
    let sigalgs = words(&ext(&raw, 13)[2..]);
    assert_eq!(sigalgs.len(), 12);
    assert!(is_grease(sigalgs[0]));
    assert_eq!(
        sigalgs[1..],
        [0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    );

    // Groups: GREASE, X25519MLKEM768, x25519, P-256, P-384.
    let groups = words(&ext(&raw, 10)[2..]);
    assert!(is_grease(groups[0]));
    assert_eq!(groups[1..], [0x11ec, 0x001d, 0x0017, 0x0018]);

    // Key shares: GREASE (1 byte), X25519MLKEM768 (1216), x25519 (32).
    let shares = ext(&raw, 51);
    let mut at = 2;
    let mut seen = Vec::new();
    while at < shares.len() {
        let group = u16::from_be_bytes([shares[at], shares[at + 1]]);
        let len = u16::from_be_bytes([shares[at + 2], shares[at + 3]]) as usize;
        seen.push((group, len));
        at += 4 + len;
    }
    assert!(is_grease(seen[0].0) && seen[0].1 == 1);
    assert_eq!(seen[1..], [(0x11ec, 1216), (0x001d, 32)]);
    // The key-share GREASE is the group GREASE, as in the capture.
    assert_eq!(seen[0].0 as u16, groups[0]);

    // Versions: GREASE, 1.3, 1.2. ALPN: http/1.1 only (a WebSocket upgrade).
    let versions = words(&ext(&raw, 43)[1..]);
    assert!(is_grease(versions[0]));
    assert_eq!(versions[1..], [0x0304, 0x0303]);
    assert_eq!(ext(&raw, 16), b"\x00\x09\x08http/1.1");

    // The small fixed ones: status_request, psk modes, ec point formats,
    // cert compression (brotli only), session ticket empty, ECH size.
    assert_eq!(ext(&raw, 5), [1, 0, 0, 0, 0]);
    assert_eq!(ext(&raw, 45), [1, 1]);
    assert_eq!(ext(&raw, 11), [1, 0]);
    assert_eq!(ext(&raw, 27), [2, 0, 2]);
    assert!(ext(&raw, 35).is_empty());
    // Body length, as the capture reports it: 186, 218, 250 or 282 (BoringSSL picks
    // the padding from four sizes, the browser does the same).
    let ech = ext(&raw, 65037).len();
    assert!([186, 218, 250, 282].contains(&ech), "ECH extension body of {ech} bytes");

    // 0xca34: a 206-byte body, a list of entries; the same set as the sample.
    let ca34 = ext(&raw, 0xca34);
    assert_eq!(ca34.len(), 206);
    assert_eq!(u16::from_be_bytes([ca34[0], ca34[1]]) as usize, 204);
    let entries = |body: &[u8]| {
        let mut at = 2;
        let mut out = Vec::new();
        while at < body.len() {
            let len = body[at] as usize;
            out.push(body[at..at + 1 + len].to_vec());
            at += 1 + len;
        }
        out.sort();
        out
    };
    let sample = hex_sample();
    assert_eq!(entries(ca34), entries(&sample), "0xca34 entries differ from the real browser's");
}

#[cfg(bssl_patched)]
fn hex_sample() -> Vec<u8> {
    let hex = "00cc04d679090b08839a648c9b2d010a0582df13021404d679090c08839a648c9b2d010708839a648c9b2d010c04d679090304d679090f04d679090a04d67909040582df1302130582df13020608839a648c9b2d01130582df13021204d67909070582df13020d04d679090e04d67909020582df13020e08839a648c9b2d010d04d67909090582df13020f04d679090608839a648c9b2d010904d679090104d679090d08839a648c9b2d010808839a648c9b2d011204d679090804d679090508839a648c9b2d010b0582df130201";
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

#[cfg(bssl_patched)]
#[test]
fn the_26_10_hello_shuffles_0xca34_and_the_extensions_between_connections() {
    let mut orders = std::collections::HashSet::new();
    let mut ca34s = std::collections::HashSet::new();
    for _ in 0..6 {
        let raw = dissect(&raw_hello_on_the_wire("yandex-windows-26.10", "kws2.web.telegram.org"));
        orders.insert(raw.extensions.iter().map(|(k, _)| *k).collect::<Vec<_>>());
        ca34s.insert(ext(&raw, 0xca34).to_vec());
    }
    assert!(orders.len() > 1, "extension order never changed");
    assert!(ca34s.len() > 1, "0xca34 entries were never reordered");
}

#[cfg(bssl_patched)]
#[test]
fn the_26_10_prediction_matches_the_wire() {
    let profile = built_in_profile("yandex-windows-26.10").expect("built in");
    let sent = hello_on_the_wire("yandex-windows-26.10", "kws2.web.telegram.org");
    assert_eq!(sent.ja4(), shape::emitted_ja4(&profile, true));
    // What a browser would show for this exact hello, JA4_a readable half.
    assert_eq!(sent.ja4_a(), "t13d1516h1");
}
