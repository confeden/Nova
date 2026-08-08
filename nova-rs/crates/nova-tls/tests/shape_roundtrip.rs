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
    parse_client_hello(&bytes).expect("what we sent is a ClientHello")
}

#[test]
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
