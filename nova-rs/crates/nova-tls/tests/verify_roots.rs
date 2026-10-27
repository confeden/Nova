//! Certificate verification in the terminator, end to end.
//!
//! A throwaway CA and leaf are generated in-process, a loopback TLS server
//! presents the leaf, and the real `tls-terminator` binary is driven through
//! its JSON-line protocol. Offline; nothing outside 127.0.0.1 is touched.
//!
//! ```text
//! cargo test -p nova-tls --features shape --test verify_roots
//! ```
#![cfg(feature = "shape")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private};
use boring::rsa::Rsa;
use boring::ssl::{SslAcceptor, SslMethod};
use boring::x509::extension::{BasicConstraints, SubjectAlternativeName};
use boring::x509::{X509NameBuilder, X509};

const TOKEN: &str = "test-token";

struct Pki {
    ca_pem: Vec<u8>,
    leaf: X509,
    leaf_key: PKey<Private>,
}

fn name(cn: &str) -> boring::x509::X509Name {
    let mut b = X509NameBuilder::new().unwrap();
    b.append_entry_by_text("CN", cn).unwrap();
    b.build()
}

fn make_ca(cn: &str) -> (X509, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name(cn)).unwrap();
    b.set_issuer_name(&name(cn)).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(2).unwrap()).unwrap();
    b.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build(), key)
}

fn make_pki(host: &str) -> Pki {
    let (ca, ca_key) = make_ca("Test CA");
    let leaf_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let serial = BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap();
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name(host)).unwrap();
    b.set_issuer_name(ca.subject_name()).unwrap();
    b.set_pubkey(&leaf_key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(2).unwrap()).unwrap();
    let san = SubjectAlternativeName::new().dns(host).build(&b.x509v3_context(Some(&ca), None)).unwrap();
    b.append_extension(san).unwrap();
    b.sign(&ca_key, MessageDigest::sha256()).unwrap();
    Pki { ca_pem: ca.to_pem().unwrap(), leaf: b.build(), leaf_key }
}

/// Accepts connections forever, answering each with `hello` after the handshake.
fn serve_tls(pki: &Pki) -> u16 {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    acceptor.set_private_key(&pki.leaf_key).unwrap();
    acceptor.set_certificate(&pki.leaf).unwrap();
    let acceptor = acceptor.build();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let acceptor = acceptor.clone();
            std::thread::spawn(move || {
                if let Ok(mut tls) = acceptor.accept(stream) {
                    let _ = tls.write_all(b"hello");
                    let _ = tls.flush();
                    let mut sink = [0u8; 16];
                    let _ = tls.read(&mut sink);
                }
            });
        }
    });
    port
}

struct Terminator {
    child: Child,
    port: u16,
}

impl Drop for Terminator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_terminator() -> Terminator {
    // Reserve a free port, release it, hand it over. Racy in theory only.
    let port = TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    let child = Command::new(env!("CARGO_BIN_EXE_tls-terminator"))
        .args(["--token", TOKEN, "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("terminator starts");
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Terminator { child, port };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("terminator never listened");
}

/// One tunnel request; returns the reply line and, on success, the first bytes.
fn tunnel(t: &Terminator, upstream: u16, sni: &str, extra: serde_json::Value) -> (serde_json::Value, Vec<u8>) {
    let stream = TcpStream::connect(("127.0.0.1", t.port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut greeting = String::new();
    reader.read_line(&mut greeting).unwrap();
    assert!(greeting.contains("tls-terminator/1"));
    let mut request = serde_json::json!({
        "token": TOKEN,
        "target": {"host": "127.0.0.1", "port": upstream},
        "egress": {"kind": "direct"},
        "sni": sni,
        "profile": "yandex-windows",
    });
    for (k, v) in extra.as_object().unwrap() {
        request[k] = v.clone();
    }
    let mut writer = stream;
    writeln!(writer, "{request}").unwrap();
    let mut reply = String::new();
    reader.read_line(&mut reply).unwrap();
    let reply: serde_json::Value = serde_json::from_str(&reply).expect("reply is json");
    let mut body = Vec::new();
    if reply["ok"] == true {
        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf).unwrap();
        body.extend_from_slice(&buf);
    }
    (reply, body)
}

fn write_pem(tag: &str, pem: &[u8]) -> String {
    let path = std::env::temp_dir().join(format!("nova-tls-verify-{}-{tag}.pem", std::process::id()));
    std::fs::write(&path, pem).unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn verification_accepts_a_pinned_root_and_the_matching_name() {
    let pki = make_pki("good.test");
    let upstream = serve_tls(&pki);
    let t = start_terminator();
    let roots = write_pem("good", &pki.ca_pem);
    let (reply, body) = tunnel(&t, upstream, "good.test", serde_json::json!({"verify_roots": roots}));
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(body, b"hello");
}

#[test]
fn verification_rejects_a_name_the_certificate_does_not_cover() {
    let pki = make_pki("good.test");
    let upstream = serve_tls(&pki);
    let t = start_terminator();
    let roots = write_pem("name", &pki.ca_pem);
    let (reply, _) = tunnel(&t, upstream, "evil.test", serde_json::json!({"verify_roots": roots}));
    assert_eq!(reply["ok"], false, "{reply}");
    assert_eq!(reply["ended"], 5, "{reply}");
    assert!(reply["error"].as_str().unwrap().contains("certificate verification failed"), "{reply}");
}

#[test]
fn verification_rejects_a_chain_that_does_not_end_in_the_pinned_roots() {
    let pki = make_pki("good.test");
    let other = make_pki("good.test");
    let upstream = serve_tls(&pki);
    let t = start_terminator();
    let roots = write_pem("other", &other.ca_pem);
    let (reply, _) = tunnel(&t, upstream, "good.test", serde_json::json!({"verify_roots": roots}));
    assert_eq!(reply["ok"], false, "{reply}");
    assert_eq!(reply["ended"], 5, "{reply}");
}

#[test]
fn verify_without_any_roots_fails_closed() {
    // No system store on Windows, and none is guaranteed elsewhere: a request
    // that asks for verification must not quietly succeed.
    let pki = make_pki("good.test");
    let upstream = serve_tls(&pki);
    let t = start_terminator();
    let (reply, _) = tunnel(&t, upstream, "good.test", serde_json::json!({"verify": true}));
    assert_eq!(reply["ok"], false, "{reply}");
}

#[test]
fn an_unreadable_or_empty_roots_file_is_a_clear_failure_not_a_pass() {
    let pki = make_pki("good.test");
    let upstream = serve_tls(&pki);
    let t = start_terminator();
    let (reply, _) = tunnel(&t, upstream, "good.test", serde_json::json!({"verify_roots": "Z:/no/such/roots.pem"}));
    assert_eq!(reply["ok"], false);
    assert!(reply["error"].as_str().unwrap().contains("verify_roots"), "{reply}");
    let empty = write_pem("empty", b"not a certificate\n");
    let (reply, _) = tunnel(&t, upstream, "good.test", serde_json::json!({"verify_roots": empty}));
    assert_eq!(reply["ok"], false, "{reply}");
}

#[test]
fn without_verify_the_old_behaviour_is_unchanged() {
    let pki = make_pki("good.test");
    let upstream = serve_tls(&pki);
    let t = start_terminator();
    let (reply, body) = tunnel(&t, upstream, "anything.test", serde_json::json!({}));
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(body, b"hello");
}
