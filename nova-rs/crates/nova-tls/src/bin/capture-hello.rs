//! Ground truth: what a browser on *this* machine actually sends.
//!
//! Profiles cannot be written from memory and cannot be taken from `fake/` —
//! that corpus turned out to be templated decoys sharing one fingerprint (see
//! `tests/corpus.rs`). The only trustworthy source is a browser that is really
//! running, on the operating system Nova runs on, in the version the user has.
//!
//! No TLS library is needed to collect it. The ClientHello is the first thing
//! the client sends and it is not encrypted — so this listens on a plain TCP
//! socket, reads the first record, prints the fingerprint and hangs up. The
//! browser will report a failed connection, which is expected and harmless:
//! the handshake is deliberately never completed, so nothing is ever served,
//! and no certificate is needed.
//!
//! ```text
//! cargo run -p nova-tls --bin capture-hello
//! ```
//!
//! Then open `https://127.0.0.1:8443/` in the browser to be measured. Add
//! `--out <dir>` to keep the raw bytes for a regression test.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use nova_tls::{Profile, parse_client_hello};

fn main() {
    let mut port = 8443u16;
    let mut out: Option<PathBuf> = None;
    let mut label = String::from("capture");

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(8443);
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--name" if i + 1 < args.len() => {
                label = args[i + 1].clone();
                i += 2;
            }
            "--help" | "-h" => {
                println!("usage: capture-hello [--port 8443] [--name chrome-windows] [--out dir]");
                return;
            }
            other => {
                eprintln!("unknown argument {other:?}; try --help");
                return;
            }
        }
    }

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("cannot listen on 127.0.0.1:{port}: {err}");
            std::process::exit(1);
        }
    };

    println!("Listening on https://127.0.0.1:{port}/");
    println!("Open that address in the browser you want to measure.");
    println!("The browser will report a connection error — that is expected;");
    println!("the handshake is never completed and nothing is served.\n");
    println!("Ctrl-C to stop.\n");

    let mut seen = 0usize;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                seen += 1;
                handle(stream, &label, seen, out.as_deref());
            }
            Err(err) => eprintln!("accept failed: {err}"),
        }
    }
}

fn handle(mut stream: TcpStream, label: &str, index: usize, out: Option<&std::path::Path>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = vec![0u8; 16 * 1024];
    let mut filled = 0usize;

    // Read until the declared record is complete, or the peer stops talking. A
    // large ClientHello can arrive split across several segments, and judging
    // it on the first one would measure the network rather than the browser.
    loop {
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
                if filled == buf.len() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = stream.write_all(b"");
    drop(stream);

    let bytes = &buf[..filled];
    println!("--- connection {index} ({filled} bytes) ---");

    // A browser pointed at `http://` rather than `https://` sends its request
    // in the clear. That is the only way to measure the headers that belong
    // with a TLS profile — the handshake here never completes, so nothing
    // encrypted ever arrives — and inventing a User-Agent to pair with a
    // measured ClientHello would put a build string on the wire that may never
    // have shipped, which is a worse tell than the one being fixed.
    if bytes.starts_with(b"GET ") || bytes.starts_with(b"POST ") || bytes.starts_with(b"HEAD ") {
        println!("  plain HTTP — headers as sent, in order:");
        for line in String::from_utf8_lossy(bytes).lines() {
            if line.trim().is_empty() {
                break;
            }
            println!("    {line}");
        }
        println!();
        return;
    }

    match parse_client_hello(bytes) {
        Ok(hello) => {
            println!("  ja4        {}", hello.ja4());
            println!("  readable   {}", hello.ja4_a());
            println!("  ciphers    {}", hello.ciphers.len());
            println!("  extensions {}", hello.extensions.len());
            println!("  alpn       {:?}", hello.alpn);
            println!("  sni        {}", if hello.has_sni { "present" } else { "absent" });
            match Profile::from_capture(label, bytes) {
                Ok(profile) => match serde_json::to_string_pretty(&profile) {
                    Ok(json) => {
                        if let Some(dir) = out {
                            write_artifacts(dir, label, index, bytes, &json);
                        } else {
                            println!("\n{json}\n");
                        }
                    }
                    Err(err) => eprintln!("  could not serialise profile: {err}"),
                },
                Err(err) => eprintln!("  could not build profile: {err}"),
            }
        }
        Err(err) => println!("  not a ClientHello: {err}"),
    }
    println!();
}

fn write_artifacts(dir: &std::path::Path, label: &str, index: usize, bytes: &[u8], json: &str) {
    if let Err(err) = std::fs::create_dir_all(dir) {
        eprintln!("  cannot create {}: {err}", dir.display());
        return;
    }
    let raw = dir.join(format!("{label}-{index}.clienthello.bin"));
    let profile = dir.join(format!("{label}-{index}.profile.json"));
    if let Err(err) = std::fs::write(&raw, bytes) {
        eprintln!("  cannot write {}: {err}", raw.display());
        return;
    }
    if let Err(err) = std::fs::write(&profile, json) {
        eprintln!("  cannot write {}: {err}", profile.display());
        return;
    }
    println!("  saved      {}", raw.display());
    println!("  saved      {}", profile.display());
}
