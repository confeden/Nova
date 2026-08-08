//! Fingerprint ClientHello files that are already on disk.
//!
//! The companion to `capture-hello`: that one collects, this one reads. Useful
//! for checking that a browser produces one stable identity across many
//! connections — if it does not, the parser is letting something random through
//! and the whole measurement is noise.
//!
//! ```text
//! cargo run -p nova-tls --bin ja4 -- path/to/*.bin
//! ```

use std::collections::BTreeMap;

use nova_tls::parse_client_hello;

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: ja4 <file>...");
        std::process::exit(2);
    }

    let mut by_fingerprint: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unreadable = Vec::new();

    for path in &paths {
        let name = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(path)
            .to_owned();
        match std::fs::read(path) {
            Ok(bytes) => match parse_client_hello(&bytes) {
                Ok(hello) => by_fingerprint.entry(hello.ja4()).or_default().push(name),
                Err(err) => unreadable.push(format!("{name}: {err}")),
            },
            Err(err) => unreadable.push(format!("{name}: {err}")),
        }
    }

    for (fingerprint, mut files) in by_fingerprint {
        files.sort();
        println!("{fingerprint}  ({} file{})", files.len(), if files.len() == 1 { "" } else { "s" });
        for file in files {
            println!("    {file}");
        }
    }
    if !unreadable.is_empty() {
        println!("\nunreadable:");
        for line in unreadable {
            println!("    {line}");
        }
    }
}
