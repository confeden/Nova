//! Ground-truth validation of a generated strategy against the real binary.
//!
//! `winws --dry-run` parses the whole command line, builds the WinDivert filter
//! and exits 0 without touching the driver or the network. That makes it an
//! exact, free oracle for "would this strategy start", and it is the only step
//! between generation and spending a network probe that can reject a candidate
//! with certainty.
//!
//! Everything cheaper than this (structural constraints, novelty) runs first;
//! everything more expensive (an actual probe) runs only on survivors.

use std::path::{Path, PathBuf};
use std::process::Command;

use nova_zapret::{Emitter, Strategy, V1Emitter};

pub struct Validator {
    winws: PathBuf,
    cwd: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Rejected {
        reason: String,
    },
    /// The binary could not be run at all — not the candidate's fault.
    Unavailable {
        reason: String,
    },
}

impl Validator {
    pub fn new(winws: impl Into<PathBuf>, cwd: impl Into<PathBuf>) -> Self {
        Self { winws: winws.into(), cwd: cwd.into() }
    }

    pub fn is_available(&self) -> bool {
        self.winws.is_file()
    }

    /// Run one candidate through `--dry-run`.
    pub fn check(&self, strategy: &Strategy) -> Verdict {
        let strategy = &strategy.as_standalone(&["80", "443"]);
        let Ok(mut argv) = V1Emitter.emit_profile(strategy) else {
            return Verdict::Rejected { reason: "not emittable".to_owned() };
        };

        // --dry-run still insists on a WindiVert filter, so supply one derived
        // from the profile's own port filter. It is discarded with the process.
        let ports = if strategy.filter.tcp_ports.is_empty() {
            "80,443".to_owned()
        } else {
            strategy.filter.tcp_ports.join(",")
        };
        let mut full = vec!["--dry-run".to_owned(), format!("--wf-tcp={ports}")];
        full.append(&mut argv);

        match Command::new(&self.winws).args(&full).current_dir(&self.cwd).output() {
            Ok(out) if out.status.success() => Verdict::Accepted,
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stderr);
                let text = if text.trim().is_empty() { String::from_utf8_lossy(&out.stdout) } else { text };
                let reason = text
                    .lines()
                    .find(|l| {
                        let l = l.to_ascii_lowercase();
                        l.contains("invalid") || l.contains("error") || l.contains("unknown") || l.contains("bad")
                    })
                    .unwrap_or_else(|| text.lines().last().unwrap_or("unknown"))
                    .trim()
                    .to_owned();
                Verdict::Rejected { reason }
            }
            Err(e) => Verdict::Unavailable { reason: e.to_string() },
        }
    }

    pub fn winws_path(&self) -> &Path {
        &self.winws
    }

    /// Measure which TLS blobs winws is able to modify.
    ///
    /// One `--dry-run` per blob, no network. Roughly 20 ms each, so the whole
    /// palette costs a second or two — paid once, and it removes a class of
    /// candidate that would otherwise be generated, validated and thrown away
    /// forever. Measuring beats a hard-coded list because the blob set is data
    /// that ships and changes.
    pub fn measure_moddable_tls(&self, blobs: &[String]) -> std::collections::BTreeSet<String> {
        blobs
            .iter()
            .filter(|blob| {
                let args = [
                    "--dry-run",
                    "--wf-tcp=443",
                    "--filter-tcp=443",
                    "--dpi-desync=multisplit",
                    "--dpi-desync-fake-tls-mod=rnd",
                ];
                let fake = format!("--dpi-desync-fake-tls=@fake/{blob}");
                Command::new(&self.winws)
                    .args(args)
                    .arg(&fake)
                    .current_dir(&self.cwd)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }
}
