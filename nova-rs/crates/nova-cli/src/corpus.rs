//! Loading Nova's real on-disk data into the IR.
//!
//! Deliberately reads the *existing* `strat/*.json` and `fake/` layout rather
//! than a new Rust-native format. The Python app and this binary must see the
//! same files during the transition, or the two halves of Nova drift apart and
//! every observation made here stops being evidence about the real product.

use std::path::{Path, PathBuf};

use nova_core::StrategyId;
use nova_zapret::{Palette, Strategy, V1Emitter};

/// One strategy pool, e.g. `strat/general.json`.
pub struct Pool {
    pub name: String,
    pub strategies: Vec<Strategy>,
}

pub struct Corpus {
    pub root: PathBuf,
    /// Where `winws.exe` lives. Not `root/bin` — see [`Corpus::bin_dir`].
    pub bin: PathBuf,
    pub pools: Vec<Pool>,
    pub palette: Palette,
}

impl Corpus {
    /// Where the binaries live, which is not the same place in the two layouts
    /// this has to work in.
    ///
    /// A checkout keeps everything as siblings: `strat/`, `fake/`, `bin/`. An
    /// installed tree does not — `Inno.py` stages `strat`, `fake`, `ip` and
    /// `list` at `{app}` but copies `bin` to `{app}\resources\bin`
    /// (`TOP_LEVEL_DIRS` vs `RESOURCE_DIRS`), and the app itself agrees
    /// (`nova.pyw:get_bin_dir`). So `bin` is the one directory whose position
    /// depends on how Nova got onto the machine.
    pub fn bin_dir(root: &Path) -> PathBuf {
        let sibling = root.join("bin");
        if sibling.is_dir() {
            sibling
        } else {
            root.join("resources").join("bin")
        }
    }

    /// Walk up from the current directory looking for a Nova tree.
    ///
    /// The anchor is `strat/`, plus a `bin` in either of its two possible
    /// positions. Requiring `bin` to be a *sibling* of `strat` — as this did —
    /// recognises a checkout and nothing else: on an installed tree the search
    /// walked to the filesystem root, returned `None`, and the binary exited 2
    /// before doing anything. Nothing caught it because nova-cli ships nowhere
    /// yet, and it would have failed on the first machine it reached.
    pub fn find_root() -> Option<PathBuf> {
        let start = std::env::current_dir().ok()?;
        start
            .ancestors()
            .find(|dir| dir.join("strat").is_dir() && Self::bin_dir(dir).is_dir())
            .map(Path::to_path_buf)
    }

    pub fn load(root: &Path) -> Result<Self, String> {
        let strat_dir = root.join("strat");
        let entries = std::fs::read_dir(&strat_dir).map_err(|e| format!("{}: {e}", strat_dir.display()))?;

        let mut pools = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let name = path.file_stem().unwrap_or_default().to_string_lossy().into_owned();
            let raw = match std::fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(_) => continue,
            };
            let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) else { continue };
            let Some(list) = json.get("strategies").and_then(|s| s.as_array()) else { continue };

            let mut strategies = Vec::new();
            for item in list {
                let sname = item.get("name").and_then(|n| n.as_str()).unwrap_or("<unnamed>");
                let Some(args) = item.get("args").and_then(|a| a.as_array()) else { continue };
                let args: Vec<String> = args.iter().filter_map(|a| a.as_str()).map(str::to_owned).collect();
                // Only the first `--new` section carries the TCP profile, which
                // is what evolution operates on; later sections are the UDP/QUIC
                // companions and are carried along unchanged by the emitter.
                let Some(section) = V1Emitter::split_profiles(&args).into_iter().next() else { continue };
                if let Ok(parsed) = V1Emitter::parse_profile(StrategyId::new(sname), &section) {
                    // boost/ and warp/ entries are fragments appended to a base
                    // command line, so they carry no filter of their own and
                    // would not render standalone. Scaffold one for tooling.
                    strategies.push(parsed.as_standalone(&["80", "443"]));
                }
            }
            if !strategies.is_empty() {
                pools.push(Pool { name, strategies });
            }
        }
        pools.sort_by(|a, b| a.name.cmp(&b.name));

        let fake_names = std::fs::read_dir(root.join("fake"))
            .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect::<Vec<_>>())
            .unwrap_or_default();

        Ok(Corpus {
            root: root.to_path_buf(),
            bin: Self::bin_dir(root),
            pools,
            palette: Palette::from_fake_dir(fake_names),
        })
    }

    pub fn total_strategies(&self) -> usize {
        self.pools.iter().map(|p| p.strategies.len()).sum()
    }

    pub fn pool(&self, name: &str) -> Option<&Pool> {
        self.pools.iter().find(|p| p.name == name)
    }

    pub fn winws_path(&self) -> PathBuf {
        self.bin.join("winws.exe")
    }
}
