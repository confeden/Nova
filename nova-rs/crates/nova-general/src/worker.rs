use crate::{
    Result, backend, platform,
    policy::{self, Job, Kind, Observation, State},
    transport::*,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{VecDeque, hash_map::DefaultHasher},
    fs,
    hash::{Hash, Hasher},
    net::Ipv4Addr,
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Deserialize)]
struct Candidate {
    name: String,
    args: Vec<String>,
}
#[derive(Deserialize)]
struct Seed {
    strategies: Vec<Candidate>,
    #[serde(default)]
    probe_hints: Vec<String>,
}
const SEED: &str = include_str!("../assets/seed.json");
const PAYLOADS: [(&str, &[u8]); 7] = [
    ("stun.bin", include_bytes!("../assets/stun.bin")),
    ("stun2.bin", include_bytes!("../assets/stun2.bin")),
    ("tls_clienthello_4pda_to.bin", include_bytes!("../assets/tls_clienthello_4pda_to.bin")),
    ("tls_clienthello_sochi_park.bin", include_bytes!("../assets/tls_clienthello_sochi_park.bin")),
    ("tls_clienthello_www_google_com.bin", include_bytes!("../assets/tls_clienthello_www_google_com.bin")),
    ("tls_clienthello_www_sferum_ru.bin", include_bytes!("../assets/tls_clienthello_www_sferum_ru.bin")),
    ("tls_clienthello_yandex_kz.bin", include_bytes!("../assets/tls_clienthello_yandex_kz.bin")),
];
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
#[derive(Debug)]
struct Budget;
impl std::fmt::Display for Budget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("background request/body budget reached")
    }
}
impl std::error::Error for Budget {}
#[derive(Debug)]
struct NetworkChanged;
impl std::fmt::Display for NetworkChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("physical network changed")
    }
}
impl std::error::Error for NetworkChanged {}
fn state_file(cache: &Path) -> PathBuf {
    cache.join("state.json")
}
fn save(cache: &Path, state: &State) -> Result<()> {
    platform::atomic_json(&state_file(cache), &serde_json::to_value(state)?)
}
fn load(cache: &Path) -> Result<State> {
    match fs::read(state_file(cache)) {
        Ok(data) => {
            let s: State = serde_json::from_slice(&data)?;
            if s.schema != 1 {
                return Err("unsupported/corrupt general state schema".into());
            }
            Ok(s)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State { schema: 1, ..State::default() }),
        Err(e) => Err(e.into()),
    }
}
fn status(cache: &Path, phase: &str, extra: Value) -> Result<()> {
    platform::atomic_json(&cache.join("status.json"), &json!({"phase":phase,"at":now(),"detail":extra}))
}
fn assets(cache: &Path) -> Result<Vec<Candidate>> {
    let seed: Seed = serde_json::from_str(SEED.trim_start_matches('\u{feff}'))?;
    if seed.strategies.is_empty() || seed.strategies.len() > policy::MAX_CANDIDATES {
        return Err("seed exceeds 12 candidate limit".into());
    }
    fs::create_dir_all(cache.join("fake/flowseal"))?;
    for (name, bytes) in PAYLOADS {
        for directory in ["fake", "fake/flowseal"] {
            let path = cache.join(directory).join(name);
            if !path.is_file() || fs::read(&path)? != bytes {
                fs::write(path, bytes)?;
            }
        }
    }
    fs::write(cache.join("Flowseal-LICENSE.txt"), include_str!("../assets/Flowseal-LICENSE.txt"))?;
    let mut candidates = seed.strategies;
    for candidate in &mut candidates {
        for arg in &mut candidate.args {
            if !(arg.starts_with("--dpi-desync") || arg.starts_with("--ip-id=") || arg == "--filter-tcp=443") {
                return Err("unsafe seed option".into());
            }
            if let Some((flag, value)) = arg.split_once('=') {
                if value.starts_with("fake/") {
                    if value.contains("..") || value.contains('\\') || !cache.join(value).is_file() {
                        return Err("missing/unsafe seed payload".into());
                    }
                    *arg = format!("{flag}={}", cache.join(value).display());
                }
            }
        }
    }
    Ok(candidates)
}
struct Context<'a> {
    cache: &'a Path,
    bin: &'a Path,
    state: State,
    physical: platform::Physical,
    started: Instant,
    last_octets: u64,
    last_sample: Instant,
}
impl Context<'_> {
    fn transaction(
        &mut self,
        host: &str,
        ip: Ipv4Addr,
        path: &str,
        args: Option<&[String]>,
    ) -> Result<backend::Measurement> {
        loop {
            policy::roll_budget(&mut self.state, now());
            if self.state.requests >= policy::MAX_REQUESTS_PER_WINDOW
                || self.state.bytes >= policy::BODY_BUDGET
                || self.state.day_requests >= policy::DAILY_REQUESTS
            {
                return Err(Budget.into());
            }
            let current = platform::physical()?.ok_or("no physical uplink")?;
            if current.network != self.physical.network {
                return Err(NetworkChanged.into());
            }
            let bytes = platform::octets(current.binding.index)?;
            let elapsed = self.last_sample.elapsed().as_secs_f64().max(0.001);
            let busy = elapsed >= 0.5 && bytes.saturating_sub(self.last_octets) as f64 / elapsed > 256. * 1024.;
            if elapsed >= 0.5 {
                self.last_octets = bytes;
                self.last_sample = Instant::now();
            }
            if policy::should_probe(&self.state, now(), self.started.elapsed().as_secs(), busy)
                && !platform::foreign_test()?
            {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        self.state.requests += 1;
        self.state.day_requests += 1;
        self.state.last_probe = now();
        save(self.cache, &self.state)?;
        let result = backend::measure(self.bin, self.cache, self.physical.binding, host, ip, path, args)?;
        if !result.physical {
            return Err("physical packets not observed; no outcome scored".into());
        }
        if let Some(ref response) = result.response {
            self.state.bytes = self.state.bytes.saturating_add(response.body.len() as u64);
            status(
                self.cache,
                "response",
                json!({"domain":host,"http":response.code,"elapsed_ms":response.elapsed_ms,"body_limited":response.range_satisfied}),
            )?;
        }
        if let Some(ref error) = result.error {
            self.state.last_transport_error = Some(error.clone());
        }
        save(self.cache, &self.state)?;
        Ok(result)
    }
    fn resolve(&mut self, host: &str) -> Result<Ipv4Addr> {
        if host.len() > 253 || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
            return Err("invalid DNS name".into());
        }
        if let Some((ip, until)) = self.state.dns.get(host) {
            if *until > now() {
                let ip: Ipv4Addr = ip.parse()?;
                if public_ip(ip) {
                    return Ok(ip);
                }
            }
        }
        let mut last = "direct DoH unavailable".to_owned();
        for (server, ip, path) in [
            ("dns.google", Ipv4Addr::new(8, 8, 8, 8), format!("/resolve?name={host}&type=A")),
            ("cloudflare-dns.com", Ipv4Addr::new(1, 1, 1, 1), format!("/dns-query?name={host}&type=A")),
        ] {
            let result = self.transaction(server, ip, &path, None)?;
            let Some(response) = result.response else {
                last = "direct DNS TLS failed".into();
                continue;
            };
            if response.code != 200 {
                last = format!("direct DoH HTTP {}", response.code);
                continue;
            }
            let data: Value = serde_json::from_slice(&response.body)?;
            let old = self.state.dns.get(host).map(|(ip, _)| ip.as_str());
            let Some(answer) = data["Answer"].as_array().and_then(|a| {
                let valid = |a: &&Value| {
                    a["type"] == 1
                        && a["data"].as_str().and_then(|s| s.parse::<Ipv4Addr>().ok()).is_some_and(public_ip)
                };
                a.iter().filter(valid).find(|a| a["data"].as_str() == old).or_else(|| a.iter().find(|a| valid(a)))
            }) else {
                last = "DNS returned no public A record".into();
                continue;
            };
            let value = answer["data"].as_str().unwrap().to_owned();
            let ip: Ipv4Addr = value.parse()?;
            let ttl = answer["TTL"].as_u64().unwrap_or(300).clamp(60, 3600);
            if self.state.dns.get(host).is_some_and(|(old, _)| old != &value) {
                self.state.observations.retain(|o| o.domain != host);
            }
            self.state.dns.insert(host.into(), (value, now() + ttl));
            save(self.cache, &self.state)?;
            return Ok(ip);
        }
        Err(last.into())
    }
    fn document(&mut self, domain: &str, args: Option<&[String]>) -> Result<(bool, u16, u64)> {
        let mut host = domain.to_owned();
        let mut path = "/".to_owned();
        let mut bytes = 0;
        for _ in 0..4 {
            let ip = self.resolve(&host)?;
            let result = self.transaction(&host, ip, &path, args)?;
            let Some(response) = result.response else {
                return Ok((false, 0, bytes));
            };
            bytes += response.body.len() as u64;
            if (200..300).contains(&response.code) {
                return Ok((true, response.code, bytes));
            }
            if (300..400).contains(&response.code) {
                let location = response.location.ok_or("redirect without Location")?;
                let next = redirect(&host, &location)?;
                host = next.0;
                path = next.1;
                continue;
            }
            return Ok((false, response.code, bytes));
        }
        Err("HTTPS redirect limit reached".into())
    }
}
fn redirect(host: &str, location: &str) -> Result<(String, String)> {
    if location.contains(['\r', '\n']) {
        return Err("invalid redirect".into());
    }
    let rest =
        if let Some(rest) = location.strip_prefix("https://") { Some(rest) } else { location.strip_prefix("//") };
    if let Some(rest) = rest {
        let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
        if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
            return Err("unsupported redirect authority".into());
        }
        return Ok((host.to_ascii_lowercase(), path));
    }
    if location.starts_with('/') && !location.starts_with("//") {
        return Ok((host.into(), location.into()));
    }
    Err("non-HTTPS/unsupported redirect is not a successful site probe".into())
}
fn cache_path(root: &Path) -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is missing")?;
    let mut hash = DefaultHasher::new();
    root.as_os_str().hash(&mut hash);
    SEED.hash(&mut hash);
    Ok(PathBuf::from(local).join("Nova/GeneralProbe").join(format!("{:016x}", hash.finish())))
}
fn options() -> Result<(PathBuf, PathBuf, u32, bool)> {
    let args: Vec<_> = std::env::args_os().skip(2).collect();
    let mut root = None;
    let mut bin = None;
    let mut parent = None;
    let mut once = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].to_str() {
            Some("--root") => {
                i += 1;
                root = args.get(i).map(PathBuf::from)
            }
            Some("--bin-dir") => {
                i += 1;
                bin = args.get(i).map(PathBuf::from)
            }
            Some("--parent") => {
                i += 1;
                parent = Some(
                    args.get(i).ok_or("parent PID value missing")?.to_str().ok_or("invalid parent PID")?.parse()?,
                )
            }
            Some("--once") => once = true,
            _ => return Err("unknown general-background option".into()),
        }
        i += 1;
    }
    let root = root.ok_or("Nova root is required")?;
    let bin = bin.unwrap_or_else(|| root.join("bin"));
    Ok((root, bin, parent.ok_or("parent PID required")?, once))
}
fn idle() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(30));
    }
}
pub(crate) fn run() -> Result<()> {
    let (root, bin, parent, once) = options()?;
    platform::watch_parent(parent)?;
    let cache = cache_path(&root)?;
    fs::create_dir_all(&cache)?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(cache.join("worker.lock"));
    let _lock = match lock {
        Ok(lock) => lock,
        Err(e) if e.raw_os_error() == Some(32) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let result = run_inner(&root, &bin, &cache, once);
    if let Err(ref error) = result {
        status(&cache, "failed", json!({"error":error.to_string(),"active_strategy_changed":false}))?;
    }
    result
}
fn run_inner(root: &Path, bin: &Path, cache: &Path, once: bool) -> Result<()> {
    for file in ["winws.exe", "WinDivert.dll", "WinDivert64.sys", "cygwin1.dll"] {
        if !bin.join(file).is_file() {
            return Err(format!("missing winws prerequisite: {file}").into());
        }
    }
    if !backend::elevated()? {
        return Err("administrator token required for verified packet capture".into());
    }
    let candidates = assets(cache)?;
    let names: Vec<_> = candidates.iter().map(|c| c.name.clone()).collect();
    let mut rkn = policy::domains(&fs::read_to_string(root.join("list/rkn.txt"))?);
    let seed: Seed = serde_json::from_str(SEED.trim_start_matches('\u{feff}'))?;
    rkn.sort_by_key(|domain| seed.probe_hints.iter().position(|hint| hint == domain).unwrap_or(usize::MAX));
    let mut state = load(cache)?;
    println!("{}", json!({"ready":true,"protocol":1,"max_candidates":policy::MAX_CANDIDATES}));
    let physical = loop {
        if let Some(p) = platform::physical()? {
            break p;
        }
        status(cache, "waiting_physical_interface", json!({}))?;
        std::thread::sleep(Duration::from_secs(5));
    };
    let network = format!("{:016x}", physical.network);
    if state.network != network {
        state = State { schema: 1, network, ..State::default() };
    }
    policy::roll_budget(&mut state, now());
    policy::retain(&mut state, now());
    save(cache, &state)?;
    status(
        cache,
        "startup_delay",
        json!({"delay_seconds":policy::STARTUP_DELAY,"max_candidates":12,"rkn_domains":rkn.len(),"youtube_required":true}),
    )?;
    let initial_octets = platform::octets(physical.binding.index)?;
    let mut context = Context {
        cache,
        bin,
        state,
        physical,
        started: Instant::now(),
        last_octets: initial_octets,
        last_sample: Instant::now(),
    };
    let mut jobs: VecDeque<_> = policy::plan(&names, &rkn, &context.state, now()).into();
    let mut completed = 0;
    while let Some(job) = jobs.pop_front() {
        if !job.baseline && job.kind == Kind::Rkn && !policy::blocked_once(&context.state, &job.domain, now()) {
            continue;
        }
        let candidate = candidates.iter().find(|c| c.name == job.candidate);
        let args =
            if job.baseline { None } else { Some(candidate.ok_or("unknown scheduled profile")?.args.as_slice()) };
        status(
            cache,
            "checking",
            json!({"candidate":job.candidate,"domain":job.domain,"requests":context.state.requests,"remaining_jobs":jobs.len()}),
        )?;
        match context.document(&job.domain, args) {
            Ok((opened, http, bytes)) => {
                context.state.observations.push(Observation {
                    candidate: job.candidate.clone(),
                    domain: job.domain.clone(),
                    kind: job.kind.clone(),
                    baseline: job.baseline,
                    at: now(),
                    physical: true,
                    opened,
                    http,
                    body_bytes: bytes,
                });
                if !job.baseline
                    && job.kind == Kind::Rkn
                    && opened
                    && !policy::eligible_rkn(&context.state, &job.domain, now())
                {
                    for _ in policy::baseline_failures(&context.state, &job.domain, now())..2 {
                        jobs.push_front(Job {
                            candidate: "baseline".into(),
                            domain: job.domain.clone(),
                            kind: Kind::Rkn,
                            baseline: true,
                        });
                    }
                }
                context.state.recommended = policy::recommendation(&context.state, now());
                policy::retain(&mut context.state, now());
                save(cache, &context.state)?;
                completed += 1;
                status(
                    cache,
                    "checked",
                    json!({"candidate":job.candidate,"domain":job.domain,"opened":opened,"requests":context.state.requests,"recommended":context.state.recommended,"active_strategy_changed":false}),
                )?;
                if once {
                    return Ok(());
                }
            }
            Err(error) if error.downcast_ref::<Budget>().is_some() => {
                status(
                    cache,
                    "budget_idle",
                    json!({"requests":context.state.requests,"bytes":context.state.bytes,"day_requests":context.state.day_requests,"retry_after_seconds":policy::next_window(&context.state,now())}),
                )?;
                if once {
                    return Ok(());
                }
                jobs.push_front(job);
                std::thread::sleep(Duration::from_secs(policy::next_window(&context.state, now()).clamp(1, 60)));
            }
            Err(error) if error.downcast_ref::<NetworkChanged>().is_some() => {
                status(cache, "network_changed_idle", json!({"resume_next_start":true,"scored":false}))?;
                idle();
            }
            Err(error) => {
                status(cache, "paused", json!({"error":error.to_string(),"scored":false,"retry_seconds":60}))?;
                if once {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_secs(60));
                jobs.push_back(job);
            }
        }
    }
    context.state.cursor = context.state.cursor.saturating_add(3);
    save(cache, &context.state)?;
    status(
        cache,
        "cycle_idle",
        json!({"checked":completed,"recommended":context.state.recommended,"active_strategy_changed":false}),
    )?;
    if once { Ok(()) } else { idle() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redirects_never_downgrade_or_target_local_authorities() {
        assert_eq!(redirect("a.org", "https://www.a.org/path").unwrap(), ("www.a.org".into(), "/path".into()));
        assert!(redirect("a.org", "http://a.org/").is_err());
        assert!(redirect("a.org", "https://localhost:444/").is_err());
        assert!(redirect("a.org", "/\r\nheader").is_err());
    }
    #[test]
    fn shipped_palette_has_at_most_twelve_profiles_and_available_payloads() {
        let seed: Seed = serde_json::from_str(SEED.trim_start_matches('\u{feff}')).unwrap();
        assert_eq!(seed.strategies.len(), 12);
        for c in seed.strategies {
            for a in c.args {
                if let Some((_, v)) = a.split_once('=') {
                    if v.starts_with("fake/") {
                        let name = Path::new(v).file_name().unwrap().to_str().unwrap();
                        assert!(PAYLOADS.iter().any(|(n, _)| *n == name));
                    }
                }
            }
        }
    }
}
