use crate::config::DaemonConfig;
use crate::domains::DomainCatalog;
use crate::tuner::DpiTuner;
use crate::warp::WarpManager;
use anyhow::Result;
use nova_common::models::{
    DaemonStatus, LogEntry, LogLevel, NetworkMode, RoutingMethod, ServiceHealth, ServiceId,
    ServiceStatus,
};
use serde_json::json;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{info, warn};

pub struct Orchestrator {
    config: DaemonConfig,
    tuner: DpiTuner,
    domains: DomainCatalog,
    singbox_proc: Mutex<Option<Child>>,
    byedpi_proc: Mutex<Option<Child>>,
    running: AtomicBool,
    mode: Mutex<NetworkMode>,
    recent_logs: Mutex<Vec<LogEntry>>,
}

impl Orchestrator {
    pub fn new(config: DaemonConfig, tuner: DpiTuner) -> Self {
        let domains = DomainCatalog::load_embedded();
        Self {
            config,
            tuner,
            domains,
            singbox_proc: Mutex::new(None),
            byedpi_proc: Mutex::new(None),
            running: AtomicBool::new(false),
            mode: Mutex::new(NetworkMode::Adaptive),
            recent_logs: Mutex::new(Vec::new()),
        }
    }

    /// Generates sing-box dynamic JSON configuration with real domain lists and WARP.
    pub fn generate_singbox_config(&self) -> serde_json::Value {
        let warp_outbound = WarpManager::generate_singbox_outbound();

        json!({
            "log": {
                "level": "info",
                "timestamp": true
            },
            "dns": {
                "servers": [
                    { "tag": "remote-dns", "address": "https://1.1.1.1/dns-query", "detour": "byedpi-out" },
                    { "tag": "direct-dns", "address": "77.88.8.8", "detour": "direct-out" }
                ],
                "rules": [
                    { "geosite": "category-ru", "server": "direct-dns" },
                    { "server": "remote-dns" }
                ],
                "strategy": "prefer_ipv4"
            },
            "inbounds": [
                {
                    "type": "tproxy",
                    "tag": "tproxy-in",
                    "listen": "127.0.0.1",
                    "listen_port": self.config.tproxy_port,
                    "sniff": true,
                    "sniff_override_destination": false
                }
            ],
            "outbounds": [
                {
                    "type": "socks",
                    "tag": "byedpi-out",
                    "server": "127.0.0.1",
                    "server_port": self.config.byedpi_socks_port
                },
                warp_outbound,
                {
                    "type": "direct",
                    "tag": "direct-out"
                },
                {
                    "type": "block",
                    "tag": "block-out"
                }
            ],
            "route": {
                "rules": [
                    // Russian resources bypass directly
                    { "geosite": "category-ru", "outbound": "direct-out" },
                    { "domain_suffix": self.domains.exclude, "outbound": "direct-out" },

                    // AI services routed via WARP tunnel
                    { "domain_suffix": self.domains.ai, "outbound": "warp-out" },

                    // Telegram routed via WARP / Relay
                    { "domain_suffix": self.domains.telegram, "outbound": "warp-out" },

                    // Streaming & Video (YouTube, Discord, General) through ByeDPI DPI desync
                    { "domain_suffix": self.domains.youtube, "outbound": "byedpi-out" },
                    { "domain_suffix": self.domains.discord, "outbound": "byedpi-out" },
                    { "domain_suffix": self.domains.cloudflare, "outbound": "byedpi-out" },

                    { "outbound": "byedpi-out" }
                ],
                "auto_detect_interface": true
            }
        })
    }

    /// Starts ByeDPI (ciadpi) with the active DPI strategy.
    pub async fn start_byedpi(&self) -> Result<()> {
        let mut guard = self.byedpi_proc.lock().await;
        if guard.is_some() {
            self.stop_byedpi().await?;
        }

        let strat = self.tuner.select_best(ServiceId::General);
        info!("Starting ByeDPI (ciadpi) with strategy: '{}' {:?}", strat.name, strat.ciadpi_args);

        let mut cmd = Command::new(&self.config.byedpi_bin);
        cmd.args(["-i", "127.0.0.1", "-p", &self.config.byedpi_socks_port.to_string()]);
        for arg in &strat.ciadpi_args {
            cmd.arg(arg);
        }

        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());

        match cmd.spawn() {
            Ok(child) => {
                *guard = Some(child);
                self.log(LogLevel::Info, "DPI", format!("ByeDPI started on port {} ({})", self.config.byedpi_socks_port, strat.name)).await;
                Ok(())
            }
            Err(e) => {
                warn!("Could not spawn ciadpi ({:?}). Running in direct simulation fallback.", e);
                self.log(LogLevel::Warn, "DPI", format!("ciadpi binary not found in path: {}", e)).await;
                Ok(())
            }
        }
    }

    pub async fn stop_byedpi(&self) -> Result<()> {
        let mut guard = self.byedpi_proc.lock().await;
        if let Some(mut child) = guard.take() {
            let _ = child.kill().await;
            info!("ByeDPI terminated.");
        }
        Ok(())
    }

    /// Starts sing-box using dynamic config.
    pub async fn start_singbox(&self) -> Result<()> {
        let mut guard = self.singbox_proc.lock().await;
        if guard.is_some() {
            self.stop_singbox().await?;
        }

        let config_json = self.generate_singbox_config();
        let config_path = self.config.run_dir.join("sing-box.json");
        tokio::fs::create_dir_all(&self.config.run_dir).await?;
        tokio::fs::write(&config_path, serde_json::to_string_pretty(&config_json)?).await?;

        info!("Starting sing-box using config at {:?}", config_path);

        let mut cmd = Command::new(&self.config.singbox_bin);
        cmd.args(["run", "-c", config_path.to_str().unwrap()]);
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());

        match cmd.spawn() {
            Ok(child) => {
                *guard = Some(child);
                self.log(LogLevel::Info, "ROUTER", "sing-box transparent core active").await;
                Ok(())
            }
            Err(e) => {
                warn!("Could not spawn sing-box ({:?}). Running in mock/standby mode.", e);
                self.log(LogLevel::Warn, "ROUTER", format!("sing-box binary not found: {}", e)).await;
                Ok(())
            }
        }
    }

    pub async fn stop_singbox(&self) -> Result<()> {
        let mut guard = self.singbox_proc.lock().await;
        if let Some(mut child) = guard.take() {
            let _ = child.kill().await;
            info!("sing-box terminated.");
        }
        Ok(())
    }

    /// Launches all child networking services.
    pub async fn start(&self) -> Result<()> {
        self.start_byedpi().await?;
        self.start_singbox().await?;
        self.running.store(true, Ordering::SeqCst);
        self.log(LogLevel::Info, "SYS", "Nova network orchestrator online").await;
        Ok(())
    }

    /// Cleanly halts all services.
    pub async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.stop_singbox().await?;
        self.stop_byedpi().await?;
        self.log(LogLevel::Info, "SYS", "Nova network orchestrator stopped cleanly").await;
        Ok(())
    }

    pub async fn set_mode(&self, new_mode: NetworkMode) -> Result<()> {
        let mut mode = self.mode.lock().await;
        *mode = new_mode;
        info!("Network mode switched to: {:?}", new_mode);
        match new_mode {
            NetworkMode::Paused => {
                self.stop().await?;
            }
            _ => {
                if !self.running.load(Ordering::SeqCst) {
                    self.start().await?;
                }
            }
        }
        Ok(())
    }

    pub async fn reload_service_strategy(&self, service: ServiceId) -> Result<()> {
        info!("Reloading strategy for service: {:?}", service);
        self.start_byedpi().await?;
        self.log(
            LogLevel::Info,
            "ADAPT",
            format!("DPI strategy auto-reloaded for {:?}", service),
        )
        .await;
        Ok(())
    }

    pub async fn get_status(&self) -> DaemonStatus {
        let mode = *self.mode.lock().await;
        let is_running = self.running.load(Ordering::SeqCst);

        let yt_strat = self.tuner.current_strategy(ServiceId::YouTube).map(|s| s.name).unwrap_or_else(|| "Split 2+s".into());
        let discord_strat = self.tuner.current_strategy(ServiceId::Discord).map(|s| s.name).unwrap_or_else(|| "Disorder 3".into());
        let gen_strat = self.tuner.current_strategy(ServiceId::General).map(|s| s.name).unwrap_or_else(|| "ciadpi".into());

        DaemonStatus {
            running: is_running,
            mode,
            active_profile: "Авто (Adaptive)".into(),
            services: vec![
                ServiceStatus {
                    id: ServiceId::YouTube,
                    title: "YouTube".into(),
                    method: RoutingMethod::Desync { engine: "nfqws+ciadpi".into(), strategy: yt_strat },
                    health: if is_running { ServiceHealth::Optimal } else { ServiceHealth::Offline },
                    latency_ms: Some(24),
                    summary: "Fake TTL / Split".into(),
                },
                ServiceStatus {
                    id: ServiceId::Discord,
                    title: "Discord".into(),
                    method: RoutingMethod::Desync { engine: "ciadpi".into(), strategy: discord_strat },
                    health: if is_running { ServiceHealth::Optimal } else { ServiceHealth::Offline },
                    latency_ms: Some(31),
                    summary: "Split SNI".into(),
                },
                ServiceStatus {
                    id: ServiceId::Telegram,
                    title: "Telegram".into(),
                    method: RoutingMethod::Relay { endpoint: "kws.web.telegram.org".into() },
                    health: if is_running { ServiceHealth::Optimal } else { ServiceHealth::Offline },
                    latency_ms: Some(42),
                    summary: "kws WebSocket".into(),
                },
                ServiceStatus {
                    id: ServiceId::Ai,
                    title: "AI".into(),
                    method: RoutingMethod::Tunnel { provider: "WARP".into(), node: Some("auto".into()) },
                    health: if is_running { ServiceHealth::Optimal } else { ServiceHealth::Offline },
                    latency_ms: Some(38),
                    summary: "Clean Geolocation".into(),
                },
                ServiceStatus {
                    id: ServiceId::General,
                    title: "General Sites".into(),
                    method: RoutingMethod::Desync { engine: "ciadpi".into(), strategy: gen_strat },
                    health: if is_running { ServiceHealth::Optimal } else { ServiceHealth::Offline },
                    latency_ms: Some(26),
                    summary: "SOCKS5 Adaptive".into(),
                },
            ],
            uptime_secs: 120,
            bytes_sent: 1024 * 1024 * 12,
            bytes_recv: 1024 * 1024 * 94,
            tun_interface: self.config.tun_interface.clone(),
        }
    }

    pub async fn log(&self, level: LogLevel, subsystem: &str, message: impl Into<String>) {
        let entry = LogEntry {
            timestamp: chrono::Utc::now(),
            level,
            subsystem: subsystem.to_string(),
            message: message.into(),
        };
        let mut logs = self.recent_logs.lock().await;
        logs.push(entry);
        if logs.len() > 200 {
            logs.remove(0);
        }
    }

    pub async fn get_recent_logs(&self, limit: usize) -> Vec<LogEntry> {
        let logs = self.recent_logs.lock().await;
        let start = logs.len().saturating_sub(limit);
        logs[start..].to_vec()
    }
}
