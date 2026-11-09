use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Global operating mode of the Nova networking pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Adaptive auto-tuning: DPI desync where possible, automated tunnel fallback when needed.
    Adaptive,
    /// Force all traffic through tunnels (WARP, VLESS, etc.).
    TunnelOnly,
    /// Direct DPI bypass only (no external proxy/tunnel fallback).
    DirectDpiOnly,
    /// Bypass completely disabled (all traffic direct without modification).
    Paused,
}

impl Default for NetworkMode {
    fn default() -> Self {
        NetworkMode::Adaptive
    }
}

/// Known service categories recognized by Nova.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceId {
    YouTube,
    Discord,
    Telegram,
    Ai,
    Cloudflare,
    General,
}

impl ServiceId {
    pub fn display_name(&self) -> &'static str {
        match self {
            ServiceId::YouTube => "YouTube",
            ServiceId::Discord => "Discord",
            ServiceId::Telegram => "Telegram",
            ServiceId::Ai => "AI (ChatGPT/Claude)",
            ServiceId::Cloudflare => "Cloudflare CDN",
            ServiceId::General => "General Sites",
        }
    }
}

/// Method used to route traffic for a given target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum RoutingMethod {
    Direct,
    Desync {
        engine: String,
        strategy: String,
    },
    Tunnel {
        provider: String,
        node: Option<String>,
    },
    Relay {
        endpoint: String,
    },
}

/// Operational state of a specific service pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceHealth {
    Optimal,
    Degraded,
    Recovering,
    Offline,
}

/// Real-time status entry for a service displayed in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub id: ServiceId,
    pub title: String,
    pub method: RoutingMethod,
    pub health: ServiceHealth,
    pub latency_ms: Option<u32>,
    pub summary: String,
}

/// High-level daemon telemetry and runtime state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub mode: NetworkMode,
    pub active_profile: String,
    pub services: Vec<ServiceStatus>,
    pub uptime_secs: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub tun_interface: String,
}

/// Severity level for log messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Single log message streamed to the GUI log drawer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub subsystem: String,
    pub message: String,
}
