use crate::models::{DaemonStatus, LogEntry, NetworkMode, ServiceId};
use serde::{Deserialize, Serialize};

/// Standard UNIX Domain Socket path for novad on Linux.
pub const DEFAULT_SOCKET_PATH: &str = "/run/nova/novad.sock";
/// Fallback user-mode socket path for testing or rootless development.
pub const USER_SOCKET_SUBPATH: &str = ".local/share/nova/novad.sock";

/// Request from GUI client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", content = "payload", rename_all = "snake_case")]
pub enum IpcRequest {
    GetStatus,
    SetMode(NetworkMode),
    SetProfile(String),
    TriggerAdaptation(Option<ServiceId>),
    GetRecentLogs(usize),
    RestartPipeline,
    Shutdown,
}

/// Response from the daemon to GUI client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum IpcResponse {
    Status(DaemonStatus),
    Logs(Vec<LogEntry>),
    Success,
    Error(String),
}

/// Real-time asynchronous push notification from the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum IpcEvent {
    StatusUpdated(DaemonStatus),
    NewLog(LogEntry),
    StrategyMutated {
        service: ServiceId,
        old_method: String,
        new_method: String,
        reason: String,
    },
}
