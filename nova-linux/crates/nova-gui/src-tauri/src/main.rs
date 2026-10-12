// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use nova_common::ipc::{IpcRequest, IpcResponse, DEFAULT_SOCKET_PATH};
use nova_common::models::{DaemonStatus, LogEntry, NetworkMode};
use std::path::Path;
use std::sync::Arc;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

pub struct DaemonClient {
    #[cfg(unix)]
    socket_path: std::path::PathBuf,
}

impl DaemonClient {
    pub fn new() -> Self {
        Self {
            #[cfg(unix)]
            socket_path: std::path::PathBuf::from(DEFAULT_SOCKET_PATH),
        }
    }

    pub async fn send_request(&self, req: IpcRequest) -> Result<IpcResponse, String> {
        let req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;

        #[cfg(unix)]
        {
            let mut stream = tokio::net::UnixStream::connect(&self.socket_path)
                .await
                .map_err(|e| format!("Cannot connect to novad at {:?}: {}", self.socket_path, e))?;

            stream.write_all(&req_bytes).await.map_err(|e| e.to_string())?;

            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
            serde_json::from_slice(&buf[..n]).map_err(|e| format!("Invalid JSON response: {}", e))
        }

        #[cfg(not(unix))]
        {
            // Dev fallback on Windows
            let mut stream = tokio::net::TcpStream::connect("127.0.0.1:18234")
                .await
                .map_err(|e| format!("Cannot connect to novad (TCP dev): {}", e))?;

            stream.write_all(&req_bytes).await.map_err(|e| e.to_string())?;

            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
            serde_json::from_slice(&buf[..n]).map_err(|e| format!("Invalid JSON response: {}", e))
        }
    }
}

pub struct AppState {
    client: Arc<DaemonClient>,
}

#[tauri::command]
async fn get_daemon_status(state: State<'_, AppState>) -> Result<DaemonStatus, String> {
    match state.client.send_request(IpcRequest::GetStatus).await {
        Ok(IpcResponse::Status(status)) => Ok(status),
        Ok(other) => Err(format!("Unexpected response: {:?}", other)),
        Err(e) => {
            warn!("novad offline fallback: {}", e);
            // Return offline simulated state so UI still works
            Ok(DaemonStatus {
                running: false,
                mode: NetworkMode::Paused,
                active_profile: "Остановлен (novad offline)".into(),
                services: vec![],
                uptime_secs: 0,
                bytes_sent: 0,
                bytes_recv: 0,
                tun_interface: "none".into(),
            })
        }
    }
}

#[tauri::command]
async fn set_network_mode(mode: String, state: State<'_, AppState>) -> Result<String, String> {
    let net_mode = match mode.as_str() {
        "paused" => NetworkMode::Paused,
        "tunnel_only" => NetworkMode::TunnelOnly,
        "direct_only" => NetworkMode::DirectDpiOnly,
        _ => NetworkMode::Adaptive,
    };

    match state.client.send_request(IpcRequest::SetMode(net_mode)).await {
        Ok(IpcResponse::Success) => Ok("OK".into()),
        Ok(IpcResponse::Error(err)) => Err(err),
        Err(e) => Err(e),
        _ => Err("Invalid response from daemon".into()),
    }
}

#[tauri::command]
async fn get_recent_logs(limit: usize, state: State<'_, AppState>) -> Result<Vec<LogEntry>, String> {
    match state.client.send_request(IpcRequest::GetRecentLogs(limit)).await {
        Ok(IpcResponse::Logs(logs)) => Ok(logs),
        Err(e) => Err(e),
        _ => Ok(vec![]),
    }
}

fn main() {
    tracing_subscriber::fmt::init();

    let client = Arc::new(DaemonClient::new());
    let state = AppState { client };

    tauri::Builder::default()
        .manage(state)
        .setup(|app| {
            // Setup system tray menu
            let show_i = MenuItem::with_id(app, "show", "Открыть Nova", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &quit_i])?;

            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_daemon_status,
            set_network_mode,
            get_recent_logs
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
