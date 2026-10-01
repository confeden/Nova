use crate::orchestrator::Orchestrator;
use anyhow::{Context, Result};
use nova_common::ipc::{IpcRequest, IpcResponse};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};

pub struct IpcServer {
    orchestrator: Arc<Orchestrator>,
    shutdown_tx: tokio::sync::mpsc::Sender<()>,
}

impl IpcServer {
    pub fn new(orchestrator: Arc<Orchestrator>, shutdown_tx: tokio::sync::mpsc::Sender<()>) -> Self {
        Self { orchestrator, shutdown_tx }
    }

    #[cfg(unix)]
    pub async fn run(&self, socket_path: &Path) -> Result<()> {
        if socket_path.exists() {
            let _ = tokio::fs::remove_file(socket_path).await;
        }

        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let listener = tokio::net::UnixListener::bind(socket_path)
            .with_context(|| format!("Failed to bind UNIX socket at {:?}", socket_path))?;

        info!("novad IPC server listening on UNIX socket: {:?}", socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let orch = Arc::clone(&self.orchestrator);
                    let tx = self.shutdown_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(stream, orch, tx).await {
                            warn!("IPC client error: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting IPC connection: {:?}", e);
                }
            }
        }
    }

    #[cfg(windows)]
    pub async fn run(&self, _socket_path: &Path) -> Result<()> {
        // Fallback for development/testing on Windows
        let listener = tokio::net::TcpListener::bind("127.0.0.1:18234").await?;
        info!("novad IPC server running in development TCP fallback on 127.0.0.1:18234");

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let orch = Arc::clone(&self.orchestrator);
                    let tx = self.shutdown_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(stream, orch, tx).await {
                            warn!("IPC client error: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting IPC connection: {:?}", e);
                }
            }
        }
    }

    async fn handle_client<S>(
        mut stream: S,
        orchestrator: Arc<Orchestrator>,
        shutdown_tx: tokio::sync::mpsc::Sender<()>,
    ) -> Result<()>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            let req: IpcRequest = match serde_json::from_slice(&buf[..n]) {
                Ok(r) => r,
                Err(e) => {
                    let resp = IpcResponse::Error(format!("Invalid JSON request: {}", e));
                    let bytes = serde_json::to_vec(&resp)?;
                    stream.write_all(&bytes).await?;
                    continue;
                }
            };

            let resp = match req {
                IpcRequest::GetStatus => {
                    let status = orchestrator.get_status().await;
                    IpcResponse::Status(status)
                }
                IpcRequest::SetMode(mode) => {
                    if let Err(e) = orchestrator.set_mode(mode).await {
                        IpcResponse::Error(e.to_string())
                    } else {
                        IpcResponse::Success
                    }
                }
                IpcRequest::SetProfile(profile) => {
                    info!("Profile change requested: {}", profile);
                    IpcResponse::Success
                }
                IpcRequest::TriggerAdaptation(service) => {
                    info!("Manual adaptation triggered for: {:?}", service);
                    IpcResponse::Success
                }
                IpcRequest::GetRecentLogs(limit) => {
                    let logs = orchestrator.get_recent_logs(limit).await;
                    IpcResponse::Logs(logs)
                }
                IpcRequest::RestartPipeline => {
                    let _ = orchestrator.stop().await;
                    let _ = orchestrator.start().await;
                    IpcResponse::Success
                }
                IpcRequest::Shutdown => {
                    let _ = orchestrator.stop().await;
                    let _ = shutdown_tx.send(()).await;
                    IpcResponse::Success
                }
            };

            let bytes = serde_json::to_vec(&resp)?;
            stream.write_all(&bytes).await?;
        }
        Ok(())
    }
}
