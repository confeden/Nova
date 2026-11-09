mod config;
mod domains;
mod firewall;
mod flap;
mod ipc;
mod orchestrator;
mod prober;
mod tuner;
mod warp;

use anyhow::Result;
use clap::Parser;
use config::DaemonConfig;
use firewall::FirewallManager;
use ipc::IpcServer;
use orchestrator::Orchestrator;
use prober::ActiveProber;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};
use tuner::DpiTuner;

#[derive(Parser, Debug)]
#[command(name = "novad", about = "Nova Linux System Networking Daemon")]
struct Cli {
    #[arg(short, long, default_value = "/run/nova/novad.sock")]
    socket: PathBuf,

    #[arg(short, long, default_value = "12345")]
    tproxy_port: u16,

    #[arg(short, long, default_value = "1080")]
    byedpi_port: u16,

    #[arg(long)]
    no_firewall: bool,

    #[arg(long)]
    no_prober: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "novad=info,nova_common=info".into()),
        )
        .init();

    let cli = Cli::parse();
    info!("Starting novad (Nova Linux Networking Core with Parity)...");

    let mut config = DaemonConfig::default();
    config.socket_path = cli.socket;
    config.tproxy_port = cli.tproxy_port;
    config.byedpi_socks_port = cli.byedpi_port;

    let firewall = Arc::new(FirewallManager::new());
    let tuner = DpiTuner::new();
    let orchestrator = Arc::new(Orchestrator::new(config.clone(), tuner.clone()));
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let ipc_server = IpcServer::new(Arc::clone(&orchestrator), shutdown_tx);

    // 1. Setup transparent routing via nftables unless disabled
    if !cli.no_firewall && cfg!(unix) {
        if firewall.check_available().await {
            if let Err(e) = firewall.apply(config.tproxy_port).await {
                error!("Failed to initialize nftables firewall rules: {:?}", e);
            }
        } else {
            info!("nftables not found or unprivileged. Skipping kernel packet interception.");
        }
    }

    // 2. Start subprocesses (sing-box & ByeDPI)
    if let Err(e) = orchestrator.start().await {
        error!("Error launching network pipeline: {:?}", e);
    }

    // 3. Setup reload channel and spawn Active Health Prober
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel(16);
    let orch_reload = Arc::clone(&orchestrator);
    tokio::spawn(async move {
        while let Some(service) = reload_rx.recv().await {
            let _ = orch_reload.reload_service_strategy(service).await;
        }
    });

    if !cli.no_prober {
        let prober = Arc::new(ActiveProber::new(tuner));
        tokio::spawn(prober.run_loop(reload_tx));
    }

    // 4. Spawn IPC server
    let socket_path = config.socket_path.clone();
    let ipc_task = tokio::spawn(async move {
        if let Err(e) = ipc_server.run(&socket_path).await {
            error!("IPC server terminated: {:?}", e);
        }
    });

    // 5. Wait for termination signal
    info!("novad is active and listening for client requests.");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal (Ctrl+C) received. Initiating graceful network cleanup...");
        }
        _ = shutdown_rx.recv() => {
            info!("Shutdown requested via IPC. Initiating graceful network cleanup...");
        }
    }

    // 6. Graceful cleanup: stop processes and remove nftables rules
    let _ = orchestrator.stop().await;
    if !cli.no_firewall && cfg!(unix) {
        let _ = firewall.cleanup().await;
    }

    ipc_task.abort();
    info!("novad cleanup complete. Internet routing restored to default.");
    Ok(())
}
