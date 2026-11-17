use crate::flap::FlapController;
use crate::tuner::DpiTuner;
use nova_common::models::ServiceId;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

pub struct ProberTarget {
    pub service: ServiceId,
    pub host: &'static str,
    pub port: u16,
}

pub struct ActiveProber {
    tuner: DpiTuner,
    flap: Arc<Mutex<FlapController>>,
    targets: Vec<ProberTarget>,
}

impl ActiveProber {
    pub fn new(tuner: DpiTuner) -> Self {
        let flap = Arc::new(Mutex::new(FlapController::new(25, 45))); // 25s min cooldown, 45s flap hold
        let targets = vec![
            ProberTarget {
                service: ServiceId::YouTube,
                host: "googlevideo.com",
                port: 443,
            },
            ProberTarget {
                service: ServiceId::Discord,
                host: "gateway.discord.gg",
                port: 443,
            },
            ProberTarget {
                service: ServiceId::Ai,
                host: "api.anthropic.com",
                port: 443,
            },
            ProberTarget {
                service: ServiceId::Telegram,
                host: "kws1.web.telegram.org",
                port: 443,
            },
        ];

        Self {
            tuner,
            flap,
            targets,
        }
    }

    /// Single probe check against a target host with timeout.
    pub async fn probe_endpoint(host: &str, port: u16, timeout_ms: u64) -> (bool, Option<u32>) {
        let addr = format!("{}:{}", host, port);
        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);

        match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(_stream)) => {
                let rtt = start.elapsed().as_millis() as u32;
                (true, Some(rtt))
            }
            Ok(Err(_)) => (false, None),
            Err(_) => (false, None), // Timed out
        }
    }

    /// Continuous background monitoring task.
    pub async fn run_loop(self: Arc<Self>, reload_tx: tokio::sync::mpsc::Sender<ServiceId>) {
        info!("Active Health Prober loop started (interval: 15s)...");

        loop {
            sleep(Duration::from_secs(15)).await;

            for target in &self.targets {
                let (success, rtt) = Self::probe_endpoint(target.host, target.port, 3500).await;

                let mut flap = self.flap.lock().await;
                if success {
                    flap.record_success(target.service);
                    self.tuner.report_outcome(target.service, true);
                    info!(
                        "[Probe OK] {:?} via {} -> {} ms",
                        target.service,
                        target.host,
                        rtt.unwrap_or(0)
                    );
                } else {
                    let can_switch = flap.record_failure(target.service);
                    info!(
                        "[Probe FAIL] {:?} via {}. Can switch: {}",
                        target.service, target.host, can_switch
                    );

                    if can_switch {
                        if let Some(new_strat) = self.tuner.report_outcome(target.service, false) {
                            warn!(
                                "[Adaptive Mutation] {:?} degraded. Switching to: '{}' {:?}",
                                target.service, new_strat.name, new_strat.ciadpi_args
                            );
                            flap.record_switch(target.service);
                            let _ = reload_tx.send(target.service).await;
                        }
                    } else {
                        warn!(
                            "[Flap Hold] Rapid switches detected for {:?}. Holding current route.",
                            target.service
                        );
                    }
                }
            }
        }
    }
}
