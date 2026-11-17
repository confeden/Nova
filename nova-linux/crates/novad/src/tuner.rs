use nova_common::models::ServiceId;
use rand::distributions::Open01;
use rand::Rng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// Functional niche of a DPI desynchronization technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StrategyNiche {
    SplitTls,
    Disorder,
    FakeTtl,
    BadSum,
    FakeSni,
}

/// A specific candidate strategy with Thompson Sampling parameters.
#[derive(Debug, Clone)]
pub struct DpiStrategy {
    pub name: String,
    pub niche: StrategyNiche,
    pub ciadpi_args: Vec<String>,
    pub alpha: f64, // Wins + 1
    pub beta: f64,  // Losses + 1
}

impl DpiStrategy {
    pub fn new(name: &str, niche: StrategyNiche, args: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            niche,
            ciadpi_args: args.iter().map(|s| s.to_string()).collect(),
            alpha: 1.0,
            beta: 1.0,
        }
    }

    /// Approximation of Beta distribution sample for Thompson sampling.
    pub fn sample<R: Rng>(&self, rng: &mut R) -> f64 {
        // Kumaraswamy approximation or standard Gamma approximation
        let u1: f64 = rng.sample(Open01);
        let u2: f64 = rng.sample(Open01);
        let x = (-u1.ln()).powf(1.0 / self.alpha.max(0.1));
        let y = (-u2.ln()).powf(1.0 / self.beta.max(0.1));
        x / (x + y).max(1e-6)
    }

    pub fn record_outcome(&mut self, success: bool) {
        if success {
            self.alpha += 1.0;
        } else {
            self.beta += 1.5; // Slight penalty bias
        }
    }
}

/// Deep module managing adaptive DPI strategy selection and mutation.
#[derive(Clone)]
pub struct DpiTuner {
    pool: Arc<Mutex<HashMap<ServiceId, Vec<DpiStrategy>>>>,
    active_indices: Arc<Mutex<HashMap<ServiceId, usize>>>,
}

impl DpiTuner {
    pub fn new() -> Self {
        let mut pool = HashMap::new();

        // Standard proven Russian ISP strategies for General Sites / TCP
        let default_strategies = vec![
            DpiStrategy::new(
                "split-sni-2",
                StrategyNiche::SplitTls,
                &["--split", "2+s", "--fake", "-1"],
            ),
            DpiStrategy::new(
                "disorder-sni-3",
                StrategyNiche::Disorder,
                &["--disorder", "3+s", "--fake", "-1", "--ttl", "5"],
            ),
            DpiStrategy::new(
                "fake-ttl-4",
                StrategyNiche::FakeTtl,
                &["--fake", "-1", "--ttl", "4", "--split", "1+s"],
            ),
            DpiStrategy::new(
                "split-sni-pos",
                StrategyNiche::SplitTls,
                &["--split", "s+1", "--disorder", "s+2"],
            ),
            DpiStrategy::new(
                "fake-sni-neutral",
                StrategyNiche::FakeSni,
                &["--fake", "-1", "--fake-sni", "gosuslugi.ru", "--split", "2"],
            ),
        ];

        pool.insert(ServiceId::YouTube, default_strategies.clone());
        pool.insert(ServiceId::Discord, default_strategies.clone());
        pool.insert(ServiceId::General, default_strategies);

        let mut active = HashMap::new();
        active.insert(ServiceId::YouTube, 0);
        active.insert(ServiceId::Discord, 0);
        active.insert(ServiceId::General, 0);

        Self {
            pool: Arc::new(Mutex::new(pool)),
            active_indices: Arc::new(Mutex::new(active)),
        }
    }

    /// Selects the best strategy for a service via Thompson Sampling.
    pub fn select_best(&self, service: ServiceId) -> DpiStrategy {
        let mut rng = rand::thread_rng();
        let pool = self.pool.lock().unwrap();

        if let Some(list) = pool.get(&service) {
            let mut best_idx = 0;
            let mut highest_sample = -1.0;

            for (idx, strat) in list.iter().enumerate() {
                let sample = strat.sample(&mut rng);
                if sample > highest_sample {
                    highest_sample = sample;
                    best_idx = idx;
                }
            }

            let mut active = self.active_indices.lock().unwrap();
            active.insert(service, best_idx);
            list[best_idx].clone()
        } else {
            DpiStrategy::new("default-fallback", StrategyNiche::SplitTls, &["--split", "2+s"])
        }
    }

    /// Notifies the tuner of an outcome (success or connection reset/timeout).
    pub fn report_outcome(&self, service: ServiceId, success: bool) -> Option<DpiStrategy> {
        let mut pool = self.pool.lock().unwrap();
        let mut active = self.active_indices.lock().unwrap();

        if let (Some(list), Some(curr_idx)) = (pool.get_mut(&service), active.get_mut(&service)) {
            if let Some(strat) = list.get_mut(*curr_idx) {
                strat.record_outcome(success);
                info!(
                    "Service '{:?}' reported outcome (success={}). Strat: '{}' (α={:.1}, β={:.1})",
                    service, success, strat.name, strat.alpha, strat.beta
                );

                if !success && strat.beta > strat.alpha * 2.0 {
                    warn!("Strategy '{}' degraded. Triggering niche mutation...", strat.name);
                    drop(pool);
                    drop(active);
                    return Some(self.select_best(service));
                }
            }
        }
        None
    }

    pub fn current_strategy(&self, service: ServiceId) -> Option<DpiStrategy> {
        let pool = self.pool.lock().unwrap();
        let active = self.active_indices.lock().unwrap();
        active.get(&service).and_then(|&idx| pool.get(&service)?.get(idx).cloned())
    }
}
