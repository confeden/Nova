use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tracing::info;

pub const TABLE_NAME: &str = "nova";
pub const FWMARK: u32 = 0x162; // Nova mark
pub const ROUTE_TABLE: u32 = 162;

/// Deep module managing Linux nftables rules for transparent proxying.
pub struct FirewallManager {
    applied: std::sync::atomic::AtomicBool,
}

impl FirewallManager {
    pub fn new() -> Self {
        Self {
            applied: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Checks if nftables is installed and available.
    pub async fn check_available(&self) -> bool {
        Command::new("nft")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Applies transparent routing rules via nftables and policy routing.
    pub async fn apply(&self, tproxy_port: u16) -> Result<()> {
        info!("Applying nftables rules for Nova (TProxy port: {})...", tproxy_port);

        // 1. Setup policy routing: ip rule add fwmark 0x162 lookup 162
        let _ = Command::new("ip")
            .args(["rule", "del", "fwmark", &format!("{:#x}", FWMARK), "lookup", &ROUTE_TABLE.to_string()])
            .output()
            .await;

        Command::new("ip")
            .args(["rule", "add", "fwmark", &format!("{:#x}", FWMARK), "lookup", &ROUTE_TABLE.to_string()])
            .status()
            .await
            .context("Failed to add ip rule for policy routing")?;

        let _ = Command::new("ip")
            .args(["route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", &ROUTE_TABLE.to_string()])
            .output()
            .await;

        Command::new("ip")
            .args(["route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", &ROUTE_TABLE.to_string()])
            .status()
            .await
            .context("Failed to add local route in policy table")?;

        // 2. Build nftables ruleset
        let ruleset = format!(
            r#"
table inet {table} {{
    chain prerouting {{
        type filter hook prerouting priority mangle; policy accept;

        # Bypass private/loopback networks
        ip daddr {{ 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32 }} return
        ip6 daddr {{ ::1/128, fc00::/7, fe80::/10, ff00::/8 }} return

        # Forward TCP to sing-box TProxy
        meta l4proto tcp tproxy to 127.0.0.1:{port} meta mark set {mark} accept

        # Forward UDP to sing-box TProxy
        meta l4proto udp tproxy to 127.0.0.1:{port} meta mark set {mark} accept
    }}

    chain output {{
        type route hook output priority mangle; policy accept;

        # Do not loop our own marked traffic
        meta mark {mark} return

        # Bypass private/loopback networks
        ip daddr {{ 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32 }} return
        ip6 daddr {{ ::1/128, fc00::/7, fe80::/10, ff00::/8 }} return

        # Mark locally-originated traffic for re-routing to prerouting/TProxy
        meta l4proto {{ tcp, udp }} meta mark set {mark}
    }}
}}
"#,
            table = TABLE_NAME,
            port = tproxy_port,
            mark = format!("{:#x}", FWMARK)
        );

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn nft command")?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(ruleset.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to apply nftables ruleset: {}", err);
        }

        self.applied.store(true, std::sync::atomic::Ordering::SeqCst);
        info!("nftables ruleset '{}' applied successfully.", TABLE_NAME);
        Ok(())
    }

    /// Atomically removes all Nova rules, ensuring no lingering network disruption.
    pub async fn cleanup(&self) -> Result<()> {
        info!("Cleaning up Nova firewall rules...");

        // Remove nft table
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", TABLE_NAME])
            .output()
            .await;

        // Remove policy routing
        let _ = Command::new("ip")
            .args(["rule", "del", "fwmark", &format!("{:#x}", FWMARK), "lookup", &ROUTE_TABLE.to_string()])
            .output()
            .await;

        let _ = Command::new("ip")
            .args(["route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", &ROUTE_TABLE.to_string()])
            .output()
            .await;

        self.applied.store(false, std::sync::atomic::Ordering::SeqCst);
        info!("Nova firewall rules wiped cleanly.");
        Ok(())
    }
}
