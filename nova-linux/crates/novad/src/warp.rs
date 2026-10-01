use serde_json::json;

/// Generates standard Cloudflare WARP WireGuard outbound configuration for sing-box.
pub struct WarpManager;

impl WarpManager {
    /// Returns a pre-configured WireGuard WARP outbound using clean IP endpoints.
    pub fn generate_singbox_outbound() -> serde_json::Value {
        // Known reliable Cloudflare WARP Anycast endpoints
        let primary_endpoint = "162.159.192.1";
        let port = 2408;

        json!({
            "type": "wireguard",
            "tag": "warp-out",
            "server": primary_endpoint,
            "server_port": port,
            "local_address": [
                "172.16.0.2/32",
                "2606:4700:110:8f81:859e:a573:26a3:f62a/128"
            ],
            // Default Cloudflare Public Peer Key
            "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            // Client key placeholder or dynamically provisioned
            "private_key": "aGVsbG8td29ybGQtbm92YS1saW51eC1rZXktY2xvdWRmbGFyZQ==",
            "mtu": 1280
        })
    }
}
