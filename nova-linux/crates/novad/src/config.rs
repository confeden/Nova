use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub config_dir: PathBuf,
    pub run_dir: PathBuf,
    pub singbox_bin: PathBuf,
    pub byedpi_bin: PathBuf,
    pub nfqws_bin: Option<PathBuf>,
    pub tun_interface: String,
    pub tun_ip: String,
    pub tproxy_port: u16,
    pub byedpi_socks_port: u16,
}

fn find_binary(name: &str, preferred: &[&str]) -> PathBuf {
    for prefix in preferred {
        let p = PathBuf::from(prefix).join(name);
        if p.exists() {
            return p;
        }
    }
    PathBuf::from(format!("/usr/local/bin/{}", name))
}

impl Default for DaemonConfig {
    fn default() -> Self {
        let candidate_paths = ["/usr/local/bin", "/usr/bin", "/bin", "/opt/bin"];
        Self {
            socket_path: PathBuf::from("/run/nova/novad.sock"),
            config_dir: PathBuf::from("/etc/nova"),
            run_dir: PathBuf::from("/run/nova"),
            singbox_bin: find_binary("sing-box", &candidate_paths),
            byedpi_bin: find_binary("ciadpi", &candidate_paths),
            nfqws_bin: Some(find_binary("nfqws", &candidate_paths)),
            tun_interface: "nova0".to_string(),
            tun_ip: "172.19.0.1/30".to_string(),
            tproxy_port: 12345,
            byedpi_socks_port: 1080,
        }
    }
}
