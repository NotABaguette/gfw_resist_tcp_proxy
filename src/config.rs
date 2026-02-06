use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub tcp_port_mapping: HashMap<u16, u16>,
    pub udp_port_mapping: HashMap<u16, u16>,
    pub vps_ip: String,
    pub xray_server_ip_address: String,
    pub vio_tcp_server_port: u16,
    pub vio_tcp_client_port: u16,
    pub vio_udp_server_port: u16,
    pub vio_udp_client_port: u16,
    pub quic_server_port: u16,
    pub quic_client_port: u16,
    pub quic_local_ip: String,
    pub quic_idle_timeout: u64,
    pub udp_timeout: u64,
    pub quic_verify_cert: bool,
    pub quic_mtu: u64,
    pub quic_cert_filepath: (String, String),
    pub quic_max_data: u64,
    pub quic_max_stream_data: u64,
    pub quic_auth_code: String,
    pub capture_interface: Option<String>,
    pub udp_buffer_bytes: usize,
    pub tcp_buffer_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_port_mapping: [(14000, 443), (15000, 2096), (16000, 10809)]
                .into_iter()
                .collect(),
            udp_port_mapping: [(17000, 945), (18000, 1014)].into_iter().collect(),
            vps_ip: "192.168.1.5".to_string(),
            xray_server_ip_address: "127.0.0.1".to_string(),
            vio_tcp_server_port: 45000,
            vio_tcp_client_port: 40000,
            vio_udp_server_port: 35000,
            vio_udp_client_port: 30000,
            quic_server_port: 25000,
            quic_client_port: 20000,
            quic_local_ip: "127.0.0.1".to_string(),
            quic_idle_timeout: 86_400,
            udp_timeout: 300,
            quic_verify_cert: false,
            quic_mtu: 1420,
            quic_cert_filepath: ("cert.pem".to_string(), "key.pem".to_string()),
            quic_max_data: 1_000 * 1024 * 1024,
            quic_max_stream_data: 1_000 * 1024 * 1024,
            quic_auth_code: "jd!gn0s4".to_string(),
            capture_interface: None,
            udp_buffer_bytes: 2 * 1024 * 1024,
            tcp_buffer_bytes: 2 * 1024 * 1024,
        }
    }
}

pub fn load_config(path: Option<&str>) -> anyhow::Result<Config> {
    let path = path.unwrap_or("config.toml");
    if !Path::new(path).exists() {
        return Ok(Config::default());
    }
    let contents = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}
