use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub quic_mtu: u16,
    pub quic_cert_filepath: (String, String),
    pub quic_max_data: u64,
    pub quic_max_stream_data: u64,
    pub quic_auth_code: String,
    pub pcap_device: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        let mut tcp_port_mapping = HashMap::new();
        tcp_port_mapping.insert(14000, 443);
        tcp_port_mapping.insert(15000, 2096);
        tcp_port_mapping.insert(16000, 10809);

        let mut udp_port_mapping = HashMap::new();
        udp_port_mapping.insert(17000, 945);
        udp_port_mapping.insert(18000, 1014);

        Self {
            tcp_port_mapping,
            udp_port_mapping,
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
            pcap_device: None,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        if let Some(path) = path {
            let contents = fs::read_to_string(path)?;
            let config: Config = toml::from_str(&contents)?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }
}
