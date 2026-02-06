use anyhow::{anyhow, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

pub fn build_client_endpoint(
    bind_addr: SocketAddr,
    verify_cert: bool,
    max_data: u64,
    max_stream_data: u64,
    idle_timeout: u64,
    mtu: u64,
    ca_cert_path: Option<&str>,
) -> Result<(Endpoint, ClientConfig)> {
    let mut endpoint = Endpoint::client(bind_addr)?;
    let mut rustls_config = rustls::ClientConfig::builder()
        .with_root_certificates(load_roots(verify_cert, ca_cert_path)?)
        .with_no_client_auth();
    if !verify_cert {
        rustls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }
    let client_crypto = QuicClientConfig::try_from(rustls_config)?;
    let mut client_config = ClientConfig::new(Arc::new(client_crypto));

    let mut transport_config = TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0u32.into());
    transport_config.max_concurrent_bidi_streams(1024u32.into());
    transport_config.receive_window(VarInt::from_u64(max_data)?);
    transport_config.stream_receive_window(VarInt::from_u64(max_stream_data)?);
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(idle_timeout).try_into()?));
    transport_config.datagram_receive_buffer_size(Some(mtu as usize));
    client_config.transport_config(Arc::new(transport_config));

    endpoint.set_default_client_config(client_config.clone());
    Ok((endpoint, client_config))
}

pub fn build_server_config(
    cert_path: &str,
    key_path: &str,
    max_data: u64,
    max_stream_data: u64,
    idle_timeout: u64,
    mtu: u64,
) -> Result<ServerConfig> {
    let certs = read_certs(cert_path)?;
    let key = read_key(key_path)?;
    let rustls_server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let server_crypto = QuicServerConfig::try_from(rustls_server_config)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));
    let mut transport_config = TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0u32.into());
    transport_config.max_concurrent_bidi_streams(1024u32.into());
    transport_config.receive_window(VarInt::from_u64(max_data)?);
    transport_config.stream_receive_window(VarInt::from_u64(max_stream_data)?);
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(idle_timeout).try_into()?));
    transport_config.datagram_receive_buffer_size(Some(mtu as usize));
    server_config.transport_config(Arc::new(transport_config));
    Ok(server_config)
}

fn read_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn read_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if let Some(key) = keys.into_iter().next() {
        Ok(PrivateKeyDer::Pkcs8(key))
    } else {
        Err(anyhow!("no private key found"))
    }
}

fn load_roots(verify_cert: bool, ca_cert_path: Option<&str>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    if verify_cert {
        if let Some(path) = ca_cert_path {
            let certs = read_certs(path)?;
            for cert in certs {
                roots.add(&cert)?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    }
    Ok(roots)
}

struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

pub fn parse_target(header: &str, auth_code: &str) -> Result<(String, u16)> {
    if !header.starts_with(auth_code) {
        return Err(anyhow!("invalid auth"));
    }
    let payload = &header[auth_code.len()..];
    let parts: Vec<&str> = payload.split(',').collect();
    if parts.len() < 3 {
        return Err(anyhow!("invalid header"));
    }
    let socket_type = parts[1].to_string();
    let port: u16 = parts[2].parse()?;
    Ok((socket_type, port))
}

pub async fn read_header_with_payload(
    recv: &mut quinn::RecvStream,
) -> Result<(String, Vec<u8>)> {
    let delimiter = b",!###!";
    let mut buffer = Vec::new();
    loop {
        let mut chunk = vec![0u8; 1024];
        let size = recv.read(&mut chunk).await?.ok_or_else(|| anyhow!("stream closed"))?;
        buffer.extend_from_slice(&chunk[..size]);
        if let Some(pos) = buffer.windows(delimiter.len()).position(|w| w == delimiter) {
            let header_bytes = buffer[..pos].to_vec();
            let remaining = buffer[pos + delimiter.len()..].to_vec();
            let header = String::from_utf8(header_bytes)?;
            return Ok((header, remaining));
        }
    }
}

pub fn parse_socket_addr(ip: &str, port: u16) -> Result<SocketAddr> {
    let addr: IpAddr = ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    Ok(SocketAddr::new(addr, port))
}
