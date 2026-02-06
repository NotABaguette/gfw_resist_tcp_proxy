use crate::config::Config;
use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use log::{info, warn};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::SignatureScheme;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::collections::HashMap;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};

const HEADER_DELIM: &[u8] = b",!###!";

fn build_auth_header(auth: &str, proto: &str, port: u16) -> String {
    format!("{auth}connect,{proto},{port},!###!")
}

async fn read_header(recv: &mut RecvStream) -> anyhow::Result<(String, BytesMut)> {
    let mut buffer = BytesMut::new();
    loop {
        let mut chunk = vec![0u8; 4096];
        let n = recv.read(&mut chunk).await?;
        let n = n.ok_or_else(|| anyhow!("stream closed"))?;
        if n == 0 {
            return Err(anyhow!("stream closed"));
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(index) = buffer.windows(HEADER_DELIM.len()).position(|w| w == HEADER_DELIM) {
            let header = buffer.split_to(index + HEADER_DELIM.len());
            let remainder = buffer.split();
            let header_str = String::from_utf8_lossy(&header).to_string();
            return Ok((header_str, remainder));
        }
    }
}

async fn read_until_ready(auth: &str, recv: &mut RecvStream) -> anyhow::Result<BytesMut> {
    let expected = format!("{auth}i am ready,!###!");
    let (header, remainder) = read_header(recv).await?;
    if header != expected {
        return Err(anyhow!("unexpected server header: {header}"));
    }
    Ok(remainder)
}

fn make_client_config(config: &Config) -> anyhow::Result<ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    if !config.quic_verify_cert {
        crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(AcceptAnyCertVerifier));
    }

    let mut client_config = ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(config.quic_idle_timeout))?,
    ));
    transport
        .max_udp_payload_size(Some(config.quic_mtu.into()))
        .max_concurrent_bidi_streams(1_000u32.into())
        .max_concurrent_uni_streams(1_000u32.into());
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

fn parse_cert_chain(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut cursor = Cursor::new(pem);
    let certs = certs(&mut cursor)?
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(anyhow!("no certificates found"));
    }
    Ok(certs)
}

fn parse_private_key(pem: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(pem);
    let keys = pkcs8_private_keys(&mut cursor)?;
    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no private key found"))?;
    Ok(PrivateKeyDer::Pkcs8(key))
}

fn make_server_config(config: &Config) -> anyhow::Result<ServerConfig> {
    let (cert_path, key_path) = &config.quic_cert_filepath;
    let cert = std::fs::read(cert_path).ok();
    let key = std::fs::read(key_path).ok();

    let (certs, key) = if let (Some(cert), Some(key)) = (cert, key) {
        (parse_cert_chain(&cert)?, parse_private_key(&key)?)
    } else {
        warn!("cert files not found, generating self-signed cert");
        let cert = generate_simple_self_signed(["localhost".to_string()])?;
        let key = PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());
        (vec![CertificateDer::from(cert.serialize_der()?)], key)
    };

    let mut server_config = ServerConfig::with_single_cert(certs, key)?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(config.quic_idle_timeout))?,
    ));
    transport
        .max_udp_payload_size(Some(config.quic_mtu.into()))
        .max_concurrent_bidi_streams(1_000u32.into())
        .max_concurrent_uni_streams(1_000u32.into());
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

pub async fn run_quic_client(config: Config) -> anyhow::Result<()> {
    let local_addr: SocketAddr = format!("0.0.0.0:{}", config.quic_client_port).parse()?;
    let mut endpoint = Endpoint::client(local_addr)?;
    endpoint.set_default_client_config(make_client_config(&config)?);

    let remote_addr: SocketAddr =
        format!("{}:{}", config.quic_local_ip, config.vio_udp_client_port).parse()?;
    info!("connecting to quic tunnel at {remote_addr}");

    let server_name = if config.quic_verify_cert {
        ServerName::try_from("localhost")?
    } else {
        let ip: IpAddr = remote_addr.ip();
        ServerName::try_from(ip)?
    };

    let connection = endpoint
        .connect(remote_addr, server_name)
        .context("connect failed")?
        .await?;
    info!("quic connection established");

    let connection = Arc::new(connection);

    for (listen_port, target_port) in config.tcp_port_mapping.clone() {
        let connection = connection.clone();
        let auth = config.quic_auth_code.clone();
        tokio::spawn(async move {
            if let Err(err) = tcp_listener_loop(listen_port, target_port, connection, auth).await {
                warn!("tcp listener error: {err}");
            }
        });
    }

    for (listen_port, target_port) in config.udp_port_mapping.clone() {
        let connection = connection.clone();
        let auth = config.quic_auth_code.clone();
        let udp_timeout = config.udp_timeout;
        tokio::spawn(async move {
            if let Err(err) =
                udp_listener_loop(listen_port, target_port, connection, auth, udp_timeout).await
            {
                warn!("udp listener error: {err}");
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn tcp_listener_loop(
    listen_port: u16,
    target_port: u16,
    connection: Arc<Connection>,
    auth: String,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", listen_port)).await?;
    info!("client listen tcp:{listen_port} -> server tcp:{target_port}");
    loop {
        let (stream, _) = listener.accept().await?;
        let connection = connection.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_tcp_client(stream, target_port, connection, auth).await {
                warn!("tcp client handler error: {err}");
            }
        });
    }
}

async fn handle_tcp_client(
    mut stream: TcpStream,
    target_port: u16,
    connection: Arc<Connection>,
    auth: String,
) -> anyhow::Result<()> {
    let (mut send, mut recv) = connection.open_bi().await?;
    let header = build_auth_header(&auth, "tcp", target_port);
    send.write_all(header.as_bytes()).await?;
    send.flush().await?;

    let remainder = read_until_ready(&auth, &mut recv).await?;

    if !remainder.is_empty() {
        stream.write_all(&remainder).await?;
    }

    let (mut tcp_reader, mut tcp_writer) = stream.into_split();
    let send_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = tcp_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await?;
            send.flush().await?;
        }
        send.finish()?;
        Ok::<_, anyhow::Error>(())
    });

    let recv_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = recv.read(&mut buf).await?;
            let Some(n) = n else { break };
            if n == 0 {
                break;
            }
            tcp_writer.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    let _ = tokio::try_join!(send_task, recv_task)?;
    Ok(())
}

struct UdpStreamHandle {
    sender: mpsc::Sender<Bytes>,
    last_activity: Arc<Mutex<Instant>>,
}

async fn udp_listener_loop(
    listen_port: u16,
    target_port: u16,
    connection: Arc<Connection>,
    auth: String,
    udp_timeout: u64,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", listen_port)).await?);
    info!("client listen udp:{listen_port} -> server udp:{target_port}");

    let streams: Arc<Mutex<HashMap<SocketAddr, UdpStreamHandle>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let cleanup_streams = streams.clone();
    tokio::spawn(async move {
        let interval = Duration::from_secs(std::cmp::min(udp_timeout, 60));
        loop {
            tokio::time::sleep(interval).await;
            let mut map = cleanup_streams.lock().await;
            let now = Instant::now();
            let mut to_remove = Vec::new();
            for (addr, handle) in map.iter() {
                let last = *handle.last_activity.lock().await;
                if now.duration_since(last) > Duration::from_secs(udp_timeout) {
                    to_remove.push(*addr);
                }
            }
            for addr in to_remove {
                warn!("udp idle timeout for {addr}");
                map.remove(&addr);
            }
        }
    });

    let mut buf = vec![0u8; 2048];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let data = Bytes::copy_from_slice(&buf[..len]);

        let sender = {
            let mut map = streams.lock().await;
            if let Some(handle) = map.get(&addr) {
                *handle.last_activity.lock().await = Instant::now();
                handle.sender.clone()
            } else {
        let (send, recv) = connection.open_bi().await?;
                let header = build_auth_header(&auth, "udp", target_port);
                let (tx, mut rx) = mpsc::channel::<Bytes>(1024);
                let last_activity = Arc::new(Mutex::new(Instant::now()));
                let handle = UdpStreamHandle {
                    sender: tx.clone(),
                    last_activity: last_activity.clone(),
                };
                map.insert(addr, handle);

                let socket_clone = socket.clone();
                tokio::spawn(async move {
                    if let Err(err) = udp_stream_sender(send, header, &mut rx).await {
                        warn!("udp stream sender error: {err}");
                    }
                });

                tokio::spawn(async move {
                    if let Err(err) = udp_stream_receiver(recv, socket_clone, addr, last_activity).await {
                        warn!("udp stream receiver error: {err}");
                    }
                });

                tx
            }
        };

        let _ = sender.send(data).await;
    }
}

async fn udp_stream_sender(
    mut send: SendStream,
    header: String,
    rx: &mut mpsc::Receiver<Bytes>,
) -> anyhow::Result<()> {
    send.write_all(header.as_bytes()).await?;
    send.flush().await?;
    while let Some(data) = rx.recv().await {
        send.write_all(&data).await?;
        send.flush().await?;
    }
    send.finish()?;
    Ok(())
}

async fn udp_stream_receiver(
    mut recv: RecvStream,
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    last_activity: Arc<Mutex<Instant>>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 2048];
    loop {
        let n = recv.read(&mut buf).await?;
        let Some(n) = n else { break };
        if n == 0 {
            break;
        }
        socket.send_to(&buf[..n], addr).await?;
        *last_activity.lock().await = Instant::now();
    }
    Ok(())
}

pub async fn run_quic_server(config: Config) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{}", config.quic_server_port).parse()?;
    let endpoint = Endpoint::server(make_server_config(&config)?, addr)?;

    info!("server listening for quic on port {}", config.quic_server_port);

    loop {
        let incoming = endpoint.accept().await;
        let config = config.clone();
        tokio::spawn(async move {
            if let Some(connecting) = incoming {
                match connecting.await {
                    Ok(connection) => {
                        info!("new quic connection from {}", connection.remote_address());
                        if let Err(err) = handle_quic_connection(connection, config).await {
                            warn!("connection handler error: {err}");
                        }
                    }
                    Err(err) => warn!("failed to accept quic connection: {err}"),
                }
            }
        });
    }
}

async fn handle_quic_connection(connection: Connection, config: Config) -> anyhow::Result<()> {
    loop {
        let (send, recv) = connection.accept_bi().await?;
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_quic_stream(send, recv, config).await {
                warn!("stream handler error: {err}");
            }
        });
    }
}

async fn handle_quic_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    config: Config,
) -> anyhow::Result<()> {
    let (header, remainder) = read_header(&mut recv).await?;
    let header_clean = header.trim_end_matches(String::from_utf8_lossy(HEADER_DELIM).as_ref());

    let auth_prefix = format!("{}connect,", config.quic_auth_code);
    if !header_clean.starts_with(&auth_prefix) {
        return Err(anyhow!("invalid auth header"));
    }
    let rest = header_clean.strip_prefix(&auth_prefix).unwrap_or("");
    let mut parts = rest.splitn(2, ',');
    let proto = parts.next().unwrap_or("");
    let port_str = parts.next().unwrap_or("");
    let port: u16 = port_str.parse().context("invalid port")?;

    match proto {
        "tcp" => handle_server_tcp(send, recv, port, config, remainder).await,
        "udp" => handle_server_udp(send, recv, port, config, remainder).await,
        _ => Err(anyhow!("unknown protocol: {proto}")),
    }
}

async fn handle_server_tcp(
    mut send: SendStream,
    mut recv: RecvStream,
    port: u16,
    config: Config,
    remainder: BytesMut,
) -> anyhow::Result<()> {
    let target: SocketAddr = format!("{}:{}", config.xray_server_ip_address, port).parse()?;
    let stream = TcpStream::connect(target).await?;
    let (mut tcp_reader, mut tcp_writer) = stream.into_split();

    let ready = format!("{}i am ready,!###!", config.quic_auth_code);
    send.write_all(ready.as_bytes()).await?;
    send.flush().await?;

    if !remainder.is_empty() {
        tcp_writer.write_all(&remainder).await?;
    }

    let send_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = tcp_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await?;
            send.flush().await?;
        }
        send.finish()?;
        Ok::<_, anyhow::Error>(())
    });

    let recv_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = recv.read(&mut buf).await?;
            let Some(n) = n else { break };
            if n == 0 {
                break;
            }
            tcp_writer.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    let _ = tokio::try_join!(send_task, recv_task)?;
    Ok(())
}

async fn handle_server_udp(
    mut send: SendStream,
    mut recv: RecvStream,
    port: u16,
    config: Config,
    remainder: BytesMut,
) -> anyhow::Result<()> {
    let target: SocketAddr = format!("{}:{}", config.xray_server_ip_address, port).parse()?;
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await?);
    socket.connect(target).await?;

    if !remainder.is_empty() {
        socket.send(&remainder).await?;
    }

    let socket_clone = socket.clone();
    let send_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let n = socket_clone.recv(&mut buf).await?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await?;
            send.flush().await?;
        }
        send.finish()?;
        Ok::<_, anyhow::Error>(())
    });

    let recv_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
        let n = recv.read(&mut buf).await?;
        let Some(n) = n else { break };
        if n == 0 {
            break;
        }
        socket.send(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    let _ = tokio::try_join!(send_task, recv_task)?;
    Ok(())
}

#[derive(Debug)]
struct AcceptAnyCertVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
