use anyhow::{anyhow, Result};
use clap::Parser;
use gfw_resist_tcp_proxy::config::load_config;
use dashmap::DashMap;
use gfw_resist_tcp_proxy::quic::{build_client_endpoint, parse_socket_addr, read_header_with_payload};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};
use futures::future::join_all;

#[derive(Parser, Debug)]
#[command(name = "quic-client")]
struct Args {
    #[arg(long)]
    config: Option<String>,
}

#[derive(Clone)]
struct UdpStreamEntry {
    send: Arc<tokio::sync::Mutex<SendStream>>,
    last_activity: Arc<tokio::sync::Mutex<std::time::Instant>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = load_config(args.config.as_deref())?;
    let bind_addr = parse_socket_addr("0.0.0.0", config.quic_client_port)?;

    let (endpoint, _client_cfg) = build_client_endpoint(
        bind_addr,
        config.quic_verify_cert,
        config.quic_max_data,
        config.quic_max_stream_data,
        config.quic_idle_timeout,
        config.quic_mtu,
        None,
    )?;

    let server_addr = SocketAddr::new(IpAddr::V4(config.quic_local_ip.parse()?), config.vio_udp_client_port);
    info!("Attempting to connect to QUIC server at {server_addr}");
    let connection = endpoint.connect(server_addr, "gfw-resist")?.await?;
    info!("Quic Established");

    let tcp_map = Arc::new(config.tcp_port_mapping);
    let udp_map = Arc::new(config.udp_port_mapping);
    let udp_entries: Arc<DashMap<SocketAddr, UdpStreamEntry>> = Arc::new(DashMap::new());

    let mut tcp_tasks = Vec::new();
    for (local_port, target_port) in tcp_map.iter() {
        let connection = connection.clone();
        let auth = config.quic_auth_code.clone();
        let local_port = *local_port;
        let target_port = *target_port;
        let tcp_buffer_bytes = config.tcp_buffer_bytes;
        tcp_tasks.push(tokio::spawn(async move {
            if let Err(err) = run_tcp_listener(connection, auth, local_port, target_port, tcp_buffer_bytes).await {
                warn!("tcp listener error: {err}");
            }
        }));
    }

    let mut udp_tasks = Vec::new();
    for (local_port, target_port) in udp_map.iter() {
        let connection = connection.clone();
        let auth = config.quic_auth_code.clone();
        let entries = Arc::clone(&udp_entries);
        let local_port = *local_port;
        let target_port = *target_port;
        let udp_buffer_bytes = config.udp_buffer_bytes;
        udp_tasks.push(tokio::spawn(async move {
            if let Err(err) = run_udp_listener(connection, auth, entries, local_port, target_port, udp_buffer_bytes).await {
                warn!("udp listener error: {err}");
            }
        }));
    }

    let cleanup_entries = Arc::clone(&udp_entries);
    let udp_timeout = config.udp_timeout;
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(std::cmp::min(udp_timeout, 60))).await;
            let now = std::time::Instant::now();
            cleanup_entries.retain(|_addr, entry| {
                let last = entry.last_activity.blocking_lock();
                now.duration_since(*last) < Duration::from_secs(udp_timeout)
            });
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received");
        }
        _ = join_all(tcp_tasks) => {}
        _ = join_all(udp_tasks) => {}
    }

    Ok(())
}

async fn run_tcp_listener(
    connection: Connection,
    auth_code: String,
    local_port: u16,
    target_port: u16,
    tcp_buffer_bytes: usize,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        local_port,
    ))
    .await?;
    info!("client listen tcp:{local_port} -> server tcp:{target_port}");
    loop {
        let (mut stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        tune_tcp_socket(&stream, tcp_buffer_bytes)?;
        let connection = connection.clone();
        let auth_code = auth_code.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_tcp_stream(connection, auth_code, target_port, &mut stream).await {
                warn!("tcp stream error: {err}");
            }
        });
    }
}

async fn handle_tcp_stream(
    connection: Connection,
    auth_code: String,
    target_port: u16,
    stream: &mut tokio::net::TcpStream,
) -> Result<()> {
    let (mut send, mut recv) = connection.open_bi().await?;
    let header = format!("{}connect,tcp,{},!###!", auth_code, target_port);
    send.write_all(header.as_bytes()).await?;

    let (ready_header, remaining) = read_header_with_payload(&mut recv).await?;
    if ready_header != format!("{}i am ready", auth_code) {
        return Err(anyhow!("invalid ready header"));
    }
    if !remaining.is_empty() {
        stream.write_all(&remaining).await?;
    }

    let (mut read_half, mut write_half) = stream.split();
    let tcp_to_quic = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let size = read_half.read(&mut buf).await?;
            if size == 0 {
                break;
            }
            send.write_all(&buf[..size]).await?;
        }
        send.finish().await?;
        Result::<()>::Ok(())
    });

    let quic_to_tcp = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let size = recv.read(&mut buf).await?;
            if size == 0 {
                break;
            }
            write_half.write_all(&buf[..size]).await?;
        }
        Result::<()>::Ok(())
    });

    let _ = tokio::try_join!(tcp_to_quic, quic_to_tcp)?;
    Ok(())
}

async fn run_udp_listener(
    connection: Connection,
    auth_code: String,
    entries: Arc<DashMap<SocketAddr, UdpStreamEntry>>,
    local_port: u16,
    target_port: u16,
    udp_buffer_bytes: usize,
) -> Result<()> {
    let socket = tokio::net::UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        local_port,
    ))
    .await?;
    tune_udp_socket(&socket, udp_buffer_bytes)?;
    info!("client listen udp:{local_port} -> server udp:{target_port}");
    let mut buf = vec![0u8; 2048];
    loop {
        let (size, addr) = socket.recv_from(&mut buf).await?;
        let entry = if let Some(entry) = entries.get(&addr) {
            entry.value().clone()
        } else {
            let (send, recv) = connection.open_bi().await?;
            let header = format!("{}connect,udp,{},!###!", auth_code, target_port);
            send.write_all(header.as_bytes()).await?;
            let entry = UdpStreamEntry {
                send: Arc::new(tokio::sync::Mutex::new(send)),
                last_activity: Arc::new(tokio::sync::Mutex::new(std::time::Instant::now())),
            };
            entries.insert(addr, entry.clone());
            let socket_clone = socket.try_clone()?;
            let recv_task = recv;
            tokio::spawn(async move {
                if let Err(err) = forward_quic_to_udp(recv_task, socket_clone, addr).await {
                    warn!("udp stream recv error: {err}");
                }
            });
            entry
        };
        {
            let mut last = entry.last_activity.lock().await;
            *last = std::time::Instant::now();
        }
        let mut send_guard = entry.send.lock().await;
        send_guard.write_all(&buf[..size]).await?;
    }
}

async fn forward_quic_to_udp(
    mut recv: RecvStream,
    socket: tokio::net::UdpSocket,
    addr: SocketAddr,
) -> Result<()> {
    let mut buf = vec![0u8; 2048];
    loop {
        let size = recv.read(&mut buf).await?;
        if size == 0 {
            break;
        }
        socket.send_to(&buf[..size], addr).await?;
    }
    Ok(())
}

fn tune_udp_socket(socket: &tokio::net::UdpSocket, bytes: usize) -> Result<()> {
    let sock = SockRef::from(socket);
    sock.set_recv_buffer_size(bytes)?;
    sock.set_send_buffer_size(bytes)?;
    Ok(())
}

fn tune_tcp_socket(socket: &tokio::net::TcpStream, bytes: usize) -> Result<()> {
    let sock = SockRef::from(socket);
    sock.set_recv_buffer_size(bytes)?;
    sock.set_send_buffer_size(bytes)?;
    Ok(())
}
