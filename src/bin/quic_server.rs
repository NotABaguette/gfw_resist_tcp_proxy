use anyhow::{anyhow, Result};
use clap::Parser;
use gfw_resist_tcp_proxy::config::load_config;
use gfw_resist_tcp_proxy::quic::{
    build_server_config, parse_socket_addr, parse_target, read_header_with_payload,
};
use quinn::{Connecting, Connection, Endpoint};
use socket2::SockRef;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "quic-server")]
struct Args {
    #[arg(long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = load_config(args.config.as_deref())?;

    let server_config = build_server_config(
        &config.quic_cert_filepath.0,
        &config.quic_cert_filepath.1,
        config.quic_max_data,
        config.quic_max_stream_data,
        config.quic_idle_timeout,
        config.quic_mtu,
    )?;

    let bind_addr = parse_socket_addr("0.0.0.0", config.quic_server_port)?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    info!("Server listening for QUIC on port {}", config.quic_server_port);

    loop {
        let Some(connecting) = endpoint.accept().await else {
            break;
        };
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(connecting, config).await {
                warn!("connection error: {err}");
            }
        });
    }
}

async fn handle_connection(connecting: Connecting, config: gfw_resist_tcp_proxy::config::Config) -> Result<()> {
    let connection = connecting.await?;
    info!("QUIC connection accepted from {}", connection.remote_address());

    loop {
        let stream = connection.accept_bi().await;
        let config = config.clone();
        match stream {
            Ok((send, recv)) => {
                tokio::spawn(async move {
                    if let Err(err) = handle_stream(connection.clone(), send, recv, config).await {
                        warn!("stream error: {err}");
                    }
                });
            }
            Err(err) => {
                warn!("accept stream error: {err}");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_stream(
    _connection: Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    config: gfw_resist_tcp_proxy::config::Config,
) -> Result<()> {
    let mut recv = recv;
    let mut send = send;
    let (header, mut remaining) = read_header_with_payload(&mut recv).await?;
    let (socket_type, port) = parse_target(&header, &config.quic_auth_code)?;

    match socket_type.as_str() {
        "tcp" => handle_tcp_stream(send, recv, &config, port, &mut remaining).await,
        "udp" => handle_udp_stream(send, recv, &config, port, &mut remaining).await,
        _ => Err(anyhow!("unknown socket type")),
    }
}

async fn handle_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    config: &gfw_resist_tcp_proxy::config::Config,
    port: u16,
    remaining: &mut Vec<u8>,
) -> Result<()> {
    let target = SocketAddr::new(config.xray_server_ip_address.parse()?, port);
    let mut tcp = tokio::net::TcpStream::connect(target).await?;
    tcp.set_nodelay(true)?;
    tune_tcp_socket(&tcp, config.tcp_buffer_bytes)?;

    let ready = format!("{}i am ready,!###!", config.quic_auth_code);
    send.write_all(ready.as_bytes()).await?;
    if !remaining.is_empty() {
        tcp.write_all(remaining).await?;
        remaining.clear();
    }

    let (mut tcp_read, mut tcp_write) = tcp.split();

    let tcp_to_quic = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let size = tcp_read.read(&mut buf).await?;
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
            tcp_write.write_all(&buf[..size]).await?;
        }
        Result::<()>::Ok(())
    });

    let _ = tokio::try_join!(tcp_to_quic, quic_to_tcp)?;
    Ok(())
}

async fn handle_udp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    config: &gfw_resist_tcp_proxy::config::Config,
    port: u16,
    remaining: &mut Vec<u8>,
) -> Result<()> {
    let target = SocketAddr::new(config.xray_server_ip_address.parse()?, port);
    let udp_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
    udp_socket.connect(target).await?;
    tune_udp_socket(&udp_socket, config.udp_buffer_bytes)?;

    if !remaining.is_empty() {
        udp_socket.send(remaining).await?;
        remaining.clear();
    }

    let udp_recv = udp_socket.try_clone()?;
    let udp_timeout = config.udp_timeout;

    let udp_to_quic = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut last_activity = std::time::Instant::now();
        loop {
            tokio::select! {
                recv = udp_recv.recv(&mut buf) => {
                    let size = recv?;
                    if size == 0 {
                        continue;
                    }
                    last_activity = std::time::Instant::now();
                    send.write_all(&buf[..size]).await?;
                }
                _ = sleep(Duration::from_secs(udp_timeout)) => {
                    if last_activity.elapsed().as_secs() > udp_timeout {
                        break;
                    }
                }
            }
        }
        send.finish().await?;
        Result::<()>::Ok(())
    });

    let quic_to_udp = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let size = recv.read(&mut buf).await?;
            if size == 0 {
                break;
            }
            udp_socket.send(&buf[..size]).await?;
        }
        Result::<()>::Ok(())
    });

    let _ = tokio::try_join!(udp_to_quic, quic_to_udp)?;
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
