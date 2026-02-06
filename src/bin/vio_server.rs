use anyhow::Result;
use clap::Parser;
use gfw_resist_tcp_proxy::config::load_config;
use gfw_resist_tcp_proxy::packet::RawSender;
use gfw_resist_tcp_proxy::sniffer::Sniffer;
use socket2::SockRef;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "vio-server")]
struct Args {
    #[arg(long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = load_config(args.config.as_deref())?;
    let vps_ip: Ipv4Addr = config.vps_ip.parse()?;

    let (tx, mut rx) = mpsc::unbounded_channel::<(Vec<u8>, Ipv4Addr, u16)>();
    let client_addr = Arc::new(Mutex::new(None));

    let vio_port = config.vio_tcp_server_port;
    let client_addr_clone = Arc::clone(&client_addr);
    let sniffer = Sniffer::spawn(
        config.capture_interface.as_deref(),
        move |payload, src_ip, src_port, dst_ip, dst_port| {
            if dst_ip == vps_ip && dst_port == vio_port {
                if let Ok(mut addr) = client_addr_clone.lock() {
                    *addr = Some((src_ip, src_port));
                }
                let _ = tx.send((payload, src_ip, src_port));
            }
        },
    )?;

    let mut raw_sender = RawSender::new()?;
    let udp_socket = tokio::net::UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        config.vio_udp_server_port,
    ))
    .await?;
    tune_udp_socket(&udp_socket, config.udp_buffer_bytes)?;
    udp_socket
        .connect(SocketAddr::new(
            IpAddr::V4(config.quic_local_ip.parse()?),
            config.quic_server_port,
        ))
        .await?;

    info!(
        "violated tcp:{} -> quic {}:{}",
        config.vio_tcp_server_port, config.quic_local_ip, config.quic_server_port
    );

    let udp_recv = udp_socket.try_clone()?;
    let client_addr_send = Arc::clone(&client_addr);
    let send_task = tokio::spawn(async move {
        while let Some((payload, _src_ip, _src_port)) = rx.recv().await {
            if let Err(err) = udp_socket.send(&payload).await {
                warn!("udp send error: {err}");
                break;
            }
        }
        drop(client_addr_send);
    });

    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let size = match udp_recv.recv(&mut buf).await {
                Ok(size) => size,
                Err(err) => {
                    warn!("udp recv error: {err}");
                    break;
                }
            };
            if size == 0 {
                continue;
            }
            let (client_ip, client_port) = match client_addr.lock() {
                Ok(guard) => guard.unwrap_or((Ipv4Addr::UNSPECIFIED, 0)),
                Err(_) => (Ipv4Addr::UNSPECIFIED, 0),
            };
            if client_port == 0 {
                continue;
            }
            if let Err(err) = raw_sender.send_tcp(
                vps_ip,
                client_ip,
                config.vio_tcp_server_port,
                client_port,
                1,
                0,
                &buf[..size],
            ) {
                warn!("raw send error: {err}");
                break;
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received");
        }
    }

    sniffer.stop();
    Ok(())
}

fn tune_udp_socket(socket: &tokio::net::UdpSocket, bytes: usize) -> Result<()> {
    let sock = SockRef::from(socket);
    sock.set_recv_buffer_size(bytes)?;
    sock.set_send_buffer_size(bytes)?;
    Ok(())
}
