use anyhow::Result;
use clap::Parser;
use gfw_resist_tcp_proxy::config::load_config;
use gfw_resist_tcp_proxy::packet::RawSender;
use gfw_resist_tcp_proxy::sniffer::Sniffer;
use socket2::SockRef;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::mpsc;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "vio-client")]
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

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let vio_port = config.vio_tcp_server_port;
    let sniffer = Sniffer::spawn(
        config.capture_interface.as_deref(),
        move |payload, src_ip, src_port, _dst_ip, _dst_port| {
            if src_ip == vps_ip && src_port == vio_port {
                let _ = tx.send(payload);
            }
        },
    )?;

    let local_ip = determine_local_ip(IpAddr::V4(vps_ip))?;
    let mut raw_sender = RawSender::new()?;
    let udp_socket = tokio::net::UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        config.vio_udp_client_port,
    ))
    .await?;
    tune_udp_socket(&udp_socket, config.udp_buffer_bytes)?;
    udp_socket
        .connect(SocketAddr::new(
            IpAddr::V4(config.quic_local_ip.parse()?),
            config.quic_client_port,
        ))
        .await?;

    info!(
        "vio client listen udp:{} -> violated tcp:{}",
        config.vio_udp_client_port, config.vio_tcp_server_port
    );

    let udp_recv = udp_socket.try_clone()?;
    let vps_ip_copy = vps_ip;
    let local_ip_copy = local_ip;
    let vio_tcp_client_port = config.vio_tcp_client_port;
    let send_task = tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            if let Err(err) = udp_socket.send(&payload).await {
                warn!("udp send error: {err}");
                break;
            }
        }
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
            if let Err(err) = raw_sender.send_tcp(
                local_ip_copy,
                vps_ip_copy,
                vio_tcp_client_port,
                config.vio_tcp_server_port,
                0,
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

fn determine_local_ip(target: IpAddr) -> Result<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
    socket.connect((target, 9))?;
    match socket.local_addr()?.ip() {
        IpAddr::V4(addr) => Ok(addr),
        IpAddr::V6(_) => Ok(Ipv4Addr::UNSPECIFIED),
    }
}

fn tune_udp_socket(socket: &tokio::net::UdpSocket, bytes: usize) -> Result<()> {
    let sock = SockRef::from(socket);
    sock.set_recv_buffer_size(bytes)?;
    sock.set_send_buffer_size(bytes)?;
    Ok(())
}
