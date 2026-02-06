use crate::config::Config;
use anyhow::Context;
use log::{info, warn};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum as ipv4_checksum, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum as tcp_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const TCP_HEADER_LEN: usize = 20;
const IPV4_HEADER_LEN: usize = 20;

#[derive(Clone, Debug, Default)]
struct ClientPeer {
    ip: Option<Ipv4Addr>,
    port: Option<u16>,
}

fn local_ipv4_for(remote: Ipv4Addr) -> anyhow::Result<Ipv4Addr> {
    let socket = StdUdpSocket::bind("0.0.0.0:0")?;
    socket.connect((remote, 9_999))?;
    let local_addr = socket.local_addr()?;
    match local_addr.ip() {
        IpAddr::V4(ip) => Ok(ip),
        _ => anyhow::bail!("expected IPv4 local address"),
    }
}

fn build_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN + TCP_HEADER_LEN + payload.len();
    let mut buffer = vec![0u8; total_len];

    let mut ip_packet = MutableIpv4Packet::new(&mut buffer).expect("ipv4 packet");
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(total_len as u16);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(src_ip);
    ip_packet.set_destination(dst_ip);

    let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).expect("tcp packet");
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(seq);
    tcp_packet.set_acknowledgement(ack);
    tcp_packet.set_flags(TcpFlags::PSH | TcpFlags::ACK);
    tcp_packet.set_window(65_535);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_payload(payload);

    let checksum = tcp_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
    tcp_packet.set_checksum(checksum);

    let checksum = ipv4_checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(checksum);

    buffer
}

fn send_raw_tcp(
    transport: &mut pnet::transport::TransportSender,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> anyhow::Result<()> {
    let packet = build_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, payload);
    transport.send_to(packet, IpAddr::V4(dst_ip))?;
    Ok(())
}

fn parse_ipv4_tcp_payload(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u16, u16, u8, Vec<u8>)> {
    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return None;
    }
    let ipv4 = Ipv4Packet::new(ethernet.payload())?;
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }
    let tcp = TcpPacket::new(ipv4.payload())?;
    let payload = tcp.payload().to_vec();
    Some((
        ipv4.get_source(),
        ipv4.get_destination(),
        tcp.get_source(),
        tcp.get_destination(),
        tcp.get_flags(),
        payload,
    ))
}

fn spawn_sniffer(
    config: Config,
    is_client: bool,
    sender: mpsc::Sender<(Vec<u8>, Ipv4Addr, u16)>,
) -> anyhow::Result<thread::JoinHandle<()>> {
    let device = if let Some(device_name) = &config.pcap_device {
        pcap::Device::list()?
            .into_iter()
            .find(|d| d.name == *device_name)
            .context("pcap device not found")?
    } else {
        pcap::Device::lookup().context("pcap lookup failed")?
    };

    let mut cap = pcap::Capture::from_device(device)?
        .promisc(true)
        .immediate_mode(true)
        .open()?;

    let filter = if is_client {
        format!(
            "tcp and src host {} and src port {}",
            config.vps_ip, config.vio_tcp_server_port
        )
    } else {
        format!(
            "tcp and dst host {} and dst port {}",
            config.vps_ip, config.vio_tcp_server_port
        )
    };
    cap.filter(&filter, true)?;

    info!("pcap sniffer started: {filter}");

    Ok(thread::spawn(move || {
        while let Ok(packet) = cap.next_packet() {
            if let Some((src_ip, dst_ip, src_port, dst_port, flags, payload)) =
                parse_ipv4_tcp_payload(packet.data)
            {
                if flags & (TcpFlags::PSH | TcpFlags::ACK) != (TcpFlags::PSH | TcpFlags::ACK) {
                    continue;
                }
                if is_client {
                    if src_ip.to_string() != config.vps_ip
                        || src_port != config.vio_tcp_server_port
                    {
                        continue;
                    }
                } else if dst_ip.to_string() != config.vps_ip
                    || dst_port != config.vio_tcp_server_port
                {
                    continue;
                }
                let _ = sender.blocking_send((payload, src_ip, src_port));
            }
        }
    }))
}

pub async fn run_vio_client(config: Config) -> anyhow::Result<()> {
    let vps_ip: Ipv4Addr = config.vps_ip.parse()?;
    let local_ip = local_ipv4_for(vps_ip)?;
    let (mut transport, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))?;

    let (sniff_tx, mut sniff_rx) = mpsc::channel::<(Vec<u8>, Ipv4Addr, u16)>(1024);
    let _sniffer = spawn_sniffer(config.clone(), true, sniff_tx)?;

    let udp_socket = Arc::new(UdpSocket::bind(("0.0.0.0", config.vio_udp_client_port)).await?);
    let quic_target: SocketAddr =
        format!("{}:{}", config.quic_local_ip, config.quic_client_port).parse()?;

    let sender_socket = udp_socket.clone();
    let sender_task = tokio::spawn(async move {
        while let Some((payload, _, _)) = sniff_rx.recv().await {
            if payload.is_empty() {
                continue;
            }
            let _ = sender_socket.send_to(&payload, quic_target).await;
        }
    });

    let recv_socket = udp_socket.clone();
    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok((len, _)) = recv_socket.recv_from(&mut buf).await else {
                break;
            };
            if len == 0 {
                continue;
            }
            if let Err(err) = send_raw_tcp(
                &mut transport,
                local_ip,
                vps_ip,
                config.vio_tcp_client_port,
                config.vio_tcp_server_port,
                0,
                0,
                &buf[..len],
            ) {
                warn!("send raw tcp failed: {err}");
            }
        }
    });

    let _ = tokio::join!(sender_task, recv_task);
    Ok(())
}

pub async fn run_vio_server(config: Config) -> anyhow::Result<()> {
    let vps_ip: Ipv4Addr = config.vps_ip.parse()?;
    let local_ip = local_ipv4_for(vps_ip)?;
    let (mut transport, _) = transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))?;

    let (sniff_tx, mut sniff_rx) = mpsc::channel::<(Vec<u8>, Ipv4Addr, u16)>(1024);
    let _sniffer = spawn_sniffer(config.clone(), false, sniff_tx)?;

    let udp_socket = Arc::new(UdpSocket::bind(("0.0.0.0", config.vio_udp_server_port)).await?);
    let quic_target: SocketAddr =
        format!("{}:{}", config.quic_local_ip, config.quic_server_port).parse()?;

    let client_peer = Arc::new(Mutex::new(ClientPeer::default()));
    let peer_sender = client_peer.clone();

    let sender_socket = udp_socket.clone();
    let sender_task = tokio::spawn(async move {
        while let Some((payload, ip, port)) = sniff_rx.recv().await {
            if payload.is_empty() {
                continue;
            }
            {
                let mut peer = peer_sender.lock().expect("peer lock");
                peer.ip = Some(ip);
                peer.port = Some(port);
            }
            let _ = sender_socket.send_to(&payload, quic_target).await;
        }
    });

    let peer_receiver = client_peer.clone();
    let recv_socket = udp_socket.clone();
    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok((len, _)) = recv_socket.recv_from(&mut buf).await else {
                break;
            };
            if len == 0 {
                continue;
            }
            let (peer_ip, peer_port) = {
                let peer = peer_receiver.lock().expect("peer lock");
                (peer.ip, peer.port)
            };
            let (Some(peer_ip), Some(peer_port)) = (peer_ip, peer_port) else {
                warn!("no client peer yet, dropping packet");
                continue;
            };
            if let Err(err) = send_raw_tcp(
                &mut transport,
                local_ip,
                peer_ip,
                config.vio_tcp_server_port,
                peer_port,
                1,
                0,
                &buf[..len],
            ) {
                warn!("send raw tcp failed: {err}");
            }
        }
    });

    let _ = tokio::join!(sender_task, recv_task);
    Ok(())
}
