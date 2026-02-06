use anyhow::{anyhow, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::packet::MutablePacket;
use pnet::transport::{transport_channel, TransportChannelType, TransportSender};
use std::net::Ipv4Addr;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;

pub struct RawSender {
    sender: TransportSender,
}

impl RawSender {
    pub fn new() -> Result<Self> {
        let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
        let (sender, _) = transport_channel(65535, protocol)?;
        Ok(Self { sender })
    }

    pub fn send_tcp(
        &mut self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Result<()> {
        let options = build_tcp_options();
        let tcp_header_len = TCP_HEADER_LEN + options.len();
        let total_len = IPV4_HEADER_LEN + tcp_header_len + payload.len();
        let mut buffer = vec![0u8; total_len];

        {
            let mut ip_packet = MutableIpv4Packet::new(&mut buffer).ok_or_else(|| anyhow!("ip packet"))?;
            ip_packet.set_version(4);
            ip_packet.set_header_length((IPV4_HEADER_LEN / 4) as u8);
            ip_packet.set_total_length(total_len as u16);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(src_ip);
            ip_packet.set_destination(dst_ip);
        }

        let mut tcp_packet = MutableTcpPacket::new(&mut buffer[IPV4_HEADER_LEN..])
            .ok_or_else(|| anyhow!("tcp packet"))?;
        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_sequence(seq);
        tcp_packet.set_acknowledgement(ack);
        tcp_packet.set_flags(TcpFlags::ACK | TcpFlags::PSH);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(((TCP_HEADER_LEN + options.len()) / 4) as u8);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_payload(payload);
        tcp_packet.payload_mut()[0..payload.len()].copy_from_slice(payload);
        let option_start = TCP_HEADER_LEN;
        tcp_packet.packet_mut()[option_start..option_start + options.len()].copy_from_slice(&options);
        let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
        tcp_packet.set_checksum(checksum);

        let ip_packet = Ipv4Packet::new(&buffer).ok_or_else(|| anyhow!("final ip packet"))?;
        self.sender
            .send_to(ip_packet, std::net::IpAddr::V4(dst_ip))
            .map(|_| ())
            .map_err(|e| anyhow!("send error: {e}"))
    }
}

fn build_tcp_options() -> Vec<u8> {
    let mss: u16 = 1280;
    let mut options = vec![
        2, 4, (mss >> 8) as u8, (mss & 0xff) as u8, // MSS
        3, 3, 8, // Window Scale
        4, 2, // SACK permitted
    ];
    while options.len() % 4 != 0 {
        options.push(1); // NOP
    }
    options
}
