use anyhow::{anyhow, Result};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct Sniffer {
    stop: Arc<AtomicBool>,
}

impl Sniffer {
    pub fn spawn<F>(interface_name: Option<&str>, handler: F) -> Result<Self>
    where
        F: Fn(Vec<u8>, Ipv4Addr, u16, Ipv4Addr, u16) + Send + 'static + Clone,
    {
        let interfaces = datalink::interfaces();
        let interface = if let Some(name) = interface_name {
            interfaces
                .into_iter()
                .find(|iface| iface.name == name)
                .ok_or_else(|| anyhow!("interface {name} not found"))?
        } else {
            interfaces
                .into_iter()
                .find(|iface| iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4()))
                .ok_or_else(|| anyhow!("no suitable network interface found"))?
        };

        let (_, mut rx) = match datalink::channel(&interface, Default::default())? {
            Ethernet(tx, rx) => (tx, rx),
            _ => return Err(anyhow!("unsupported channel type")),
        };

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        std::thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                if let Ok(packet) = rx.next() {
                    process_packet(packet, &handler);
                }
            }
        });

        Ok(Self { stop })
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn process_packet<F>(packet: &[u8], handler: &F)
where
    F: Fn(Vec<u8>, Ipv4Addr, u16, Ipv4Addr, u16) + Clone,
{
    let ethernet = match EthernetPacket::new(packet) {
        Some(pkt) => pkt,
        None => return,
    };
    if ethernet.get_ethertype() != EtherTypes::Ipv4 {
        return;
    }
    let ipv4 = match Ipv4Packet::new(ethernet.payload()) {
        Some(pkt) => pkt,
        None => return,
    };
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return;
    }
    let tcp = match TcpPacket::new(ipv4.payload()) {
        Some(pkt) => pkt,
        None => return,
    };
    let flags = tcp.get_flags();
    if flags != (TcpFlags::ACK | TcpFlags::PSH) {
        return;
    }
    let payload = tcp.payload().to_vec();
    let src_ip = ipv4.get_source();
    let dst_ip = ipv4.get_destination();
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();
    handler(payload, src_ip, src_port, dst_ip, dst_port);
}
