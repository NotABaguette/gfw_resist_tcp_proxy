توجه: این متد اتصال، در قطعی اینترنت ناشی از سرکوب خونین مردم در دیماه 1404 کاملا جواب میدهد. اما نیاز به خط اینترنت ثابت و دسترسی روت هم در vps و هم در pc دارد. در تلاش هستیم نسخه باینری تهیه کنیم که راه اندازی آن را ساده کند. ( در نت موبایل ، 4g ، tl-lte و دانگل و هات اسپات و امثالهم جواب نمیدهد چون نیازمند ارسال پکت نامتعارف به شبکه است اما در خطوط ثابت و مودم های adsl استاندارد و همچنین سرور ایران که نت پهن باند دارند قابل استفاده است )

نمونه پیاده شده با زبان گو :  (https://github.com/hanselime/paqet)
# gfw_resist_tcp_proxy
knock up GFW IP blockage

# goodbye IP filtering & goodbye GFW mf'er
<img src="/meme.jpg?raw=true" width="300" >
<br>

# main Idea -> TCP violation:
- GFW needs to check every packet against large list of filtered ip in order to drop them<br>
- since its not practical in huge traffic, they separate tcp handshake (SYN) and check them only.<br>
- in fact, they only drop SYN packet with blocked ip in both direction.
- so we can bypass ip filtering by building communication link without tcp handshake.<br><br>
<img src="/slide1.png?raw=true" width="800" >
<br><br>


# how important is it?
- it bypass ip blockage, so it bypass principal core of filtering
- it change the paradigm of anti-censorship from "hiding traffic" / "escaping blockage" to "drilling whatever blocked"
- what more can a censorman do after detecting a VPN, beside blocking ip?
- similar to [fragment](https://github.com/GFW-knocker/gfw_resist_tls_proxy) that bypass filtered Domain/SNI , it operate at the lower network layer
- no matter which protocol used at upper level, it can drill everything, even blocked port

# can GFW block tcp violation method?
- this method is not based on a bug nor a protocol at application layer
- it operate on lowest possible layer of network (transport and ip layer)
- need lots of dedicated Hardware to fight with (not achievable in software)
- we use TCP ACK/PUSH packets which is 100000X more frequent than SYN
- they have large list of blocked ip that want to drop
- they simply cant hold & check every single packet in high speed traffic. (unless with millions of dollar HW investment)

# how to run
- need a VPS
- need <b>root/admin</b> access in <b>both client & server</b> to modify/send/sniff crafted packet
- we implement method1 : a prototype for proof-of-concept that can run on both windows & linux
- its not ready for production yet but we plan to build stable and standalone version in near future

# what is Next?
- next step is to implement on xray-core
- thus anyone can easily create a "tcp violation" config and revive blocked vps ip

# Rust implementation (full)
This repository now includes a full Rust implementation of method1 that mirrors the Python behavior (vio + QUIC tunnel). It includes four binaries:
- `vio-client` / `vio-server`: raw TCP violation packet sender/sniffer + UDP bridge.
- `quic-client` / `quic-server`: QUIC tunnel that multiplexes TCP/UDP streams.
- `mainclient` / `mainserver`: convenience wrappers that launch the two components together.

## Build
```bash
cargo build --release
```

## Configure
Edit `config.toml` (same fields as `method1/parameters.py`). Make sure:
- `vps_ip` is the blocked VPS IP.
- `vio_tcp_*` ports are **closed** at OS firewall to prevent the kernel from replying with RST.
- `quic_*` ports are reachable between client and server.
- Tune `udp_buffer_bytes` / `tcp_buffer_bytes` for high-throughput environments.

## Run
On VPS:
```bash
sudo ./target/release/mainserver --config config.toml
```

On client:
```bash
sudo ./target/release/mainclient --config config.toml
```

> Root/admin access is required for raw packet capture and injection.
