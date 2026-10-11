from pathlib import Path
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

output = Path("data/test_traffic.pcap")
output.parent.mkdir(parents=True, exist_ok=True)

packets = []

# TCP SYN packets to distinct destination ports
for port in range(20, 31):
    packets.append(
        Ether() / IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(sport=45000, dport=port, flags="S")
    )

# UDP packets to distinct destination ports
for port in range(1000, 1011):
    packets.append(
        Ether() / IP(src="192.0.2.11", dst="192.0.2.20")
        / UDP(sport=45001, dport=port)
    )

# ICMP echo requests
for _ in range(12):
    packets.append(
        Ether() / IP(src="192.0.2.12", dst="192.0.2.20")
        / ICMP(type=8, code=0)
    )

# Twelve conflicting ARP observations, producing twelve ARP alerts.
for i in range(12):
    source_ip = f"192.0.2.{30 + i}"
    first_mac = f"02:00:00:00:{i:02x}:01"
    second_mac = f"02:00:00:00:{i:02x}:02"
    packets.extend(
        (
            Ether(src=first_mac)
            / ARP(op=2, hwsrc=first_mac, psrc=source_ip,
                  hwdst="ff:ff:ff:ff:ff:ff", pdst="192.0.2.1"),
            Ether(src=second_mac)
            / ARP(op=2, hwsrc=second_mac, psrc=source_ip,
                  hwdst="ff:ff:ff:ff:ff:ff", pdst="192.0.2.1"),
        )
    )

# DNS queries
for i in range(12):
    packets.append(
        Ether() / IP(src="192.0.2.13", dst="192.0.2.53")
        / UDP(sport=46000 + i, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=f"test{i}.example.com"))
    )

# DNS NXDOMAIN responses
for i in range(6):
    packets.append(
        Ether() / IP(src="192.0.2.53", dst="192.0.2.13")
        / UDP(sport=53, dport=46000 + i)
        / DNS(
            id=i,
            qr=1,
            rcode=3,
            qd=DNSQR(qname=f"missing{i}.example.com")
        )
    )

wrpcap(str(output), packets)
print(f"Created {output} with {len(packets)} synthetic packets.")