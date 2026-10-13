"""
parsers.py — Protocol parsing for NetSentinel.

Extracts fields from Scapy packets into a normalized ParsedPacket dataclass.
Handles Ethernet, ARP, IPv4, TCP, UDP, ICMP, and DNS.

Design principles
-----------------
* Never crash the monitoring process because one packet cannot be parsed.
* Use Scapy's layer API instead of manual offset arithmetic.
* Do not assume that every expected layer is present.
* Distinguish a missing field (None) from a legitimate zero value.
* Do not store full packet payloads.
* Return a documented, consistent representation.

Each parse_* function is independently testable without live capture.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TCP flag constants (Scapy encodes flags as a string or FlagValue)
# ---------------------------------------------------------------------------
TCP_FLAG_SYN = "S"
TCP_FLAG_ACK = "A"
TCP_FLAG_FIN = "F"
TCP_FLAG_RST = "R"
TCP_FLAG_PSH = "P"
TCP_FLAG_URG = "U"

# ICMP type values we care about for detection rules.
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0

# ARP operation codes
ARP_REQUEST = 1
ARP_REPLY   = 2

# DNS response code for "name not found"
DNS_RCODE_NXDOMAIN = 3


# ---------------------------------------------------------------------------
# Parsed packet dataclass
# ---------------------------------------------------------------------------

@dataclass
class ParsedPacket:
    """
    Normalized representation of a captured packet.

    All fields are optional — callers must test for None before use.
    Fields are populated only when the relevant protocol layer is present
    in the packet and the field value is parsable.
    """

    # --- Common ---
    timestamp_utc: str = ""          # ISO-8601 UTC, e.g. "2024-05-01T12:00:00.000Z"
    raw_timestamp: float = 0.0       # Scapy packet time (POSIX seconds)
    packet_length: int = 0           # Total length in bytes as Scapy sees it

    # --- Layer 2 (Ethernet) ---
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ether_type: Optional[int] = None  # 0x0800 = IP, 0x0806 = ARP, etc.

    # --- Layer 3 (IP) ---
    protocol: Optional[str] = None   # "TCP", "UDP", "ICMP", "ARP", "DNS", "OTHER"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_ttl: Optional[int] = None
    ip_proto: Optional[int] = None   # Raw IP protocol number

    # --- ARP ---
    arp_op: Optional[int] = None     # 1 = request, 2 = reply
    arp_src_ip: Optional[str] = None
    arp_dst_ip: Optional[str] = None
    arp_src_mac: Optional[str] = None
    arp_dst_mac: Optional[str] = None

    # --- Layer 4 (TCP) ---
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None  # String like "S", "SA", "FA" etc.
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    is_syn: bool = False             # True only for pure SYN (no ACK)
    is_syn_ack: bool = False

    # --- Layer 4 (UDP) ---
    udp_length: Optional[int] = None

    # --- ICMP ---
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    is_echo_request: bool = False
    is_echo_reply: bool = False

    # --- DNS ---
    is_dns: bool = False
    dns_is_response: bool = False    # True if this is a DNS response (qr=1)
    dns_query_name: Optional[str] = None   # First question name
    dns_query_type: Optional[int] = None   # Query type (1=A, 28=AAAA, etc.)
    dns_rcode: Optional[int] = None        # Response code (0=OK, 3=NXDOMAIN)
    dns_answer_count: Optional[int] = None

    # --- Flags for detection routing ---
    has_ip: bool = False
    has_tcp: bool = False
    has_udp: bool = False
    has_icmp: bool = False
    has_arp: bool = False
    parse_error: bool = False        # True if any parsing exception occurred


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _scapy_time_to_iso(pkt_time: float) -> str:
    """Convert Scapy packet.time (POSIX float) to ISO-8601 UTC string."""
    from datetime import datetime, timezone
    try:
        dt = datetime.fromtimestamp(float(pkt_time), tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (OSError, OverflowError, ValueError):
        from utils import utc_now_iso
        return utc_now_iso()


def _safe_str(value: object) -> Optional[str]:
    """Return str(value).strip() or None if value is falsy."""
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _safe_int(value: object) -> Optional[int]:
    """Return int(value) or None on any error."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _tcp_flags_str(flags: object) -> Optional[str]:
    """
    Convert Scapy's TCP flags representation to a plain string like "SA".

    Scapy may return a FlagValue, an integer, or a string depending on
    version.  We convert to string and strip whitespace.
    """
    if flags is None:
        return None
    try:
        return str(flags).strip() or None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public parse function
# ---------------------------------------------------------------------------

def parse_packet(pkt: object) -> Optional[ParsedPacket]:
    """
    Parse a raw Scapy packet and return a ParsedPacket.

    Returns None only if *pkt* is None.
    On any parsing exception, returns a ParsedPacket with parse_error=True
    so that the caller can count malformed packets without crashing.
    """
    if pkt is None:
        return None

    parsed = ParsedPacket()

    try:
        _populate(pkt, parsed)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Unexpected parse error: %s", exc, exc_info=True)
        parsed.parse_error = True

    return parsed


def _populate(pkt: object, p: ParsedPacket) -> None:
    """Fill *p* in-place from Scapy packet *pkt*."""
    # Import Scapy layers lazily so that tests can mock or import this module
    # without triggering Scapy's interface discovery on import.
    try:
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns import DNS
        scapy_available = True
    except ImportError:
        scapy_available = False

    # --- Timing and length ---
    try:
        p.raw_timestamp = float(pkt.time)  # type: ignore[attr-defined]
        p.timestamp_utc = _scapy_time_to_iso(p.raw_timestamp)
    except AttributeError:
        from utils import utc_now_iso
        p.timestamp_utc = utc_now_iso()

    try:
        p.packet_length = len(pkt)  # type: ignore[arg-type]
    except TypeError:
        p.packet_length = 0

    if not scapy_available:
        p.parse_error = True
        return

    # --- Ethernet ---
    if pkt.haslayer(Ether):  # type: ignore[attr-defined]
        eth = pkt[Ether]  # type: ignore[index]
        p.src_mac = _safe_str(getattr(eth, "src", None))
        p.dst_mac = _safe_str(getattr(eth, "dst", None))
        try:
            p.ether_type = int(eth.type)
        except (TypeError, ValueError):
            pass

    # --- ARP ---
    if pkt.haslayer(ARP):  # type: ignore[attr-defined]
        p.has_arp = True
        p.protocol = "ARP"
        arp = pkt[ARP]  # type: ignore[index]
        p.arp_op = _safe_int(getattr(arp, "op", None))
        p.arp_src_ip = _safe_str(getattr(arp, "psrc", None))
        p.arp_dst_ip = _safe_str(getattr(arp, "pdst", None))
        p.arp_src_mac = _safe_str(getattr(arp, "hwsrc", None))
        p.arp_dst_mac = _safe_str(getattr(arp, "hwdst", None))
        # Mirror src/dst for unified IP fields used by some rules.
        p.src_ip = p.arp_src_ip
        p.dst_ip = p.arp_dst_ip
        p.src_mac = p.src_mac or p.arp_src_mac
        return  # ARP has no IP/TCP/UDP layers

    # --- IPv4 ---
    if pkt.haslayer(IP):  # type: ignore[attr-defined]
        p.has_ip = True
        ip = pkt[IP]  # type: ignore[index]
        p.src_ip = _safe_str(getattr(ip, "src", None))
        p.dst_ip = _safe_str(getattr(ip, "dst", None))
        p.ip_ttl = _safe_int(getattr(ip, "ttl", None))
        p.ip_proto = _safe_int(getattr(ip, "proto", None))
    else:
        # Not IPv4 (could be IPv6 or unknown); no further layer parsing.
        p.protocol = "OTHER"
        return

    # --- TCP ---
    if pkt.haslayer(TCP):  # type: ignore[attr-defined]
        p.has_tcp = True
        p.protocol = "TCP"
        tcp = pkt[TCP]  # type: ignore[index]
        p.src_port = _safe_int(getattr(tcp, "sport", None))
        p.dst_port = _safe_int(getattr(tcp, "dport", None))
        p.tcp_flags = _tcp_flags_str(getattr(tcp, "flags", None))
        p.tcp_seq = _safe_int(getattr(tcp, "seq", None))
        p.tcp_ack = _safe_int(getattr(tcp, "ack", None))

        # Determine SYN / SYN-ACK for detection rules.
        # Scapy flag strings: "S" = SYN only, "SA" = SYN+ACK
        flags_str = p.tcp_flags or ""
        p.is_syn = (TCP_FLAG_SYN in flags_str) and (TCP_FLAG_ACK not in flags_str)
        p.is_syn_ack = (TCP_FLAG_SYN in flags_str) and (TCP_FLAG_ACK in flags_str)

    # --- UDP ---
    elif pkt.haslayer(UDP):  # type: ignore[attr-defined]
        p.has_udp = True
        p.protocol = "UDP"
        udp = pkt[UDP]  # type: ignore[index]
        p.src_port = _safe_int(getattr(udp, "sport", None))
        p.dst_port = _safe_int(getattr(udp, "dport", None))
        p.udp_length = _safe_int(getattr(udp, "len", None))

    # --- ICMP ---
    elif pkt.haslayer(ICMP):  # type: ignore[attr-defined]
        p.has_icmp = True
        p.protocol = "ICMP"
        icmp = pkt[ICMP]  # type: ignore[index]
        p.icmp_type = _safe_int(getattr(icmp, "type", None))
        p.icmp_code = _safe_int(getattr(icmp, "code", None))
        p.is_echo_request = (p.icmp_type == ICMP_ECHO_REQUEST)
        p.is_echo_reply = (p.icmp_type == ICMP_ECHO_REPLY)
        p.protocol = "ICMP"

    # --- DNS (layered on top of UDP/TCP) ---
    # We check for DNS after transport layers because DNS can ride on UDP or TCP.
    # Re-check after the above elif chain.
    _parse_dns_layer(pkt, p, DNS)


def _parse_dns_layer(pkt: object, p: ParsedPacket, DNS: type) -> None:
    """
    Attempt to parse a DNS layer from *pkt*.

    DNS usually rides on UDP port 53 or TCP port 53.
    Updates *p* in-place; does not change p.protocol to avoid
    overwriting "UDP" or "TCP" — instead sets p.is_dns = True.
    """
    try:
        if not pkt.haslayer(DNS):  # type: ignore[attr-defined]
            return
    except Exception:
        return

    try:
        dns = pkt[DNS]  # type: ignore[index]
    except Exception:
        return

    p.is_dns = True

    try:
        # qr=0 means query, qr=1 means response.
        qr = getattr(dns, "qr", None)
        p.dns_is_response = bool(qr)
    except Exception:
        pass

    try:
        p.dns_rcode = _safe_int(getattr(dns, "rcode", None))
    except Exception:
        pass

    try:
        p.dns_answer_count = _safe_int(getattr(dns, "ancount", None))
    except Exception:
        pass

    # Extract the first question name and type.
    try:
        qd = getattr(dns, "qd", None)
        if qd is not None:
            if isinstance(qd, (list, tuple)) and qd:
                qd = qd[0]
            if qd is not None:
                name = getattr(qd, "qname", None)
                if name is not None:
                    # Scapy may return bytes or a packet-list-like wrapper; decode safely.
                    if isinstance(name, (bytes, bytearray)):
                        name = bytes(name).decode("utf-8", errors="replace").rstrip(".")
                    else:
                        name = str(name).rstrip(".")
                    p.dns_query_name = name if name else None

                qtype = getattr(qd, "qtype", None)
                p.dns_query_type = _safe_int(qtype)
    except Exception as exc:
        logger.debug("DNS question parse error: %s", exc)


# ---------------------------------------------------------------------------
# Convenience layer-check helpers used by tests and the alert manager
# ---------------------------------------------------------------------------

def is_tcp_syn(p: ParsedPacket) -> bool:
    """True if packet is a pure SYN (no ACK flag)."""
    return p.has_tcp and p.is_syn


def is_icmp_echo_request(p: ParsedPacket) -> bool:
    """True if packet is an ICMP echo request (type 8)."""
    return p.has_icmp and p.is_echo_request


def is_arp_reply(p: ParsedPacket) -> bool:
    """True if packet is an ARP reply (op=2)."""
    return p.has_arp and p.arp_op == ARP_REPLY


def is_arp_request(p: ParsedPacket) -> bool:
    """True if packet is an ARP request (op=1)."""
    return p.has_arp and p.arp_op == ARP_REQUEST


def is_dns_query(p: ParsedPacket) -> bool:
    """True if packet contains a DNS query (not a response)."""
    return p.is_dns and not p.dns_is_response


def is_dns_nxdomain(p: ParsedPacket) -> bool:
    """True if packet is a DNS response with NXDOMAIN (rcode=3)."""
    return p.is_dns and p.dns_is_response and p.dns_rcode == DNS_RCODE_NXDOMAIN
