"""Defensive protocol parsing for NetSentinel.

Every function here takes a Scapy packet and returns plain Python values.
Nothing downstream touches Scapy objects, which keeps the detection engine
testable without a live socket.

Design rules:
  * Never assume a layer exists - use ``haslayer()``.
  * Never raise on malformed input - return ``None`` for the missing field.
  * Never log or store packet payloads.
  * Distinguish "field absent" (``None``) from "field legitimately zero" (``0``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from utils import normalize_ip, normalize_mac, to_utc_iso

try:  # Scapy is a hard runtime dependency but must not break imports in tests.
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Packet
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only on broken installs.
    SCAPY_AVAILABLE = False
    Packet = object  # type: ignore[assignment,misc]

LOGGER = logging.getLogger(__name__)

# Scapy flag names are single characters; we expose them sorted for readability.
_TCP_FLAG_ORDER = ("F", "S", "R", "P", "A", "U", "E", "C")

# DNS type/rcode numeric-to-name maps kept small on purpose; unknown values are
# rendered as their integer so we never silently mislabel a packet.
_DNS_QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY",
}
_DNS_RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}


@dataclass
class ParsedPacket:
    """Normalised representation of one captured packet.

    Fields are ``None`` when the corresponding protocol layer or value is
    absent.  A zero value (for example ``ttl=0`` or ``dns_rcode=0`` meaning
    NOERROR) is preserved as ``0``.
    """

    timestamp_utc: str
    timestamp_epoch: float
    length: Optional[int] = None

    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_proto: Optional[int] = None
    ip_proto_name: Optional[str] = None
    ttl: Optional[int] = None

    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    tcp_syn: bool = False
    tcp_ack: bool = False
    tcp_fin: bool = False
    tcp_rst: bool = False

    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    arp_op: Optional[int] = None
    arp_sender_ip: Optional[str] = None
    arp_sender_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None
    arp_target_mac: Optional[str] = None

    dns_is_query: bool = False
    dns_is_response: bool = False
    dns_qname: Optional[str] = None
    dns_qtype: Optional[str] = None
    dns_rcode: Optional[int] = None
    dns_rcode_name: Optional[str] = None
    dns_txid: Optional[int] = None

    protocol: str = "OTHER"
    parse_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary suitable for export."""
        data = asdict(self)
        # ``parse_notes`` is an implementation detail; keep it out of exports.
        data.pop("parse_notes", None)
        return data


# --------------------------------------------------------------------------
# Layer extraction helpers
# --------------------------------------------------------------------------

def _safe(value: Any) -> Any:
    """Convert a Scapy value to a plain Python scalar, or ``None``."""
    if value is None:
        return None
    if isinstance(value, (int, float, str, bool)):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return str(value)


def _extract_ethernet(pkt: Any, result: ParsedPacket) -> None:
    if not SCAPY_AVAILABLE or not pkt.haslayer(Ether):
        return
    ether = pkt[Ether]
    result.src_mac = normalize_mac(ether.src)
    result.dst_mac = normalize_mac(ether.dst)


def _extract_ipv4(pkt: Any, result: ParsedPacket) -> None:
    if not SCAPY_AVAILABLE or not pkt.haslayer(IP):
        return
    ip_layer = pkt[IP]
    result.src_ip = normalize_ip(ip_layer.src)
    result.dst_ip = normalize_ip(ip_layer.dst)
    result.ttl = _safe(ip_layer.ttl)
    proto = _safe(ip_layer.proto)
    if isinstance(proto, int):
        result.ip_proto = proto
        result.ip_proto_name = {
            1: "ICMP", 6: "TCP", 17: "UDP",
        }.get(proto, f"IP-{proto}")


def _extract_tcp(pkt: Any, result: ParsedPacket) -> None:
    if not SCAPY_AVAILABLE or not pkt.haslayer(TCP):
        return
    tcp = pkt[TCP]
    result.src_port = _safe(tcp.sport)
    result.dst_port = _safe(tcp.dport)

    flags_value = int(tcp.flags)
    # Scapy encodes flags as a bitmask; convert to a stable, sorted string.
    present = [name for name in _TCP_FLAG_ORDER if flags_value & _flag_bit(name)]
    result.tcp_flags = "".join(present) if present else ""
    result.tcp_syn = bool(flags_value & _flag_bit("S"))
    result.tcp_ack = bool(flags_value & _flag_bit("A"))
    result.tcp_fin = bool(flags_value & _flag_bit("F"))
    result.tcp_rst = bool(flags_value & _flag_bit("R"))


def _flag_bit(name: str) -> int:
    """Return the Scapy bitmask value for a TCP flag character."""
    if SCAPY_AVAILABLE:
        from scapy.layers.inet import TCP as _TCP  # local import to avoid cycles
        return int(_TCP.flags.values.get(name, 0))
    return 0


def _extract_udp(pkt: Any, result: ParsedPacket) -> None:
    if not SCAPY_AVAILABLE or not pkt.haslayer(UDP):
        return
    udp = pkt[UDP]
    result.src_port = _safe(udp.sport)
    result.dst_port = _safe(udp.dport)


def _extract_icmp(pkt: Any, result: ParsedPacket) -> None:
    if not SCAPY_AVAILABLE or not pkt.haslayer(ICMP):
        return
    icmp = pkt[ICMP]
    result.icmp_type = _safe(icmp.type)
    result.icmp_code = _safe(icmp.code)


def _extract_arp(pkt: Any, result: ParsedPacket) -> None:
    if not SCAPY_AVAILABLE or not pkt.haslayer(ARP):
        return
    arp = pkt[ARP]
    result.arp_op = _safe(arp.op)
    result.arp_sender_ip = normalize_ip(arp.psrc)
    result.arp_sender_mac = normalize_mac(arp.hwsrc)
    result.arp_target_ip = normalize_ip(arp.pdst)
    result.arp_target_mac = normalize_mac(arp.hwdst)


def _normalise_qname(raw: Any) -> Optional[str]:
    """Return a lowercase DNS name without the trailing dot, or ``None``."""
    if raw is None:
        return None
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("idna", errors="replace")
        except Exception:  # pragma: no cover - extremely defensive
            return None
    text = str(raw).strip().rstrip(".")
    if not text:
        return None
    return text.lower()


def _extract_dns(pkt: Any, result: ParsedPacket) -> None:
    if not SCAPY_AVAILABLE or not pkt.haslayer(DNS):
        return
    dns = pkt[DNS]
    result.dns_txid = _safe(dns.id)

    # qr == 0 -> query, qr == 1 -> response.  Preserve the distinction.
    qr = _safe(dns.qr)
    if qr == 0:
        result.dns_is_query = True
    elif qr == 1:
        result.dns_is_response = True
        rcode = _safe(dns.rcode)
        if isinstance(rcode, int):
            result.dns_rcode = rcode
            result.dns_rcode_name = _DNS_RCODE_NAMES.get(rcode, f"RCODE-{rcode}")

    # Queries are the first qd entry; responses can carry a question section too.
    question = None
    if dns.qd is not None:
        try:
            question = dns.qd if SCAPY_AVAILABLE and pkt.haslayer(DNSQR) else None
        except (AttributeError, IndexError):
            question = None

    if question is not None:
        qname = _normalise_qname(getattr(question, "qname", None))
        if qname:
            result.dns_qname = qname
        qtype_value = _safe(getattr(question, "qtype", None))
        if isinstance(qtype_value, int):
            result.dns_qtype = _DNS_QTYPE_NAMES.get(qtype_value, f"TYPE{qtype_value}")

    # Some servers put the queried name only in the answer section; fall back.
    if result.dns_qname is None and result.dns_is_response and dns.an is not None:
        try:
            rr_name = getattr(dns.an, "rrname", None)
        except (AttributeError, IndexError):
            rr_name = None
        qname = _normalise_qname(rr_name)
        if qname:
            result.dns_qname = qname


def _classify_protocol(result: ParsedPacket) -> str:
    """Return a short protocol label used for counters and baselining."""
    if result.arp_op is not None:
        return "ARP"
    if result.dns_is_query or result.dns_is_response:
        return "DNS"
    if result.icmp_type is not None:
        return "ICMP"
    if result.tcp_flags is not None:
        return "TCP"
    if result.src_port is not None and result.ip_proto == 17:
        return "UDP"
    # UDP without ports is malformed; still label as UDP if proto says so.
    if result.ip_proto == 17:
        return "UDP"
    if result.ip_proto is not None:
        return result.ip_proto_name or "IP"
    return "OTHER"


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def parse_packet(pkt: Any) -> Optional[ParsedPacket]:
    """Dissect ``pkt`` and return a :class:`ParsedPacket`, or ``None``.

    Returns ``None`` only when the packet cannot be dissected at all (for
    example a bare ``None`` or a non-packet object).  Any individual layer
    that fails to parse is recorded in ``parse_notes`` and its fields stay
    ``None``; the rest of the packet is still returned.
    """
    if pkt is None:
        return None

    try:
        epoch = float(getattr(pkt, "time", 0.0) or 0.0)
    except (TypeError, ValueError):
        epoch = 0.0

    result = ParsedPacket(
        timestamp_utc=to_utc_iso(epoch) if epoch > 0 else to_utc_iso(0),
        timestamp_epoch=epoch,
        length=_safe(getattr(pkt, "len", None) or getattr(pkt, "wirelen", None)),
    )

    # Each extractor is isolated so a fault in one protocol cannot lose the
    # whole packet.  The exception is logged at DEBUG level and recorded.
    for name, extractor in (
        ("ethernet", _extract_ethernet),
        ("ipv4", _extract_ipv4),
        ("tcp", _extract_tcp),
        ("udp", _extract_udp),
        ("icmp", _extract_icmp),
        ("arp", _extract_arp),
        ("dns", _extract_dns),
    ):
        try:
            extractor(pkt, result)
        except Exception as exc:  # noqa: BLE001 - defensive per-packet isolation
            result.parse_notes.append(f"{name}: {type(exc).__name__}: {exc}")
            LOGGER.debug("Parser layer %s failed on packet: %s", name, exc)

    result.protocol = _classify_protocol(result)
    return result


def describe_packet(parsed: ParsedPacket) -> str:
    """Return a one-line human-readable summary for console output."""
    parts: List[str] = [parsed.protocol]
    if parsed.src_ip or parsed.dst_ip:
        src = parsed.src_ip or "?"
        dst = parsed.dst_ip or "?"
        if parsed.src_port is not None or parsed.dst_port is not None:
            sport = parsed.src_port if parsed.src_port is not None else "-"
            dport = parsed.dst_port if parsed.dst_port is not None else "-"
            parts.append(f"{src}:{sport} -> {dst}:{dport}")
        else:
            parts.append(f"{src} -> {dst}")
    elif parsed.arp_sender_ip or parsed.arp_target_ip:
        parts.append(
            f"ARP {parsed.arp_sender_ip or '?'} -> {parsed.arp_target_ip or '?'}"
        )
    if parsed.dns_qname:
        parts.append(f"q={parsed.dns_qname}")
    if parsed.tcp_flags:
        parts.append(f"flags={parsed.tcp_flags}")
    return " ".join(parts)