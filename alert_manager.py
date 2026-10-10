"""Detection engine, alert model and alert storage for NetSentinel.

Design principles
-----------------
* Each rule is an independent class with a single ``process`` method.  Rules
  are stateful only through bounded, time-pruned containers.
* Rules never read the wall clock.  ``capture.py`` passes the packet's own
  timestamp, so offline PCAP replay and unit tests are deterministic.
* Every alert carries ``evidence`` describing exactly why it fired.  Alerts
  describe *observations* and *suspicions*, not confirmed incidents; the
  ``confidence`` field is separate from ``severity``.
* ``AlertStore`` writes append-only JSONL plus a human-readable log.  Both
  writes are guarded by a single lock so concurrent producers cannot
  interleave partial lines.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Tuple

from parsers import ParsedPacket
from utils import (
    FileAppender,
    NetSentinelError,
    dumps_json,
    generate_id,
    ip_in_networks,
    to_utc_iso,
)

LOGGER = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Alert model
# --------------------------------------------------------------------------

@dataclass
class Alert:
    """Structured detection result.

    Field names match the schema documented in the README.  ``evidence`` is a
    free-form dictionary whose keys are documented per rule.
    """

    alert_id: str
    timestamp_utc: str
    rule_id: str
    rule_name: str
    severity: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    protocol: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommended_action: str = ""
    confidence: str = "medium"

    # Populated by the manager when a duplicate alert is suppressed.
    occurrence_count: int = 1
    first_seen_utc: Optional[str] = None
    last_seen_utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Alert storage
# --------------------------------------------------------------------------

class AlertStore:
    """Append-only alert sink.

    Writes each alert to ``alerts/alerts.jsonl`` (machine readable) and to
    ``alerts/alerts.log`` (human readable).  The two files are intentionally
    separate from the operational log in ``logs/`` so that security events
    are never mixed with application noise.
    """

    def __init__(self, jsonl_path: Path | str, log_path: Path | str) -> None:
        self.jsonl = FileAppender(jsonl_path)
        self.log = FileAppender(log_path)
        self._lock = threading.Lock()

    def write(self, alert: Alert) -> None:
        """Persist ``alert``.  Errors propagate to the caller."""
        with self._lock:
            try:
                self.jsonl.append(dumps_json(alert.to_dict()))
            except OSError as exc:
                LOGGER.error("Failed to append alert JSON: %s", exc)
                raise
            try:
                self.log.append(self._format_log_line(alert))
            except OSError as exc:
                LOGGER.error("Failed to append alert log: %s", exc)
                raise

    @staticmethod
    def _format_log_line(alert: Alert) -> str:
        src = alert.source_ip or "-"
        dst = alert.destination_ip or "-"
        return (
            f"{alert.timestamp_utc} [{alert.severity.upper():8s}] "
            f"{alert.rule_id} {alert.rule_name} | {src} -> {dst} | "
            f"{alert.description}"
        )


# --------------------------------------------------------------------------
# Detection rule base class
# --------------------------------------------------------------------------

class DetectionRule:
    """Base class for a single detection rule.

    Subclasses implement :meth:`process` and are responsible for keeping
    their own state bounded.
    """

    rule_id: str = "BASE-000"
    rule_name: str = "Base Rule"
    default_severity: str = "low"
    default_confidence: str = "medium"
    recommended_action: str = "Review the affected host and related traffic."

    def __init__(
        self,
        severity: Optional[str] = None,
        trusted_hosts: Optional[Iterable[str]] = None,
    ) -> None:
        self.severity = severity or self.default_severity
        self.trusted_hosts = set(trusted_hosts or ())

    def is_trusted(self, ip: Optional[str]) -> bool:
        return ip is not None and ip in self.trusted_hosts

    def process(self, packet: ParsedPacket, now: float) -> Optional[Alert]:
        """Return an :class:`Alert` if the rule fires for ``packet``.

        ``now`` is the packet's epoch timestamp; rules must not call the
        wall clock themselves.
        """
        raise NotImplementedError

    # Convenience helper so subclasses share one alert-construction path.
    def _make_alert(
        self,
        packet: ParsedPacket,
        now: float,
        description: str,
        evidence: Dict[str, Any],
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        confidence: Optional[str] = None,
    ) -> Alert:
        return Alert(
            alert_id=generate_id("alert"),
            timestamp_utc=to_utc_iso(now),
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            source_ip=source_ip if source_ip is not None else packet.src_ip,
            destination_ip=(
                destination_ip if destination_ip is not None else packet.dst_ip
            ),
            protocol=protocol or packet.protocol,
            description=description,
            evidence=evidence,
            recommended_action=self.recommended_action,
            confidence=confidence or self.default_confidence,
            first_seen_utc=to_utc_iso(now),
            last_seen_utc=to_utc_iso(now),
        )


# --------------------------------------------------------------------------
# Rule 1: TCP SYN destination-port diversity
# --------------------------------------------------------------------------

class TcpPortScanRule(DetectionRule):
    """TCP-001 - unusually broad TCP SYN activity from one source.

    Counts *distinct* destination ports per source inside a sliding window.
    SYN+ACK, FIN, RST and pure data segments are ignored; only pure SYN
    (or SYN without ACK) contributes.  Retransmissions to the same port are
    naturally collapsed because we track port sets.
    """

    rule_id = "TCP-001"
    rule_name = "Possible TCP Port Scan"
    default_severity = "medium"
    default_confidence = "medium"
    recommended_action = (
        "Identify the source host, confirm whether the scan was authorised, "
        "and review adjacent authentication and firewall logs."
    )

    def __init__(
        self,
        window_seconds: float,
        threshold: int,
        excluded_ports: Optional[Iterable[int]] = None,
        max_tracked_sources: int = 2048,
        severity: Optional[str] = None,
        trusted_hosts: Optional[Iterable[str]] = None,
    ) -> None:
        super().__init__(severity=severity, trusted_hosts=trusted_hosts)
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if threshold < 2:
            raise ValueError("threshold must be at least 2")

        self.window_seconds = float(window_seconds)
        self.threshold = int(threshold)
        self.excluded_ports = set(excluded_ports or ())
        self.max_tracked_sources = int(max_tracked_sources)

        # source_ip -> deque[(timestamp, dst_ip, dst_port)]
        self._events: "OrderedDict[str, Deque[Tuple[float, str, int]]]" = OrderedDict()

    def _prune(self, events: Deque[Tuple[float, str, int]], now: float) -> None:
        cutoff = now - self.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()

    def process(self, packet: ParsedPacket, now: float) -> Optional[Alert]:
        # Only TCP SYN without ACK counts as a connection attempt.
        if packet.protocol != "TCP":
            return None
        if not packet.tcp_syn or packet.tcp_ack:
            return None
        if packet.src_ip is None or packet.dst_port is None:
            return None
        if packet.dst_port in self.excluded_ports:
            return None
        if self.is_trusted(packet.src_ip):
            return None

        events = self._events.get(packet.src_ip)
        if events is None:
            events = deque()
            self._events[packet.src_ip] = events
            # Bounded LRU: drop the oldest idle source when over the cap.
            while len(self._events) > self.max_tracked_sources:
                self._events.popitem(last=False)
        self._events.move_to_end(packet.src_ip)

        events.append((now, packet.dst_ip or "", int(packet.dst_port)))
        self._prune(events, now)

        distinct_ports = {port for _, _, port in events}
        if len(distinct_ports) < self.threshold:
            return None

        distinct_targets = {dst for _, dst, _ in events if dst}
        oldest = events[0][0] if events else now
        evidence = {
            "distinct_destination_ports": len(distinct_ports),
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "observation_duration_seconds": round(now - oldest, 3),
            "distinct_destination_hosts": len(distinct_targets),
            "sample_ports": sorted(distinct_ports)[:20],
        }
        return self._make_alert(
            packet,
            now,
            description=(
                f"{len(distinct_ports)} distinct TCP destination ports contacted "
                f"by {packet.src_ip} within {self.window_seconds:.0f}s "
                f"(threshold {self.threshold}). This is consistent with a port "
                f"scan but may also reflect legitimate service discovery."
            ),
            evidence=evidence,
            source_ip=packet.src_ip,
        )


# --------------------------------------------------------------------------
# Rule 2: UDP destination-port diversity
# --------------------------------------------------------------------------

class UdpPortDiversityRule(DetectionRule):
    """UDP-001 - unusually broad UDP destination-port activity."""

    rule_id = "UDP-001"
    rule_name = "UDP Destination-Port Diversity"
    default_severity = "medium"
    default_confidence = "low"
    recommended_action = (
        "Confirm whether the source host normally probes many UDP ports. "
        "Correlate with DHCP, mDNS, NTP and service-discovery traffic."
    )

    def __init__(
        self,
        window_seconds: float,
        threshold: int,
        max_tracked_sources: int = 2048,
        severity: Optional[str] = None,
        trusted_hosts: Optional[Iterable[str]] = None,
    ) -> None:
        super().__init__(severity=severity, trusted_hosts=trusted_hosts)
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if threshold < 2:
            raise ValueError("threshold must be at least 2")

        self.window_seconds = float(window_seconds)
        self.threshold = int(threshold)
        self.max_tracked_sources = int(max_tracked_sources)
        self._events: "OrderedDict[str, Deque[Tuple[float, str, int]]]" = OrderedDict()

    def _prune(self, events: Deque[Tuple[float, str, int]], now: float) -> None:
        cutoff = now - self.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()

    def process(self, packet: ParsedPacket, now: float) -> Optional[Alert]:
        if packet.protocol != "UDP":
            return None
        if packet.src_ip is None or packet.dst_port is None:
            return None
        if self.is_trusted(packet.src_ip):
            return None

        events = self._events.get(packet.src_ip)
        if events is None:
            events = deque()
            self._events[packet.src_ip] = events
            while len(self._events) > self.max_tracked_sources:
                self._events.popitem(last=False)
        self._events.move_to_end(packet.src_ip)

        events.append((now, packet.dst_ip or "", int(packet.dst_port)))
        self._prune(events, now)

        distinct_ports = {port for _, _, port in events}
        if len(distinct_ports) < self.threshold:
            return None

        oldest = events[0][0] if events else now
        evidence = {
            "distinct_destination_ports": len(distinct_ports),
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "observation_duration_seconds": round(now - oldest, 3),
            "sample_ports": sorted(distinct_ports)[:20],
            "note": (
                "A UDP timeout is not proof that a port is closed; the remote "
                "host may simply not have replied yet."
            ),
        }
        return self._make_alert(
            packet,
            now,
            description=(
                f"{len(distinct_ports)} distinct UDP destination ports contacted "
                f"by {packet.src_ip} within {self.window_seconds:.0f}s "
                f"(threshold {self.threshold})."
            ),
            evidence=evidence,
            source_ip=packet.src_ip,
        )


# --------------------------------------------------------------------------
# Rule 3: ICMP echo-request rate
# --------------------------------------------------------------------------

class IcmpEchoRateRule(DetectionRule):
    """ICMP-001 - high ICMP echo-request rate from one source."""

    rule_id = "ICMP-001"
    rule_name = "ICMP Echo Request Rate Anomaly"
    default_severity = "low"
    default_confidence = "medium"
    recommended_action = (
        "Check whether the source is an authorised monitoring host. "
        "Review firewall logs and confirm the destination is reachable."
    )

    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0

    def __init__(
        self,
        window_seconds: float,
        threshold: int,
        max_tracked_sources: int = 2048,
        severity: Optional[str] = None,
        trusted_hosts: Optional[Iterable[str]] = None,
    ) -> None:
        super().__init__(severity=severity, trusted_hosts=trusted_hosts)
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if threshold < 2:
            raise ValueError("threshold must be at least 2")

        self.window_seconds = float(window_seconds)
        self.threshold = int(threshold)
        self.max_tracked_sources = int(max_tracked_sources)
        self._events: "OrderedDict[str, Deque[float]]" = OrderedDict()

    def _prune(self, events: Deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while events and events[0] < cutoff:
            events.popleft()

    def process(self, packet: ParsedPacket, now: float) -> Optional[Alert]:
        if packet.protocol != "ICMP":
            return None
        # Only echo requests count; replies and other ICMP types are ignored.
        if packet.icmp_type != self.ICMP_ECHO_REQUEST:
            return None
        if packet.src_ip is None or self.is_trusted(packet.src_ip):
            return None

        events = self._events.get(packet.src_ip)
        if events is None:
            events = deque()
            self._events[packet.src_ip] = events
            while len(self._events) > self.max_tracked_sources:
                self._events.popitem(last=False)
        self._events.move_to_end(packet.src_ip)

        events.append(now)
        self._prune(events, now)

        if len(events) < self.threshold:
            return None

        oldest = events[0] if events else now
        evidence = {
            "echo_requests": len(events),
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "observation_duration_seconds": round(now - oldest, 3),
            "note": (
                "ICMP filtering, rate limiting and incomplete capture on the "
                "monitoring interface can change the observed request count."
            ),
        }
        return self._make_alert(
            packet,
            now,
            description=(
                f"{len(events)} ICMP echo requests from {packet.src_ip} within "
                f"{self.window_seconds:.0f}s (threshold {self.threshold})."
            ),
            evidence=evidence,
            source_ip=packet.src_ip,
        )


# --------------------------------------------------------------------------
# Rule 4: ARP mapping change
# --------------------------------------------------------------------------

@dataclass
class _ArpEntry:
    mac: str
    first_seen: float
    last_seen: float
    packet_count: int = 1


class ArpMappingChangeRule(DetectionRule):
    """ARP-001 - IP-to-MAC mapping changes observed on the local segment.

    Uses a bounded LRU of IP -> :class:`_ArpEntry`.  A change is reported only
    when a *different* MAC is observed for an IP that is still fresh.  The
    rule never asserts spoofing; it reports a mapping transition and leaves
    the interpretation to the analyst.
    """

    rule_id = "ARP-001"
    rule_name = "ARP Mapping Change"
    default_severity = "high"
    default_confidence = "medium"
    recommended_action = (
        "Confirm whether the change was expected (DHCP lease change, failover, "
        "VM migration). If not, capture ARP traffic and check the switch MAC "
        "table for the affected port."
    )

    def __init__(
        self,
        mapping_ttl_seconds: float,
        max_tracked_mappings: int = 1024,
        trusted_mappings: Optional[Mapping[str, str]] = None,
        severity: Optional[str] = None,
        trusted_hosts: Optional[Iterable[str]] = None,
    ) -> None:
        super().__init__(severity=severity, trusted_hosts=trusted_hosts)
        if mapping_ttl_seconds <= 0:
            raise ValueError("mapping_ttl_seconds must be positive")
        if max_tracked_mappings < 1:
            raise ValueError("max_tracked_mappings must be at least 1")

        self.mapping_ttl_seconds = float(mapping_ttl_seconds)
        self.max_tracked_mappings = int(max_tracked_mappings)
        # Trusted mappings are pre-populated so the first packet from a known
        # static host does not trigger a "new mapping" alert.
        self.trusted_mappings: Dict[str, str] = {
            ip: mac.lower() for ip, mac in (trusted_mappings or {}).items()
        }
        self._mappings: "OrderedDict[str, _ArpEntry]" = OrderedDict()

    def _expire_stale(self, now: float) -> None:
        cutoff = now - self.mapping_ttl_seconds
        stale = [ip for ip, entry in self._mappings.items() if entry.last_seen < cutoff]
        for ip in stale:
            self._mappings.pop(ip, None)

    def process(self, packet: ParsedPacket, now: float) -> Optional[Alert]:
        if packet.protocol != "ARP":
            return None
        if not packet.arp_sender_ip or not packet.arp_sender_mac:
            return None
        if self.is_trusted(packet.arp_sender_ip):
            return None

        self._expire_stale(now)

        ip = packet.arp_sender_ip
        mac = packet.arp_sender_mac.lower()

        # Honour an explicitly trusted mapping.
        trusted_mac = self.trusted_mappings.get(ip)
        if trusted_mac is not None and mac == trusted_mac:
            return None

        previous = self._mappings.get(ip)
        if previous is None:
            # First observation for this IP within the TTL window.
            self._mappings[ip] = _ArpEntry(mac=mac, first_seen=now, last_seen=now)
            self._mappings.move_to_end(ip)
            while len(self._mappings) > self.max_tracked_mappings:
                self._mappings.popitem(last=False)
            return None

        previous.last_seen = now
        previous.packet_count += 1
        self._mappings.move_to_end(ip)

        if previous.mac == mac:
            return None

        if trusted_mac is not None and mac != trusted_mac:
            # A conflicting mapping against a trusted entry is worth reporting
            # with slightly higher confidence.
            confidence = "high"
        else:
            confidence = self.default_confidence

        evidence = {
            "ip_address": ip,
            "previous_mac": previous.mac,
            "new_mac": mac,
            "previous_first_seen_utc": to_utc_iso(previous.first_seen),
            "previous_last_seen_utc": to_utc_iso(previous.last_seen),
            "seconds_since_previous_observation": round(
                now - previous.first_seen, 3
            ),
            "previous_observation_count": previous.packet_count,
            "trusted_mapping": trusted_mac,
            "note": (
                "Mapping changes are common after DHCP renewal, VM migration, "
                "failover or NIC replacement and are not proof of ARP spoofing."
            ),
        }

        old_mac = previous.mac
        previous.mac = mac
        previous.first_seen = now
        previous.packet_count = 1

        return self._make_alert(
            packet,
            now,
            description=(
                f"ARP mapping for {ip} changed from {old_mac} to {mac}."
            ),
            evidence=evidence,
            source_ip=packet.arp_sender_ip,
            destination_ip=packet.arp_target_ip,
            protocol="ARP",
            confidence=confidence,
        )


# --------------------------------------------------------------------------
# Rule 5: DNS query-rate
# --------------------------------------------------------------------------

class DnsQueryRateRule(DetectionRule):
    """DNS-001 - high DNS query rate from one source.

    Only DNS *queries* (qr == 0) are counted.  Responses never increase the
    counter, which is what prevents the rule from double-counting a simple
    request/response exchange.
    """

    rule_id = "DNS-001"
    rule_name = "DNS Query Rate Anomaly"
    default_severity = "medium"
    default_confidence = "medium"
    recommended_action = (
        "Confirm whether the source is a resolver, DHCP client or monitoring "
        "host. Review queried domain names for unusual patterns."
    )

    def __init__(
        self,
        window_seconds: float,
        threshold: int,
        max_tracked_sources: int = 2048,
        severity: Optional[str] = None,
        trusted_hosts: Optional[Iterable[str]] = None,
    ) -> None:
        super().__init__(severity=severity, trusted_hosts=trusted_hosts)
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if threshold < 2:
            raise ValueError("threshold must be at least 2")

        self.window_seconds = float(window_seconds)
        self.threshold = int(threshold)
        self.max_tracked_sources = int(max_tracked_sources)
        # source_ip -> deque[(timestamp, qname, qtype)]
        self._events: "OrderedDict[str, Deque[Tuple[float, str, str]]]" = OrderedDict()

    def _prune(self, events: Deque[Tuple[float, str, str]], now: float) -> None:
        cutoff = now - self.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()

    def process(self, packet: ParsedPacket, now: float) -> Optional[Alert]:
        if packet.protocol != "DNS":
            return None
        if not packet.dns_is_query:
            return None
        if packet.src_ip is None or self.is_trusted(packet.src_ip):
            return None

        events = self._events.get(packet.src_ip)
        if events is None:
            events = deque()
            self._events[packet.src_ip] = events
            while len(self._events) > self.max_tracked_sources:
                self._events.popitem(last=False)
        self._events.move_to_end(packet.src_ip)

        qname = packet.dns_qname or ""
        qtype = packet.dns_qtype or ""
        events.append((now, qname, qtype))
        self._prune(events, now)

        if len(events) < self.threshold:
            return None

        oldest = events[0][0] if events else now
        distinct_names = {name for _, name, _ in events if name}
        evidence = {
            "query_count": len(events),
            "distinct_query_names": len(distinct_names),
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "observation_duration_seconds": round(now - oldest, 3),
            "sample_queries": sorted(distinct_names)[:10],
        }
        return self._make_alert(
            packet,
            now,
            description=(
                f"{len(events)} DNS queries from {packet.src_ip} within "
                f"{self.window_seconds:.0f}s (threshold {self.threshold})."
            ),
            evidence=evidence,
            source_ip=packet.src_ip,
        )


# --------------------------------------------------------------------------
# Rule 6: NXDOMAIN ratio / count
# --------------------------------------------------------------------------

class DnsNxdomainRule(DetectionRule):
    """DNS-002 - excessive NXDOMAIN responses.

    Tracks DNS responses per *responding server* and fires when both an
    absolute floor and a ratio threshold are exceeded.  Unmatched responses
    are still counted - the rule deliberately errs on the side of not
    assuming request/response pairing.
    """

    rule_id = "DNS-002"
    rule_name = "Excessive DNS NXDOMAIN Responses"
    default_severity = "high"
    default_confidence = "low"
    recommended_action = (
        "Review the queried domains; high NXDOMAIN volume can indicate DGA "
        "activity but is also common for misconfigured clients and typos."
    )

    NXDOMAIN_RCODE = 3

    def __init__(
        self,
        window_seconds: float,
        min_responses: int,
        min_nxdomain: int,
        ratio: float,
        max_tracked_sources: int = 2048,
        severity: Optional[str] = None,
        trusted_hosts: Optional[Iterable[str]] = None,
    ) -> None:
        super().__init__(severity=severity, trusted_hosts=trusted_hosts)
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if min_responses < 1:
            raise ValueError("min_responses must be at least 1")
        if min_nxdomain < 1:
            raise ValueError("min_nxdomain must be at least 1")
        if min_nxdomain > min_responses:
            raise ValueError("min_nxdomain cannot exceed min_responses")
        if not 0.0 < ratio <= 1.0:
            raise ValueError("ratio must be in (0.0, 1.0]")

        self.window_seconds = float(window_seconds)
        self.min_responses = int(min_responses)
        self.min_nxdomain = int(min_nxdomain)
        self.ratio = float(ratio)
        self.max_tracked_sources = int(max_tracked_sources)
        # server_ip -> deque[(timestamp, is_nxdomain, qname)]
        self._events: "OrderedDict[str, Deque[Tuple[float, bool, str]]]" = OrderedDict()

    def _prune(self, events: Deque[Tuple[float, bool, str]], now: float) -> None:
        cutoff = now - self.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()

    def process(self, packet: ParsedPacket, now: float) -> Optional[Alert]:
        if packet.protocol != "DNS":
            return None
        if not packet.dns_is_response:
            return None
        if packet.dns_rcode is None:
            return None
        # The "source" of a DNS response is the server; we key on it so a
        # single noisy resolver is not attributed to many clients.
        server_ip = packet.src_ip
        if server_ip is None or self.is_trusted(server_ip):
            return None

        events = self._events.get(server_ip)
        if events is None:
            events = deque()
            self._events[server_ip] = events
            while len(self._events) > self.max_tracked_sources:
                self._events.popitem(last=False)
        self._events.move_to_end(server_ip)

        is_nxdomain = packet.dns_rcode == self.NXDOMAIN_RCODE
        events.append((now, is_nxdomain, packet.dns_qname or ""))
        self._prune(events, now)

        total = len(events)
        nxdomain = sum(1 for _, flag, _ in events if flag)
        if total < self.min_responses or nxdomain < self.min_nxdomain:
            return None
        observed_ratio = nxdomain / total
        if observed_ratio < self.ratio:
            return None

        oldest = events[0][0] if events else now
        nx_names = sorted({name for _, flag, name in events if flag and name})
        evidence = {
            "total_responses": total,
            "nxdomain_responses": nxdomain,
            "observed_ratio": round(observed_ratio, 4),
            "min_responses": self.min_responses,
            "min_nxdomain": self.min_nxdomain,
            "ratio_threshold": self.ratio,
            "window_seconds": self.window_seconds,
            "observation_duration_seconds": round(now - oldest, 3),
            "sample_nxdomain_queries": nx_names[:10],
            "note": (
                "The NXDOMAIN count reflects only responses visible on this "
                "capture interface. High NXDOMAIN is not by itself proof of "
                "DGA or malware activity."
            ),
        }
        return self._make_alert(
            packet,
            now,
            description=(
                f"{nxdomain}/{total} DNS responses from {server_ip} were "
                f"NXDOMAIN ({observed_ratio:.0%}, threshold "
                f"{self.ratio:.0%})."
            ),
            evidence=evidence,
            source_ip=server_ip,
            destination_ip=packet.dst_ip,
        )


# --------------------------------------------------------------------------
# Manager
# --------------------------------------------------------------------------

class AlertManager:
    """Runs enabled rules, deduplicates alerts and persists them.

    Deduplication key: ``(rule_id, source_ip, destination_ip)``.  A repeat
    inside the suppression window does not create a new alert; it updates
    ``occurrence_count`` and ``last_seen_utc`` on the cached alert and
    rewrites it to the log so the count is visible to a human reader.
    """

    def __init__(
        self,
        rules: Iterable[DetectionRule],
        store: Optional[AlertStore] = None,
        suppression_window_seconds: float = 60.0,
        max_in_memory_alerts: int = 5000,
        local_networks: Optional[Iterable[str]] = None,
        network_scope_enabled: bool = False,
    ) -> None:
        if suppression_window_seconds < 0:
            raise ValueError("suppression_window_seconds cannot be negative")
        if max_in_memory_alerts < 1:
            raise ValueError("max_in_memory_alerts must be at least 1")

        self.rules: List[DetectionRule] = list(rules)
        self.store = store
        self.suppression_window_seconds = float(suppression_window_seconds)
        self.local_networks = list(local_networks or ())
        self.network_scope_enabled = bool(network_scope_enabled)

        self._alerts: Deque[Alert] = deque(maxlen=int(max_in_memory_alerts))
        self._dedup: "OrderedDict[Tuple[str, Optional[str], Optional[str]], Alert]" = (
            OrderedDict()
        )
        self._lock = threading.Lock()

        # Counters exposed to the reporter.
        self.total_alerts = 0
        self.suppressed_alerts = 0

    # ------------------------------------------------------------------

    def _scope_allows(self, packet: ParsedPacket) -> bool:
        """Return True if ``packet`` is inside the configured network scope."""
        if not self.network_scope_enabled or not self.local_networks:
            return True
        candidates = [
            packet.src_ip, packet.dst_ip,
            packet.arp_sender_ip, packet.arp_target_ip,
        ]
        # If we cannot identify either endpoint, do not drop the packet: an
        # ARP or ICMP packet with missing addresses could still be evidence.
        present = [ip for ip in candidates if ip]
        if not present:
            return True
        return any(ip_in_networks(ip, self.local_networks) for ip in present)

    def process(self, packet: ParsedPacket) -> List[Alert]:
        """Run all rules against ``packet`` and return any *new* alerts."""
        if packet is None:
            return []
        if not self._scope_allows(packet):
            return []

        now = packet.timestamp_epoch
        new_alerts: List[Alert] = []

        for rule in self.rules:
            try:
                alert = rule.process(packet, now)
            except Exception as exc:  # noqa: BLE001 - one rule must not break all
                LOGGER.exception(
                    "Rule %s raised while processing a packet: %s",
                    rule.rule_id, exc,
                )
                continue
            if alert is None:
                continue
            if self._register(alert):
                new_alerts.append(alert)

        return new_alerts

    def _register(self, alert: Alert) -> bool:
        """Insert ``alert`` or merge it into an existing one.

        Returns True when a *new* alert was stored (and therefore should be
        surfaced to the caller for immediate display).
        """
        key = (alert.rule_id, alert.source_ip, alert.destination_ip)

        with self._lock:
            existing = self._dedup.get(key)
            if existing is not None:
                last_seen = self._parse_epoch(existing.last_seen_utc)
                if (
                    last_seen is not None
                    and alert.timestamp_epoch_is_old(last_seen)
                ):
                    # Too old to suppress: expire the old entry and fall through.
                    self._dedup.pop(key, None)
                else:
                    existing.occurrence_count += 1
                    existing.last_seen_utc = alert.timestamp_utc
                    existing.evidence["occurrence_count"] = existing.occurrence_count
                    self.suppressed_alerts += 1
                    if self.store is not None:
                        try:
                            self.store.write(existing)
                        except OSError:
                            LOGGER.error(
                                "Could not persist merged alert %s",
                                existing.alert_id,
                            )
                    return False

            self._dedup[key] = alert
            # Cap the dedup dictionary so a pathological stream cannot grow it.
            while len(self._dedup) > self._alerts.maxlen or 0:
                if len(self._dedup) <= (self._alerts.maxlen or 0):
                    break
                self._dedup.popitem(last=False)

            self._alerts.append(alert)
            self.total_alerts += 1

        if self.store is not None:
            try:
                self.store.write(alert)
            except OSError:
                LOGGER.error("Could not persist new alert %s", alert.alert_id)
        return True

    @staticmethod
    def _parse_epoch(iso: Optional[str]) -> Optional[float]:
        if not iso:
            return None
        try:
            text = iso[:-1] + "+00:00" if iso.endswith("Z") else iso
            from datetime import datetime  # local import keeps module light
            return datetime.fromisoformat(text).timestamp()
        except (ValueError, TypeError):
            return None

    # ------------------------------------------------------------------

    def alerts(self) -> List[Alert]:
        """Return a snapshot list of the in-memory alerts (newest last)."""
        with self._lock:
            return list(self._alerts)

    def counts_by_rule(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for alert in self.alerts():
            counts[alert.rule_id] = counts.get(alert.rule_id, 0) + 1
        return counts

    def counts_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for alert in self.alerts():
            counts[alert.severity] = counts.get(alert.severity, 0) + 1
        return counts


# --------------------------------------------------------------------------
# Convenience factory
# --------------------------------------------------------------------------

def build_rules_from_config(
    config: Mapping[str, Any],
    trusted_hosts: Optional[Iterable[str]] = None,
) -> List[DetectionRule]:
    """Construct the enabled rules from a validated config dictionary.

    Rules whose ``enabled`` flag is false are skipped.  Severity is always
    taken from ``config["severity"]`` so it never diverges from the config
    file the analyst can inspect.
    """
    detection = config["detection"]
    severity_map = config["severity"]
    trusted = list(trusted_hosts or config.get("trusted_hosts", []))

    rules: List[DetectionRule] = []

    tcp = detection["tcp"]
    if tcp["enabled"]:
        rules.append(TcpPortScanRule(
            window_seconds=tcp["window_seconds"],
            threshold=tcp["distinct_destination_ports"],
            excluded_ports=tcp.get("excluded_destination_ports", []),
            max_tracked_sources=tcp["max_tracked_sources"],
            severity=severity_map["TCP-001"],
            trusted_hosts=trusted,
        ))

    udp = detection["udp"]
    if udp["enabled"]:
        rules.append(UdpPortDiversityRule(
            window_seconds=udp["window_seconds"],
            threshold=udp["distinct_destination_ports"],
            max_tracked_sources=udp["max_tracked_sources"],
            severity=severity_map["UDP-001"],
            trusted_hosts=trusted,
        ))

    icmp = detection["icmp"]
    if icmp["enabled"]:
        rules.append(IcmpEchoRateRule(
            window_seconds=icmp["window_seconds"],
            threshold=icmp["echo_requests"],
            max_tracked_sources=icmp["max_tracked_sources"],
            severity=severity_map["ICMP-001"],
            trusted_hosts=trusted,
        ))

    arp = detection["arp"]
    if arp["enabled"]:
        rules.append(ArpMappingChangeRule(
            mapping_ttl_seconds=arp["mapping_ttl_seconds"],
            max_tracked_mappings=arp["max_tracked_mappings"],
            trusted_mappings=arp.get("trusted_mappings", {}),
            severity=severity_map["ARP-001"],
            trusted_hosts=trusted,
        ))

    dns = detection["dns"]
    if dns["enabled"]:
        rules.append(DnsQueryRateRule(
            window_seconds=dns["query_window_seconds"],
            threshold=dns["queries_per_source"],
            max_tracked_sources=dns["max_tracked_sources"],
            severity=severity_map["DNS-001"],
            trusted_hosts=trusted,
        ))
        rules.append(DnsNxdomainRule(
            window_seconds=dns["nxdomain_window_seconds"],
            min_responses=dns["nxdomain_min_responses"],
            min_nxdomain=dns["nxdomain_min_count"],
            ratio=dns["nxdomain_ratio"],
            max_tracked_sources=dns["max_tracked_sources"],
            severity=severity_map["DNS-002"],
            trusted_hosts=trusted,
        ))

    return rules