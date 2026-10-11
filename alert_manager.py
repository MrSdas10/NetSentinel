"""
alert_manager.py — Detection engine and alert management for NetSentinel.

Implements six detection rules as independent classes plus an AlertManager
that routes packets, manages deduplication, and stores structured alerts.

Rules
-----
TCP-001  TCP SYN destination-port diversity (possible port scan)
UDP-001  UDP destination-port diversity
ICMP-001 ICMP echo-request rate anomaly
ARP-001  ARP IP-to-MAC mapping change
DNS-001  DNS query-rate anomaly
DNS-002  Excessive DNS NXDOMAIN responses

Design principles
-----------------
* Each rule class owns its bounded time-windowed state.
* Rules return Optional[dict] (the evidence dict), not Alert objects;
  the AlertManager creates Alert objects to keep output concerns separated.
* Time is injected via a callable (default: time.time) so that tests can
  control the clock without real delays.
* Bounded deques/dicts prevent unbounded memory growth.
* Deduplication suppresses repeated alerts for the same (rule, src_ip)
  pair within a configurable window, while still counting occurrences.
* Detections are described as "possible" or "suspected" — never as
  confirmed attacks.
"""

import collections
import logging
import time as time_module
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from config_loader import Config
from parsers import ParsedPacket
from utils import new_alert_id, utc_now_iso

logger = logging.getLogger(__name__)

# Type alias for a time function returning float seconds.
TimeFn = Callable[[], float]

# Maximum entries in any per-IP tracking dict to prevent unbounded growth.
_MAX_TRACKING_ENTRIES = 4096


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """
    Structured security alert produced by a detection rule.

    Fields are populated from available packet data; unavailable fields
    are set to None rather than invented values.
    """
    alert_id: str
    timestamp_utc: str
    rule_id: str
    rule_name: str
    severity: str                  # "low" | "medium" | "high" | "critical"
    source_ip: Optional[str]
    destination_ip: Optional[str]
    protocol: str
    description: str
    evidence: dict
    recommended_action: str
    confidence: str                # "low" | "medium" | "high"

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp_utc": self.timestamp_utc,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "description": self.description,
            "evidence": self.evidence,
            "recommended_action": self.recommended_action,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Helper: bounded time-window counter
# ---------------------------------------------------------------------------

class _TimeWindowTracker:
    """
    Tracks timestamps in a bounded deque for a sliding time window.

    Each entry is a float POSIX timestamp.  Entries older than
    *window_seconds* are pruned on each call to add() or count().
    The deque is capped at *max_entries* to bound memory.
    """

    def __init__(self, window_seconds: float, max_entries: int = 2048) -> None:
        self.window_seconds = window_seconds
        self._entries: collections.deque = collections.deque(maxlen=max_entries)

    def add(self, ts: float) -> None:
        self._prune(ts)
        self._entries.append(ts)

    def count(self, now: float) -> int:
        self._prune(now)
        return len(self._entries)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._entries and self._entries[0] < cutoff:
            self._entries.popleft()

    def reset(self) -> None:
        self._entries.clear()


class _PortDiversityTracker:
    """
    Tracks distinct destination ports contacted by a source IP within a
    sliding time window.

    Entries are (timestamp, dst_port) tuples stored in a deque.
    Pruning removes entries older than the window.  The distinct port
    count is computed from what remains after pruning.
    """

    def __init__(self, window_seconds: float, max_entries: int = 4096) -> None:
        self.window_seconds = window_seconds
        self._entries: collections.deque = collections.deque(maxlen=max_entries)

    def add(self, ts: float, dst_port: int) -> None:
        self._prune(ts)
        self._entries.append((ts, dst_port))

    def distinct_port_count(self, now: float) -> int:
        self._prune(now)
        return len({port for _, port in self._entries})

    def distinct_ports(self, now: float) -> set:
        self._prune(now)
        return {port for _, port in self._entries}

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._entries and self._entries[0][0] < cutoff:
            self._entries.popleft()

    def reset(self) -> None:
        self._entries.clear()


# ---------------------------------------------------------------------------
# Rule 1 — TCP-001: SYN port-scan detection
# ---------------------------------------------------------------------------

class TcpPortScanRule:
    """
    TCP-001: Detect a source IP contacting an unusually large number of
    distinct TCP destination ports within a sliding window.

    Only pure SYN packets (no ACK) are counted.  Retransmissions to the
    same port are not counted as new port contacts.
    """
    RULE_ID = "TCP-001"
    RULE_NAME = "Possible TCP Port Scan"

    def __init__(self, config: Config, time_fn: TimeFn = time_module.time) -> None:
        self._cfg = config.tcp
        self._time_fn = time_fn
        # src_ip → _PortDiversityTracker
        self._trackers: Dict[str, _PortDiversityTracker] = {}

    def process(self, packet: ParsedPacket) -> Optional[dict]:
        """
        Update state for *packet*.  Return an evidence dict if the rule
        triggers, otherwise None.

        Returns None (no alert) when:
        * TCP detection is disabled.
        * The packet is not a pure SYN.
        * The source IP is in the exclusion list.
        * The distinct-port threshold has not been crossed.
        """
        if not self._cfg.enabled:
            return None
        if not packet.has_tcp or not packet.is_syn:
            return None
        src = packet.src_ip
        if not src:
            return None
        if src in self._cfg.excluded_sources:
            return None
        if packet.dst_port is None:
            return None

        now = self._time_fn()

        # Evict oldest entry if table is too large.
        if src not in self._trackers and len(self._trackers) >= _MAX_TRACKING_ENTRIES:
            oldest = next(iter(self._trackers))
            del self._trackers[oldest]

        tracker = self._trackers.setdefault(
            src,
            _PortDiversityTracker(self._cfg.observation_window_seconds),
        )
        tracker.add(now, packet.dst_port)

        distinct_count = tracker.distinct_port_count(now)
        if distinct_count >= self._cfg.syn_port_threshold:
            ports_sample = sorted(tracker.distinct_ports(now))[:20]
            return {
                "rule_id": self.RULE_ID,
                "source_ip": src,
                "destination_ip": packet.dst_ip,
                "distinct_dst_ports": distinct_count,
                "threshold": self._cfg.syn_port_threshold,
                "observation_window_seconds": self._cfg.observation_window_seconds,
                "sampled_ports": ports_sample,
                "last_dst_port": packet.dst_port,
            }
        return None


# ---------------------------------------------------------------------------
# Rule 2 — UDP-001: UDP port diversity
# ---------------------------------------------------------------------------

class UdpPortDiversityRule:
    """
    UDP-001: Detect a source IP sending UDP to an unusually large number
    of distinct destination ports within a sliding window.
    """
    RULE_ID = "UDP-001"
    RULE_NAME = "Possible UDP Port Sweep"

    def __init__(self, config: Config, time_fn: TimeFn = time_module.time) -> None:
        self._cfg = config.udp
        self._time_fn = time_fn
        self._trackers: Dict[str, _PortDiversityTracker] = {}

    def process(self, packet: ParsedPacket) -> Optional[dict]:
        if not self._cfg.enabled:
            return None
        if not packet.has_udp:
            return None
        src = packet.src_ip
        if not src:
            return None
        if src in self._cfg.excluded_sources:
            return None
        if packet.dst_port is None:
            return None

        now = self._time_fn()

        if src not in self._trackers and len(self._trackers) >= _MAX_TRACKING_ENTRIES:
            oldest = next(iter(self._trackers))
            del self._trackers[oldest]

        tracker = self._trackers.setdefault(
            src,
            _PortDiversityTracker(self._cfg.observation_window_seconds),
        )
        tracker.add(now, packet.dst_port)

        distinct_count = tracker.distinct_port_count(now)
        if distinct_count >= self._cfg.port_diversity_threshold:
            ports_sample = sorted(tracker.distinct_ports(now))[:20]
            return {
                "rule_id": self.RULE_ID,
                "source_ip": src,
                "destination_ip": packet.dst_ip,
                "distinct_dst_ports": distinct_count,
                "threshold": self._cfg.port_diversity_threshold,
                "observation_window_seconds": self._cfg.observation_window_seconds,
                "sampled_ports": ports_sample,
                "last_dst_port": packet.dst_port,
            }
        return None


# ---------------------------------------------------------------------------
# Rule 3 — ICMP-001: ICMP echo-request rate
# ---------------------------------------------------------------------------

class IcmpRateRule:
    """
    ICMP-001: Detect a source IP sending an unusually high number of
    ICMP echo requests within a sliding window.

    Only type-8 (echo request) packets are counted.  Replies, unreachables,
    time-exceeded, and other ICMP types are not counted.
    """
    RULE_ID = "ICMP-001"
    RULE_NAME = "Possible ICMP Sweep / Flood"

    def __init__(self, config: Config, time_fn: TimeFn = time_module.time) -> None:
        self._cfg = config.icmp
        self._time_fn = time_fn
        # src_ip → _TimeWindowTracker
        self._trackers: Dict[str, _TimeWindowTracker] = {}

    def process(self, packet: ParsedPacket) -> Optional[dict]:
        if not self._cfg.enabled:
            return None
        if not packet.is_echo_request:
            return None
        src = packet.src_ip
        if not src:
            return None
        if src in self._cfg.excluded_sources:
            return None

        now = self._time_fn()

        if src not in self._trackers and len(self._trackers) >= _MAX_TRACKING_ENTRIES:
            oldest = next(iter(self._trackers))
            del self._trackers[oldest]

        tracker = self._trackers.setdefault(
            src,
            _TimeWindowTracker(self._cfg.observation_window_seconds),
        )
        tracker.add(now)
        count = tracker.count(now)

        if count >= self._cfg.echo_request_threshold:
            return {
                "rule_id": self.RULE_ID,
                "source_ip": src,
                "destination_ip": packet.dst_ip,
                "echo_request_count": count,
                "threshold": self._cfg.echo_request_threshold,
                "observation_window_seconds": self._cfg.observation_window_seconds,
            }
        return None


# ---------------------------------------------------------------------------
# Rule 4 — ARP-001: ARP mapping change
# ---------------------------------------------------------------------------

@dataclass
class _ArpEntry:
    mac: str
    last_seen: float


class ArpSpoofingRule:
    """
    ARP-001: Detect unexpected changes in IP-to-MAC address mappings.

    Maintains a bounded table of observed IP→MAC pairs.  When a new MAC
    is seen for a previously observed IP, an alert is generated.

    Important caveats (documented in README)
    -----------------------------------------
    * DHCP lease renewals, failover, and virtualization environments can
      produce legitimate MAC changes.
    * A mapping change is reported as "possible ARP spoofing or network
      reconfiguration" — never as a confirmed attack.
    * Trusted mappings (from config) are never alerted on.
    * Stale entries are expired after mapping_expiry_seconds.
    """
    RULE_ID = "ARP-001"
    RULE_NAME = "Possible ARP Spoofing / Mapping Change"

    def __init__(self, config: Config, time_fn: TimeFn = time_module.time) -> None:
        self._cfg = config.arp
        self._time_fn = time_fn
        # ip → _ArpEntry
        self._table: Dict[str, _ArpEntry] = {}

    def process(self, packet: ParsedPacket) -> Optional[dict]:
        if not self._cfg.enabled:
            return None
        if not packet.has_arp:
            return None

        # We care about both requests and replies for mapping tracking.
        src_ip = packet.arp_src_ip
        src_mac = packet.arp_src_mac
        if not src_ip or not src_mac:
            return None

        now = self._time_fn()
        self._expire_stale(now)

        # Check trusted mappings.
        trusted_mac = self._cfg.trusted_mappings.get(src_ip)
        if trusted_mac and trusted_mac.lower() == src_mac.lower():
            # Known-good mapping; update last_seen and do not alert.
            self._table[src_ip] = _ArpEntry(mac=src_mac, last_seen=now)
            return None

        existing = self._table.get(src_ip)
        if existing is None:
            # First time we see this IP→MAC mapping; record and continue.
            if len(self._table) < self._cfg.max_table_size:
                self._table[src_ip] = _ArpEntry(mac=src_mac, last_seen=now)
            return None

        if existing.mac.lower() == src_mac.lower():
            # Same MAC; update timestamp.
            existing.last_seen = now
            return None

        # MAC has changed — potential ARP spoofing.
        previous_mac = existing.mac
        # Update table to reflect new observation.
        self._table[src_ip] = _ArpEntry(mac=src_mac, last_seen=now)

        return {
            "rule_id": self.RULE_ID,
            "source_ip": src_ip,
            "destination_ip": packet.arp_dst_ip,
            "previous_mac": previous_mac,
            "new_mac": src_mac,
            "arp_operation": packet.arp_op,
        }

    def _expire_stale(self, now: float) -> None:
        """Remove IP→MAC entries not seen within expiry window."""
        cutoff = now - self._cfg.mapping_expiry_seconds
        stale = [ip for ip, entry in self._table.items()
                 if entry.last_seen < cutoff]
        for ip in stale:
            del self._table[ip]

    @property
    def table_size(self) -> int:
        return len(self._table)


# ---------------------------------------------------------------------------
# Rule 5 — DNS-001: DNS query-rate anomaly
# ---------------------------------------------------------------------------

class DnsQueryRateRule:
    """
    DNS-001: Detect an unusually high DNS query rate from a source IP.

    Only DNS queries (qr=0) are counted.  Responses are explicitly excluded
    to avoid counting both directions of a single lookup.
    """
    RULE_ID = "DNS-001"
    RULE_NAME = "Possible DNS Query Rate Anomaly"

    def __init__(self, config: Config, time_fn: TimeFn = time_module.time) -> None:
        self._cfg = config.dns
        self._time_fn = time_fn
        self._trackers: Dict[str, _TimeWindowTracker] = {}
        # Track last query name per source for evidence.
        self._last_query: Dict[str, str] = {}

    def process(self, packet: ParsedPacket) -> Optional[dict]:
        if not self._cfg.enabled:
            return None
        if not packet.is_dns or packet.dns_is_response:
            return None  # Not a DNS query.
        src = packet.src_ip
        if not src:
            return None
        if src in self._cfg.excluded_sources:
            return None

        now = self._time_fn()

        if src not in self._trackers and len(self._trackers) >= _MAX_TRACKING_ENTRIES:
            oldest = next(iter(self._trackers))
            del self._trackers[oldest]

        tracker = self._trackers.setdefault(
            src, _TimeWindowTracker(self._cfg.observation_window_seconds)
        )
        tracker.add(now)

        if packet.dns_query_name:
            self._last_query[src] = packet.dns_query_name

        count = tracker.count(now)
        if count >= self._cfg.query_rate_threshold:
            return {
                "rule_id": self.RULE_ID,
                "source_ip": src,
                "query_count": count,
                "threshold": self._cfg.query_rate_threshold,
                "observation_window_seconds": self._cfg.observation_window_seconds,
                "last_query_name": self._last_query.get(src),
            }
        return None


# ---------------------------------------------------------------------------
# Rule 6 — DNS-002: Excessive NXDOMAIN responses
# ---------------------------------------------------------------------------

class DnsNxdomainRule:
    """
    DNS-002: Detect an unusually high number of NXDOMAIN responses
    received by a source IP (or associated with queries from it).

    Note: In passive capture, NXDOMAIN responses are seen on the
    destination side of the query.  We track by the query-source IP when
    visible (src_ip of the original query = dst_ip of the response in a
    passive capture).  Because passive capture may not see every DNS
    conversation, counts reflect visible responses only.

    A high NXDOMAIN count is described as suspicious, not as proof of
    malware or DGA activity.
    """
    RULE_ID = "DNS-002"
    RULE_NAME = "Possible Excessive NXDOMAIN Responses"

    def __init__(self, config: Config, time_fn: TimeFn = time_module.time) -> None:
        self._cfg = config.dns
        self._time_fn = time_fn
        # We track by destination IP of the response (= the original querier).
        self._trackers: Dict[str, _TimeWindowTracker] = {}

    def process(self, packet: ParsedPacket) -> Optional[dict]:
        if not self._cfg.enabled:
            return None
        if not packet.is_dns or not packet.dns_is_response:
            return None
        if packet.dns_rcode != 3:  # 3 = NXDOMAIN
            return None

        # The original querier is the destination of the response.
        querier = packet.dst_ip
        if not querier:
            return None
        if querier in self._cfg.excluded_sources:
            return None

        now = self._time_fn()

        if querier not in self._trackers and len(self._trackers) >= _MAX_TRACKING_ENTRIES:
            oldest = next(iter(self._trackers))
            del self._trackers[oldest]

        tracker = self._trackers.setdefault(
            querier, _TimeWindowTracker(self._cfg.nxdomain_window_seconds)
        )
        tracker.add(now)
        count = tracker.count(now)

        if count >= self._cfg.nxdomain_threshold:
            return {
                "rule_id": self.RULE_ID,
                "source_ip": querier,    # The host receiving NXDOMAINs
                "nxdomain_count": count,
                "threshold": self._cfg.nxdomain_threshold,
                "observation_window_seconds": self._cfg.nxdomain_window_seconds,
                "queried_name": packet.dns_query_name,
            }
        return None


# ---------------------------------------------------------------------------
# AlertManager — orchestration
# ---------------------------------------------------------------------------

class AlertManager:
    """
    Routes parsed packets to detection rules, manages deduplication,
    creates Alert objects, and maintains a bounded in-memory alert list.

    Thread safety: process_packet() is called from the capture callback
    (potentially a Scapy thread).  The alert list is protected by a simple
    approach: appends are atomic in CPython due to the GIL, and we cap the
    list size.  For multi-threaded production use, a queue would be preferable.
    """

    def __init__(
        self,
        config: Config,
        time_fn: TimeFn = time_module.time,
    ) -> None:
        self._config = config
        self._time_fn = time_fn
        self._max_alerts = config.output.max_alerts_in_memory
        self._suppression_window = config.output.alert_suppression_window_seconds

        # Instantiate all rules.
        self._rules = [
            TcpPortScanRule(config, time_fn),
            UdpPortDiversityRule(config, time_fn),
            IcmpRateRule(config, time_fn),
            ArpSpoofingRule(config, time_fn),
            DnsQueryRateRule(config, time_fn),
            DnsNxdomainRule(config, time_fn),
        ]

        # Bounded alert storage.
        self._alerts: List[Alert] = []

        # Deduplication: (rule_id, src_ip) → last alert timestamp.
        self._last_alert_time: Dict[Tuple[str, str], float] = {}

        # Alert counters.
        self.total_alerts: int = 0
        self.suppressed_alerts: int = 0

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def process_packet(self, packet: ParsedPacket) -> List[Alert]:
        """
        Pass *packet* through all enabled detection rules.

        Returns the list of new Alert objects generated (may be empty).
        """
        new_alerts: List[Alert] = []

        for rule in self._rules:
            try:
                evidence = rule.process(packet)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Rule %s raised an unexpected exception: %s",
                    getattr(rule, "RULE_ID", "?"), exc, exc_info=True,
                )
                continue

            if evidence is None:
                continue

            alert = self._build_alert(evidence, packet)
            if alert is None:
                continue  # Suppressed.

            new_alerts.append(alert)

        return new_alerts

    # ------------------------------------------------------------------
    # Alert building and deduplication
    # ------------------------------------------------------------------

    def _build_alert(
        self, evidence: dict, packet: ParsedPacket
    ) -> Optional[Alert]:
        """
        Build an Alert from rule evidence.  Returns None if the alert
        should be suppressed (deduplication window active).
        """
        rule_id = evidence.get("rule_id", "UNKNOWN")
        src_ip = evidence.get("source_ip") or packet.src_ip

        # Deduplication check.
        dedup_key = (rule_id, src_ip or "")
        now = self._time_fn()
        last_time = self._last_alert_time.get(dedup_key)
        if last_time is not None and (now - last_time) < self._suppression_window:
            self.suppressed_alerts += 1
            logger.debug(
                "Alert suppressed (dedup): rule=%s src=%s", rule_id, src_ip
            )
            return None

        self._last_alert_time[dedup_key] = now

        alert = Alert(
            alert_id=new_alert_id(),
            timestamp_utc=packet.timestamp_utc or utc_now_iso(),
            rule_id=rule_id,
            rule_name=_RULE_NAMES.get(rule_id, rule_id),
            severity=_RULE_SEVERITIES.get(rule_id, "medium"),
            source_ip=src_ip,
            destination_ip=evidence.get("destination_ip") or packet.dst_ip,
            protocol=packet.protocol or "UNKNOWN",
            description=_build_description(evidence),
            evidence=evidence,
            recommended_action=_RULE_ACTIONS.get(rule_id, "Investigate the source host."),
            confidence=_RULE_CONFIDENCE.get(rule_id, "medium"),
        )

        self._store_alert(alert)
        self.total_alerts += 1
        logger.info(
            "[ALERT] %s | %s | src=%s | %s",
            alert.rule_id, alert.severity, alert.source_ip, alert.description,
        )
        return alert

    def _store_alert(self, alert: Alert) -> None:
        """Append alert to the bounded in-memory list."""
        if len(self._alerts) >= self._max_alerts:
            # Discard oldest alert to stay within the limit.
            self._alerts.pop(0)
        self._alerts.append(alert)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def alerts(self) -> List[Alert]:
        """Return a copy of the current alert list."""
        return list(self._alerts)

    def alert_count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for alert in self._alerts:
            counts[alert.severity] = counts.get(alert.severity, 0) + 1
        return counts

    def alert_count_by_rule(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for alert in self._alerts:
            counts[alert.rule_id] = counts.get(alert.rule_id, 0) + 1
        return counts

    def clear(self) -> None:
        """Remove all stored alerts and reset counters."""
        self._alerts.clear()
        self._last_alert_time.clear()
        self.total_alerts = 0
        self.suppressed_alerts = 0


# ---------------------------------------------------------------------------
# Rule metadata tables
# ---------------------------------------------------------------------------

_RULE_NAMES: Dict[str, str] = {
    "TCP-001": "Possible TCP Port Scan",
    "UDP-001": "Possible UDP Port Sweep",
    "ICMP-001": "Possible ICMP Sweep / Flood",
    "ARP-001": "Possible ARP Spoofing / Mapping Change",
    "DNS-001": "Possible DNS Query Rate Anomaly",
    "DNS-002": "Possible Excessive NXDOMAIN Responses",
}

_RULE_SEVERITIES: Dict[str, str] = {
    "TCP-001": "medium",
    "UDP-001": "medium",
    "ICMP-001": "low",
    "ARP-001": "high",
    "DNS-001": "low",
    "DNS-002": "medium",
}

_RULE_CONFIDENCE: Dict[str, str] = {
    "TCP-001": "medium",
    "UDP-001": "medium",
    "ICMP-001": "low",
    "ARP-001": "medium",
    "DNS-001": "low",
    "DNS-002": "medium",
}

_RULE_ACTIONS: Dict[str, str] = {
    "TCP-001": (
        "Investigate the source host. Review firewall logs and recent "
        "connection history. Determine whether the activity is authorized "
        "(e.g. a network scanner, vulnerability assessment tool, or CI/CD "
        "pipeline) before taking action."
    ),
    "UDP-001": (
        "Review UDP traffic from the source host. Assess whether the "
        "destination port diversity reflects normal application behavior "
        "(e.g. mDNS, SSDP, or a network discovery tool)."
    ),
    "ICMP-001": (
        "Assess the ICMP echo-request volume from the source. A short burst "
        "may reflect network troubleshooting; a sustained high rate may "
        "indicate a sweep or flood. Review at the host level."
    ),
    "ARP-001": (
        "Verify the IP-to-MAC mapping change at the switch and DHCP server. "
        "Determine whether the change was caused by a legitimate DHCP renewal, "
        "failover, or hardware replacement before concluding that ARP spoofing "
        "is occurring."
    ),
    "DNS-001": (
        "Review DNS query logs for the source host. Elevated query rates may "
        "indicate misconfiguration, a misbehaving application, or malicious "
        "activity such as DNS tunneling."
    ),
    "DNS-002": (
        "Review DNS query patterns for the host receiving NXDOMAIN responses. "
        "A high failure rate may reflect misconfiguration, a misbehaving "
        "application, or domain generation algorithm (DGA) activity. Correlate "
        "with other indicators before drawing conclusions."
    ),
}


def _build_description(evidence: dict) -> str:
    """
    Build a human-readable description string from the evidence dict.
    Used as the Alert.description field.
    """
    rule_id = evidence.get("rule_id", "UNKNOWN")
    src = evidence.get("source_ip", "unknown")

    if rule_id == "TCP-001":
        return (
            f"Source {src} contacted {evidence.get('distinct_dst_ports')} distinct "
            f"TCP destination ports in {evidence.get('observation_window_seconds')}s "
            f"(threshold: {evidence.get('threshold')}). Possible port scan."
        )
    if rule_id == "UDP-001":
        return (
            f"Source {src} sent UDP to {evidence.get('distinct_dst_ports')} distinct "
            f"destination ports in {evidence.get('observation_window_seconds')}s "
            f"(threshold: {evidence.get('threshold')}). Possible UDP port sweep."
        )
    if rule_id == "ICMP-001":
        return (
            f"Source {src} sent {evidence.get('echo_request_count')} ICMP echo "
            f"requests in {evidence.get('observation_window_seconds')}s "
            f"(threshold: {evidence.get('threshold')}). Possible ICMP sweep or flood."
        )
    if rule_id == "ARP-001":
        return (
            f"IP {src} previously mapped to MAC {evidence.get('previous_mac')} "
            f"is now associated with MAC {evidence.get('new_mac')}. "
            "Possible ARP spoofing or legitimate network reconfiguration."
        )
    if rule_id == "DNS-001":
        return (
            f"Source {src} sent {evidence.get('query_count')} DNS queries in "
            f"{evidence.get('observation_window_seconds')}s "
            f"(threshold: {evidence.get('threshold')}). Possible DNS abuse."
        )
    if rule_id == "DNS-002":
        return (
            f"Host {src} received {evidence.get('nxdomain_count')} NXDOMAIN "
            f"responses in {evidence.get('observation_window_seconds')}s "
            f"(threshold: {evidence.get('threshold')}). Possible domain enumeration "
            "or DGA activity."
        )
    return f"Rule {rule_id} triggered for source {src}."
