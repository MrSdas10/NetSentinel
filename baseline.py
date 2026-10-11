"""
baseline.py — Lightweight behavioral baselining for NetSentinel.

Maintains protocol and host counts over a configurable learning period,
persists the baseline to JSON, and supports comparison against live traffic.

Design notes
------------
* No machine learning — only simple counters and explicit thresholds.
* First-run or missing baseline files are handled gracefully.
* Malformed baseline files do not crash the application.
* The analyst can reset the baseline by deleting the JSON file or by
  calling Baseline.reset().
* Learning mode (is_learning=True) collects data; detection mode
  (is_learning=False) compares against the stored baseline.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from parsers import ParsedPacket
from utils import utc_now_iso

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Snapshot dataclass — represents one baseline snapshot
# ---------------------------------------------------------------------------

@dataclass
class BaselineSnapshot:
    """
    Protocol and host counters collected during a learning period.
    Stored as / loaded from JSON.
    """
    created_utc: str = ""
    learning_duration_seconds: int = 0
    total_packets: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    # src_ip → packet count
    host_counts: Dict[str, int] = field(default_factory=dict)
    # src_ip → distinct dst_port count (TCP)
    tcp_port_diversity: Dict[str, int] = field(default_factory=dict)
    # src_ip → ICMP request count
    icmp_request_counts: Dict[str, int] = field(default_factory=dict)
    # src_ip → DNS query count
    dns_query_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "created_utc": self.created_utc,
            "learning_duration_seconds": self.learning_duration_seconds,
            "total_packets": self.total_packets,
            "protocol_counts": self.protocol_counts,
            "host_counts": self.host_counts,
            "tcp_port_diversity": self.tcp_port_diversity,
            "icmp_request_counts": self.icmp_request_counts,
            "dns_query_counts": self.dns_query_counts,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BaselineSnapshot":
        return cls(
            created_utc=str(d.get("created_utc", "")),
            learning_duration_seconds=int(d.get("learning_duration_seconds", 0)),
            total_packets=int(d.get("total_packets", 0)),
            protocol_counts=dict(d.get("protocol_counts", {})),
            host_counts=dict(d.get("host_counts", {})),
            tcp_port_diversity=dict(d.get("tcp_port_diversity", {})),
            icmp_request_counts=dict(d.get("icmp_request_counts", {})),
            dns_query_counts=dict(d.get("dns_query_counts", {})),
        )


# ---------------------------------------------------------------------------
# Comparison result
# ---------------------------------------------------------------------------

@dataclass
class BaselineComparison:
    """Result of comparing current counters to the stored baseline."""
    has_baseline: bool = False
    tcp_diversity_anomalies: Dict[str, dict] = field(default_factory=dict)
    icmp_anomalies: Dict[str, dict] = field(default_factory=dict)
    dns_anomalies: Dict[str, dict] = field(default_factory=dict)
    new_hosts: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Baseline class
# ---------------------------------------------------------------------------

class Baseline:
    """
    Manages learning-phase data collection and baseline comparison.

    Usage
    -----
    1. Instantiate with the path to the baseline JSON file and the
       learning duration (seconds).
    2. Call update(packet) for each parsed packet.
    3. After the learning period, call finalize() to compute and save the
       snapshot.
    4. On subsequent runs, load() restores the stored baseline.
    5. Call compare(current_counters) to detect anomalies.
    """

    def __init__(
        self,
        baseline_file: Path,
        learning_duration_seconds: int,
        anomaly_multiplier: float = 2.0,
    ) -> None:
        self.baseline_file = baseline_file
        self.learning_duration_seconds = learning_duration_seconds
        self.anomaly_multiplier = anomaly_multiplier

        self.is_learning: bool = False
        self._stored: Optional[BaselineSnapshot] = None

        # Live accumulators (reset on each update cycle)
        self._total_packets: int = 0
        self._protocol_counts: Dict[str, int] = {}
        self._host_counts: Dict[str, int] = {}
        self._tcp_dst_ports: Dict[str, set] = {}
        self._icmp_req_counts: Dict[str, int] = {}
        self._dns_query_counts: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start_learning(self) -> None:
        """Enter learning mode — updates will accumulate baseline data."""
        logger.info("Baseline: learning mode started (%d s).",
                    self.learning_duration_seconds)
        self.is_learning = True
        self.reset_accumulators()

    def finalize(self) -> BaselineSnapshot:
        """
        Exit learning mode, compute the snapshot, save to disk, and return it.
        """
        self.is_learning = False
        snapshot = BaselineSnapshot(
            created_utc=utc_now_iso(),
            learning_duration_seconds=self.learning_duration_seconds,
            total_packets=self._total_packets,
            protocol_counts=dict(self._protocol_counts),
            host_counts=dict(self._host_counts),
            tcp_port_diversity={
                ip: len(ports) for ip, ports in self._tcp_dst_ports.items()
            },
            icmp_request_counts=dict(self._icmp_req_counts),
            dns_query_counts=dict(self._dns_query_counts),
        )
        self._stored = snapshot
        self._save(snapshot)
        logger.info(
            "Baseline finalized: %d packets, %d hosts.",
            snapshot.total_packets, len(snapshot.host_counts),
        )
        return snapshot

    def load(self) -> bool:
        """
        Load a previously saved baseline from disk.

        Returns True on success, False if the file is absent or invalid.
        A failed load does not raise — the caller continues without a baseline.
        """
        if not self.baseline_file.exists():
            logger.info("No baseline file found at %s.", self.baseline_file)
            return False

        try:
            raw = self.baseline_file.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Baseline file root must be a JSON object.")
            self._stored = BaselineSnapshot.from_dict(data)
            logger.info(
                "Baseline loaded: %d packets, created %s.",
                self._stored.total_packets,
                self._stored.created_utc,
            )
            return True
        except (OSError, json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning(
                "Could not load baseline from %s: %s. "
                "Continuing without baseline comparison.",
                self.baseline_file, exc,
            )
            self._stored = None
            return False

    def reset(self) -> None:
        """
        Delete the baseline file and clear in-memory state.
        Allows the analyst to intentionally recreate a baseline.
        """
        if self.baseline_file.exists():
            try:
                self.baseline_file.unlink()
                logger.info("Baseline file deleted: %s.", self.baseline_file)
            except OSError as exc:
                logger.warning("Could not delete baseline file: %s", exc)
        self._stored = None
        self.reset_accumulators()

    def reset_accumulators(self) -> None:
        """Clear live counters (does not affect the stored baseline)."""
        self._total_packets = 0
        self._protocol_counts = {}
        self._host_counts = {}
        self._tcp_dst_ports = {}
        self._icmp_req_counts = {}
        self._dns_query_counts = {}

    # ------------------------------------------------------------------
    # Update (called per packet)
    # ------------------------------------------------------------------

    def update(self, packet: ParsedPacket) -> None:
        """
        Feed a parsed packet into the live accumulators.

        If is_learning is False, this method still tracks live data so that
        compare() can compare against the stored baseline.
        """
        self._total_packets += 1

        proto = packet.protocol or "UNKNOWN"
        self._protocol_counts[proto] = self._protocol_counts.get(proto, 0) + 1

        src = packet.src_ip
        if src:
            self._host_counts[src] = self._host_counts.get(src, 0) + 1

        if packet.has_tcp and packet.is_syn and src and packet.dst_port is not None:
            ports = self._tcp_dst_ports.setdefault(src, set())
            ports.add(packet.dst_port)

        if packet.is_echo_request and src:
            self._icmp_req_counts[src] = self._icmp_req_counts.get(src, 0) + 1

        if packet.is_dns and not packet.dns_is_response and src:
            self._dns_query_counts[src] = self._dns_query_counts.get(src, 0) + 1

    # ------------------------------------------------------------------
    # Comparison
    # ------------------------------------------------------------------

    def compare(self) -> BaselineComparison:
        """
        Compare current live accumulators to the stored baseline.

        Returns a BaselineComparison.  If no stored baseline exists,
        has_baseline is False and all anomaly dicts are empty.
        """
        result = BaselineComparison(has_baseline=self._stored is not None)

        if self._stored is None:
            return result

        baseline = self._stored
        mult = self.anomaly_multiplier

        # TCP port diversity anomalies
        for ip, live_count in self._tcp_dst_ports.items():
            baseline_count = baseline.tcp_port_diversity.get(ip, 0)
            threshold = max(1, baseline_count * mult)
            if len(live_count) > threshold:
                result.tcp_diversity_anomalies[ip] = {
                    "live_distinct_ports": len(live_count),
                    "baseline_distinct_ports": baseline_count,
                    "threshold": threshold,
                }

        # ICMP request anomalies
        for ip, live_count in self._icmp_req_counts.items():
            baseline_count = baseline.icmp_request_counts.get(ip, 0)
            threshold = max(1, baseline_count * mult)
            if live_count > threshold:
                result.icmp_anomalies[ip] = {
                    "live_requests": live_count,
                    "baseline_requests": baseline_count,
                    "threshold": threshold,
                }

        # DNS query anomalies
        for ip, live_count in self._dns_query_counts.items():
            baseline_count = baseline.dns_query_counts.get(ip, 0)
            threshold = max(1, baseline_count * mult)
            if live_count > threshold:
                result.dns_anomalies[ip] = {
                    "live_queries": live_count,
                    "baseline_queries": baseline_count,
                    "threshold": threshold,
                }

        # New hosts not seen during baseline
        baseline_hosts = set(baseline.host_counts.keys())
        for ip in self._host_counts:
            if ip and ip not in baseline_hosts:
                result.new_hosts.append(ip)

        return result

    @property
    def stored_snapshot(self) -> Optional[BaselineSnapshot]:
        """Return the currently loaded baseline snapshot, or None."""
        return self._stored

    @property
    def live_protocol_counts(self) -> Dict[str, int]:
        """Return a copy of the live protocol counter."""
        return dict(self._protocol_counts)

    @property
    def live_total_packets(self) -> int:
        return self._total_packets

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self, snapshot: BaselineSnapshot) -> None:
        """Write the baseline snapshot to disk as JSON."""
        try:
            self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
            self.baseline_file.write_text(
                json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8"
            )
            logger.info("Baseline saved to %s.", self.baseline_file)
        except OSError as exc:
            logger.error("Failed to save baseline: %s", exc)
