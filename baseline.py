"""Transparent behavioural baselining for NetSentinel.

The baseline is intentionally simple: it records per-protocol counts, a set of
observed hosts, and simple traffic-shape metrics during a learning window, then
exposes a comparison that flags *new* hosts and *unusual* protocol shares.

No machine learning is used.  Every decision is derived from counts that an
analyst can inspect in ``data/baseline.json``.

Baseline JSON schema (v1):

    {
      "version": 1,
      "created_utc": "...",
      "observation_seconds": 300,
      "packets_observed": 12345,
      "protocol_counts": {"TCP": 100, "UDP": 20, ...},
      "observed_hosts": ["10.0.0.1", ...],
      "top_talkers": {"10.0.0.1": 500, ...},
      "protocol_share": {"TCP": 0.82, "UDP": 0.16, ...}
    }
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set

from parsers import ParsedPacket
from utils import NetSentinelError, atomic_write_text, to_utc_iso, utc_now

LOGGER = logging.getLogger(__name__)

BASELINE_VERSION = 1
TOP_TALKERS_LIMIT = 20
# A protocol share is "unusual" when it is more than this factor different
# from the learned share and the absolute difference is at least 5 points.
_SHARE_FACTOR = 2.0
_SHARE_MIN_DELTA = 0.05


class BaselineError(NetSentinelError):
    """Raised for unrecoverable baseline file problems."""


@dataclass
class BaselineComparison:
    """Result of comparing current traffic against a stored baseline."""

    has_baseline: bool
    packets_observed: int = 0
    new_hosts: List[str] = field(default_factory=list)
    protocol_drift: Dict[str, Dict[str, float]] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "has_baseline": self.has_baseline,
            "packets_observed": self.packets_observed,
            "new_hosts": list(self.new_hosts),
            "protocol_drift": dict(self.protocol_drift),
        }


class BaselineManager:
    """Accumulate traffic statistics and compare against a stored baseline.

    ``learning_mode`` selects whether ``observe`` merely records counts (for a
    later ``save``) or also runs a comparison against a loaded baseline.
    """

    def __init__(
        self,
        baseline_path: str | Path,
        observation_seconds: float,
        learning_mode: bool = False,
    ) -> None:
        if observation_seconds <= 0:
            raise ValueError("observation_seconds must be positive")

        self.path = Path(baseline_path)
        self.observation_seconds = float(observation_seconds)
        self.learning_mode = bool(learning_mode)

        self._protocol_counts: Counter[str] = Counter()
        self._host_counts: Counter[str] = Counter()
        self._packets_observed = 0
        self._started_utc = to_utc_iso(utc_now())

        self._baseline: Optional[Dict[str, Any]] = None
        self._baseline_protocol_share: Dict[str, float] = {}
        self._baseline_hosts: Set[str] = set()

        if not self.learning_mode:
            self._load_baseline()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_baseline(self) -> None:
        """Load an existing baseline if present and valid.

        A missing baseline is not an error - the manager simply runs in
        "first run" mode where ``has_baseline`` is False.  A malformed
        baseline is logged and treated as absent rather than crashing the
        application, because losing the baseline must not stop monitoring.
        """
        if not self.path.is_file():
            LOGGER.info("No baseline file at %s; running without a baseline",
                        self.path)
            return

        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Baseline file %s could not be read (%s); ignoring it",
                           self.path, exc)
            return

        if not isinstance(data, dict) or data.get("version") != BASELINE_VERSION:
            LOGGER.warning(
                "Baseline file %s has an unsupported schema; ignoring it",
                self.path,
            )
            return

        self._baseline = data
        share = data.get("protocol_share")
        if isinstance(share, dict):
            self._baseline_protocol_share = {
                str(k): float(v) for k, v in share.items()
                if isinstance(v, (int, float))
            }
        hosts = data.get("observed_hosts")
        if isinstance(hosts, list):
            self._baseline_hosts = {str(h) for h in hosts if isinstance(h, str)}
        LOGGER.info(
            "Loaded baseline from %s (%d observed hosts, %d protocol classes)",
            self.path, len(self._baseline_hosts), len(self._baseline_protocol_share),
        )

    def save(self) -> Path:
        """Write the current counters to disk and return the file path."""
        total = sum(self._protocol_counts.values()) or 1
        share = {
            proto: count / total
            for proto, count in self._protocol_counts.items()
        }
        top_talkers = dict(self._host_counts.most_common(TOP_TALKERS_LIMIT))

        payload: Dict[str, Any] = {
            "version": BASELINE_VERSION,
            "created_utc": self._started_utc,
            "saved_utc": to_utc_iso(utc_now()),
            "observation_seconds": self.observation_seconds,
            "packets_observed": self._packets_observed,
            "protocol_counts": dict(self._protocol_counts),
            "protocol_share": share,
            "observed_hosts": sorted(self._host_counts.keys()),
            "top_talkers": top_talkers,
        }

        text = json.dumps(payload, indent=2, ensure_ascii=False)
        try:
            atomic_write_text(self.path, text)
        except OSError as exc:
            raise BaselineError(f"Unable to write baseline {self.path}: {exc}") from exc

        LOGGER.info("Baseline saved to %s (%d packets, %d hosts)",
                    self.path, self._packets_observed, len(self._host_counts))
        return self.path

    def reset(self) -> None:
        """Discard accumulated counters and any loaded baseline."""
        self._protocol_counts.clear()
        self._host_counts.clear()
        self._packets_observed = 0
        self._started_utc = to_utc_iso(utc_now())
        self._baseline = None
        self._baseline_protocol_share = {}
        self._baseline_hosts = set()

    # ------------------------------------------------------------------
    # Observation
    # ------------------------------------------------------------------

    def observe(self, packet: ParsedPacket) -> None:
        """Record one parsed packet against the baseline counters."""
        self._packets_observed += 1
        if packet.protocol:
            self._protocol_counts[packet.protocol] += 1
        for host in (packet.src_ip, packet.dst_ip,
                     packet.arp_sender_ip, packet.arp_target_ip):
            if host:
                self._host_counts[host] += 1

    def compare(self) -> BaselineComparison:
        """Return a snapshot comparison against the loaded baseline."""
        if self._baseline is None:
            return BaselineComparison(
                has_baseline=False,
                packets_observed=self._packets_observed,
            )

        total = sum(self._protocol_counts.values()) or 1
        current_share = {
            proto: count / total for proto, count in self._protocol_counts.items()
        }

        drift: Dict[str, Dict[str, float]] = {}
        all_protocols = set(current_share) | set(self._baseline_protocol_share)
        for proto in sorted(all_protocols):
            learned = self._baseline_protocol_share.get(proto, 0.0)
            current = current_share.get(proto, 0.0)
            delta = current - learned
            if abs(delta) < _SHARE_MIN_DELTA:
                continue
            larger = max(learned, current)
            smaller = max(min(learned, current), 1e-9)
            if larger / smaller >= _SHARE_FACTOR:
                drift[proto] = {
                    "baseline_share": round(learned, 4),
                    "current_share": round(current, 4),
                    "delta": round(delta, 4),
                }

        new_hosts = sorted(set(self._host_counts) - self._baseline_hosts)
        # Bound the reported list so a wide scan does not flood the summary.
        new_hosts = new_hosts[:100]

        return BaselineComparison(
            has_baseline=True,
            packets_observed=self._packets_observed,
            new_hosts=new_hosts,
            protocol_drift=drift,
        )

    # ------------------------------------------------------------------
    # Accessors (used by the reporter)
    # ------------------------------------------------------------------

    @property
    def has_baseline(self) -> bool:
        return self._baseline is not None

    @property
    def learning_mode_active(self) -> bool:
        return self.learning_mode

    def summary(self) -> Dict[str, Any]:
        """Return a small dictionary suitable for embedding in reports."""
        return {
            "learning_mode": self.learning_mode,
            "has_baseline": self.has_baseline,
            "observation_seconds": self.observation_seconds,
            "packets_observed": self._packets_observed,
            "protocol_counts": dict(self._protocol_counts),
            "observed_hosts_count": len(self._host_counts),
        }

    def observed_hosts(self) -> Iterable[str]:
        return tuple(self._host_counts.keys())